/*
 * Low level functions & objects for moveable, hybrid (part private memmory,
 * part shared memory) synchronization objects.
 *
 * Copyright (C) 2015 Daniel Santos
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef WINE_SYNC_IS_SERVER
# error "This is an unguarded header file that defines implementations"
/* The following exists only to make my IDEs happy */
# define WINE_SYNC_IS_SERVER 0
//# include "wine/port.h"
# include "ntstatus.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <syscall.h>
#ifdef __linux__
# include <linux/futex.h>
#endif

#include "ntstatus.h"
#include "wine/sync.h"

/* make debugging a little easier */
#if defined(__GNUC__) && !defined(__OPTIMIZE__)
# undef FORCEINLINE
# define FORCEINLINE __attribute__((noinline, unused))
#endif

/* Set to 1 to fail an assertion on conditions caused by corrupted data in shared memory and zero
 * to respond with STATUS_FILE_CORRUPTED */
#define SYNC_DEBUG_ASSERTS 1
static enum shm_sync_value_result check_data_anomalous(struct hybrid_sync_object *ho,
                                                       union shm_sync_value *pre_ptr,
                                                       enum shm_sync_value_result flags, int wait_lock);

#if !WINE_SYNC_IS_SERVER /* client only */
static struct
{
    /* Function to get the new shared memory and change the value pointer. This
     * is callable by any function that attempts to dereference the value
     * pointer via the path check_data --> check_data_trans -->
     * check_data_anomalous --> hybrid_object_do_move */
    NTSTATUS (*move)( struct hybrid_sync_object *ho );
    NTSTATUS (*destroy)( struct hybrid_sync_object *ho );
} hybrid_object_client_fns = { NULL, NULL };
#endif /* !WINE_SYNC_IS_SERVER (client only) */

/* where the server writes the last CPU number and the client reads it */
static unsigned int *last_server_cpu_ptr = NULL;

/******************************************************************
 *              sync_impl_init
 *
 * Initialize static values in sync_impl.h translation unit. Call (at least) once from the .c file
 * you include this from.
 */
static void sync_impl_init( NTSTATUS (*move)( struct hybrid_sync_object *ho ),
                            NTSTATUS (*destroy)( struct hybrid_sync_object *ho ),
                            unsigned int *_last_server_cpu_ptr )
{
#if !WINE_SYNC_IS_SERVER
    hybrid_object_client_fns.move    = move;
    hybrid_object_client_fns.destroy = destroy;
#endif
    last_server_cpu_ptr              = _last_server_cpu_ptr;
}

/* Non-fatal errors:
 *   EAGAIN
 *   EWOULDBLOCK
 *   ETIMEDOUT
 *   EINTR
 *
 * Fatal errors
 *   EACCES
 *   EFAULT
 *   EINVAL
 *   ENFILE
 *   ENOSYS
 */
static void DECLSPEC_NORETURN __noinline __cold fatal_futex_error(const char *op, int *addr)
{
    int err = errno;
    perror(op);
    fprintf(stderr, "%s on address %p failed with unexpected error %d\n", op, addr, err);
    assert(0);
    exit(-1);
}

/******************************************************************
 *              futex_wait
 *
 * Wrapper for syscall futex (FUTEX_WAIT) operation
 *
 * PARAMS
 *  addr    [I]  The address (to a 32-bit value) to wait on
 *  cur     [I]  The value last read from address
 *  timeout [I]  The timeout or NULL for infinite
 *
 * Returns
 *  0             Success
 *  -ETIMEDOUT    Timed out
 *  -EWOULDBLOCK  The value has changed (repeat operation)
 *  -EINTR        Interrupted by a signal (repeat operation)
 *
 * Any other error is considered fatal (shouldn't happen).
 *
 * See also: man futex(2)
 *
 * TODO: consolidate with dlls/ntdll/critsection.c, maybe move to port.h
 */
static FORCEINLINE int futex_wait(int *addr, int cur, struct timespec *timeout)
{
    if (syscall( __NR_futex, addr, FUTEX_WAIT, cur, timeout, 0, 0 ) == -1)
    {
        int err = errno;

        switch (err)
        {
        case EWOULDBLOCK:
        case ETIMEDOUT:
        case EINTR:
            return -err;

        default:
            fatal_futex_error("futex_wait", addr);
        }
    }

    return 0;
}

/******************************************************************
 *              futex_wake
 *
 * Wrapper for syscall futex (FUTEX_WAKE) operation
 *
 * PARAMS
 *  addr    [I]  An address to a 32-bit value to wake waiters on
 *  count   [I]  The number of threads to wake
 *
 * Returns
 *  The number of threads awoken
 *  Any errors are considered fatal and do not return
 *
 * See also: man futex(2)
 *
 * TODO: consolidate with dlls/ntdll/critsection.c
 */
static FORCEINLINE int futex_wake(int *addr, int count)
{
    int ret = syscall( __NR_futex, addr, FUTEX_WAKE, count, NULL, 0, 0 );

    if (ret == -1)
        fatal_futex_error("futex_wake", addr);

    return ret;
}

#define FNV_32_PRIME  (0x01000193)
#define FNV1A_32_INIT (0x811c9dc5)

/* 32-bit FNV-1a hash (loosely based on http://www.isthe.com/chongo/tech/comp/fnv) */
static unsigned int fnv1a_hash32(unsigned int base, const void *in, size_t len)
{
    const unsigned char *p   = in;
    const unsigned char *end = p + len;
    unsigned int ret         = base;

    for (; p < end; ++p)
    {
        ret ^= *p;
        ret *= FNV_32_PRIME;
        /* the below is alegedly faster, but it would seem at the expense of larger text size */
        /* ret += (ret << 1) + (ret << 4) + (ret << 7) + (ret << 8) + (ret << 24); */
    }

    return ret;
}

/* create a hash value in the upper 28 bits of union shm_sync_value::flags_hash and OR to the supplied flags */
static unsigned int hash28(unsigned int base, enum shm_sync_value_result flags, unsigned int data)
{

    /* flags should only contain flags */
    assert(!(flags & SHM_SYNC_VALUE_HASH_MASK));

    /* slight modification of algo for speed (need to test uniqueness and random spread) */
    base ^= data;
    base *= FNV_32_PRIME;
    base ^= flags;
    base *= FNV_32_PRIME;

    return (base << SHM_SYNC_VALUE_FLAGS_BITS) | flags;

#if 0
    /* This implementation would be slower, but use the FVN-1a unmodified */
    unsigned char in[5];
    *((unsigned int*)in) = data;
    in[4] = (unsigned char)flags;

    return (fnv1a_hash32(base, in, sizeof(in)) << SHM_SYNC_VALUE_FLAGS_BITS) | flags;
#endif
}


/* REMOVE: for debugging race conditions only! */
#if WINE_SYNC_IS_SERVER
static inline void assert_not_doing_move(struct hybrid_sync_object *ho){}
#else
static inline void assert_not_doing_move(struct hybrid_sync_object *ho)
{
    int curfr = interlocked_xchg_add((int*)&ho->flags_refcount, 0);
    assert(!(curfr & HYBRID_SYNC_DBG_DOING_MOVE));
}
#endif

/* atomically set the bit SHM_SYNC_VALUE_CORRUPTED_BIT and don't bother updating the
 * hash to match it */
static __cold enum shm_sync_value_result sync_fail(struct hybrid_sync_object *ho, const char *fmt, ...)
{
    if (fmt)
    {
        va_list valist;

        va_start(valist, fmt);
        vfprintf(stderr, fmt, valist);
        va_end(valist);
    }
assert_not_doing_move(ho);
    if (SYNC_DEBUG_ASSERTS)
        assert(0);

    /* this bit lets all processes know that we're corrupted */
    interlocked_test_and_set_bit(&ho->value->flags_hash, SHM_SYNC_VALUE_CORRUPTED_BIT);

    /* this bit is for the local process, because now we don't trust that the
     * shared bit will not be overwritten */
    interlocked_test_and_set_bit((int*)&ho->flags_refcount, HYBRID_SYNC_BAD);

    return SHM_SYNC_VALUE_CORRUPTED;
}

static inline int is_local_private(struct hybrid_sync_object *ho)
{
    return WINE_SYNC_IS_SERVER && hybrid_object_is_server_private(ho);
}

static __cold void bad_hash(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr, int hash)
{
    unsigned a = hash;
    unsigned b = pre_ptr->flags_hash;
    sync_fail(ho, "ERROR %s: hash mismatch: ho=%p hash_base=0x%08x data=0x%08x "
              "(0x%07x/%1x != 0x%07x/%1x)\n",
              __func__, ho, ho->hash_base, pre_ptr->data,
              a >> SHM_SYNC_VALUE_FLAGS_BITS, a & SHM_SYNC_VALUE_FLAGS_MASK,
              b >> SHM_SYNC_VALUE_FLAGS_BITS, b & SHM_SYNC_VALUE_FLAGS_MASK);
}

/******************************************************************************
 *              check_data
 *
 * Check the union shm_sync_value data for corruption or anomalous conditions.
 *
 * ho           [I] The object
 * pre_ptr      [I] Pointer to the buffer where the value has been stored (not
 *                  to shared memory)
 * wait_lock    [I] (client only, ignored on server) if non-zero and the
 *                  SHM_SYNC_VALUE_LOCKED bit is set, automatically call
 *                  hybrid_object_wait_global_lock(), otherwise return the bit
 *                  value.
 *
 * Returns
 *      SHM_SYNC_VALUE_SUCCESS          if the caller should proceed as normal
 *      SHM_SYNC_VALUE_AGAIN            restart operation
 *      SHM_SYNC_VALUE_CORRUPTED        object is corrupt
 *      SHM_SYNC_VALUE_FAIL             client: object is unusable due to error in migration
 */
static FORCEINLINE enum shm_sync_value_result
check_data(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr, int wait_lock)
{
    int flags;
    int flags_hash;
    int hash_base            = ho->hash_base;
    int anomalous_flags_mask = (SHM_SYNC_VALUE_MOVED | SHM_SYNC_VALUE_CORRUPTED);

    if (is_local_private(ho))
        return SHM_SYNC_VALUE_SUCCESS;

assert_not_doing_move(ho);

    if (!WINE_SYNC_IS_SERVER)
        anomalous_flags_mask |= SHM_SYNC_VALUE_LOCKED;

    if (pre_ptr->flags_hash & anomalous_flags_mask)
        return check_data_anomalous(ho, pre_ptr, pre_ptr->flags_hash, wait_lock);

    /* verify no corruption */
    flags      = pre_ptr->flags_hash & SHM_SYNC_VALUE_FLAGS_MASK;
    flags_hash = (int)hash28(hash_base, flags, pre_ptr->data);
    if (unlikely(pre_ptr->flags_hash != flags_hash))
    {
        barrier();
        if (ho->hash_base != hash_base)
            fprintf(stderr, "ho->hash_base != hash_base\n");
        bad_hash(ho, pre_ptr, flags_hash);
        return SHM_SYNC_VALUE_CORRUPTED;
    }

    return SHM_SYNC_VALUE_SUCCESS;
}

/******************************************************************************
 *              sync_try_op
 *
 * Attempt a compare & swap operation on a synchronization object.
 *
 * PARAMS
 *  ho          [IO]    The struct hybrid_sync_object to operate on.
 *  pre_ptr     [IO]    A pointer to the current value, which should be read via
 *                      a normal volatile memory read prior to
 *                      calling sync_try_op(), returns the value *prior* to a
 *                      the operation.
 *  post_ptr    [O]     (optional) pointer to the buffer to receive the new value after a sucessful operation. If not sucessful, buffer will not be written to.
 *  data        [I]     The new data portion of the value to set.
 *  flags       [I]     The new flags.
 *
 * Checks for exceptional conditions (flags set or corruption), calculates new
 * hash value and performs an atomic compare & swap. The value pointed to by
 * pre_ptr is updated only if the operation is either successful or failed due
 * to a change (SHM_SYNC_VALUE_AGAIN).
 *
 * RETURNS
 *  SHM_SYNC_VALUE_SUCCESS      The operation was successful.
 *  SHM_SYNC_VALUE_MOVING
 *  STATUS_FILE_CORRUPT_ERROR
 *  SHM_SYNC_VALUE_AGAIN -- the value changed and the operation should be attempted again (EAGAIN would be a better value)
 */
static FORCEINLINE enum shm_sync_value_result
sync_try_op(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
            union shm_sync_value *post_ptr, int data, int flags)
{
    union shm_sync_value new_value;
    union shm_sync_value updated_value;
    NTSTATUS ret = SHM_SYNC_VALUE_SUCCESS;

    if (!is_local_private( ho ))
    {
        ret = check_data( ho, pre_ptr, TRUE );
        if ( ret )
            return ret;

        if (!WINE_SYNC_IS_SERVER)
            /* if any of these flags are set, client should not be attempting any operation */
            assert(!(flags & (SHM_SYNC_VALUE_LOCKED | SHM_SYNC_VALUE_MOVED | SHM_SYNC_VALUE_CORRUPTED)));

        new_value.flags_hash = hash28(ho->hash_base, flags, data);
    }
    else
        new_value.flags_hash = 0;
    new_value.data = data;

    updated_value.int64 = interlocked_cmpxchg64(&ho->value->int64,
                                                new_value.int64, pre_ptr->int64);

    if (updated_value.int64 != pre_ptr->int64)
        ret = SHM_SYNC_VALUE_AGAIN;

    pre_ptr->int64 = updated_value.int64;
    if (post_ptr && !ret)
        post_ptr->int64 = new_value.int64;

    return ret;
}

/******************************************************************************
 *              hybrid_object_init
 *
 * PARAMS
 *  ho          [IO]    The object to initialize
 *  value       [I]     A pointer to a union shm_sync_value object in shared memory
 *                      or NULL in any other case (see truth table below)
 *  local_flags [I]     Flags possibly containing only HYBRID_SYNC_SERVER_PRIVATE
 *  hash_base   [I]     the base value used to create hash for the object (or zero)
 *
 * Truth table of acceptable parameter values
 *  _____  ________  _____________________  ___________
 * |     || flags  ||       value         ||           |
 *  From   svr_prvt  input   result         Description
 * ----------------------------------------------------
 * server  0         -> shm  -> shm         server-side of shared memory object
 * client  0         -> shm  -> shm         client-side of shared memory object
 * server  1         NULL    &private_value server-side private object
 * client  1         NULL    NULL           client-side stub for interacting with server-private
 *                                          object (all actions routed through server calls).
 *
 * Legend of columns:
 * From          - whether the call to hybrid_object_init() is made via the client or server
 * svr_prvt      - value of HYBRID_SYNC_SERVER_PRIVATE bit is set in local_flags
 * value, input  - the value passed as the 'value' parameter
 * value, result - the the resultant value of ho->value
 */
static void hybrid_object_init(struct hybrid_sync_object *ho, union shm_sync_value *value,
                               int local_flags, unsigned int hash_base)
{
    assert(!(local_flags & ~HYBRID_SYNC_INIT_MASK));

    /* If private, then you do not pass a value -- it will either be NULL if the
     * storage is foreign or set to &private_value if local. If not private then
     * a value pointer is required. */
    assert((local_flags & HYBRID_SYNC_SERVER_PRIVATE) ? !value : !!value);

    if (value) {
        ho->value          = value;
        ho->hash_base      = hash_base;
    } else {
        if (WINE_SYNC_IS_SERVER)
            ho->value      = &ho->private_value;
        else
            ho->value      = NULL;

        /* ho->private_value intentionally left uninitialized since it should be
         * inited by derived class via ho->value if the object is local to the
         * process -- never inited otherwise */
    }

    /* server does not use ho->flags_refcount for reference counting, but client
     * does, so increment it only for client */
    if (!WINE_SYNC_IS_SERVER)
        local_flags |= (1u << HYBRID_SYNC_FLAGS_BITS);

    ho->flags_refcount = local_flags;
}

/******************************************************************
 *              hybrid_semaphore_init
 *
 * Initialize a hybrid semaphore
 *
 * PARAMS
 *  sem      [I] Pointer to the new semaphore object.
 *  initial  [I] Initial value
 *  max      [I] max value.
 *
 * This function should be called only after calling hybrid_object_init() on &sem->ho.
 *
 * TODO: initing server-private semaphores is stupid here because calculate hash-base which won't be used.
 *
 */
NTSTATUS hybrid_semaphore_init(struct hybrid_semaphore *sem, unsigned int initial, unsigned int max)
{
    union shm_sync_value *value = sem->ho.value;

    if (max > (unsigned int)INT_MAX || initial > max)
        return STATUS_INVALID_PARAMETER;

    if (value)
    {
        value->data       = initial;
        value->flags_hash = hybrid_object_is_server_private(&sem->ho)
                          ? 0
                          : hash28(sem->ho.hash_base, 0, initial);
    }
    sem->max              = max;

    return STATUS_SUCCESS;
}

/******************************************************************
 *              xxxxxxxxxxx
 *
 * xxxxxxxxxxx
 *
 * PARAMS
 *
 */
static __noinline __cold NTSTATUS wine_sync_value_result_to_ntstatus(enum shm_sync_value_result value)
{
    switch ((int)value)
    {
    case SHM_SYNC_VALUE_SUCCESS:
        return STATUS_SUCCESS;

    case SHM_SYNC_VALUE_MOVED:
#if !WINE_SYNC_IS_SERVER
        return SHM_SYNC_VALUE_MOVED;
#else
        /* server should never get this flag, so fall-through to assert */
#endif
    case SHM_SYNC_VALUE_LOCKED:        /* check_data should intercept this on client, server shouldn't get it unexpectedly */
        /* intentional fall-through */
    case SHM_SYNC_VALUE_CORRUPTED:     return STATUS_FILE_CORRUPT_ERROR;

    /* a few NTSTATUS codes to pass on */
    case STATUS_TOO_MANY_THREADS:
    case STATUS_FILE_CORRUPT_ERROR:
        return (NTSTATUS)value;
    default:
        assert(0);
        exit(1);
    }
}

/******************************************************************************
 *              __hybrid_semaphore_op
 *
 * Perform any operation on a semaphore object.
 *
 * PARAMS
 *  sem      [I] The object to operate on
 *  pre_ptr  [O] Pointer to a buffer where the pre-operation value will be stored.
 *  post_ptr [O] (Optional) Pointer to a buffer where the post-operation value will be stored.
 *  change   [I] The change to (attemptto ) make. (e.g., 1 for a post, -1 for a get, etc.)
 *
 * If change == -1 and tryonly = 0, the function will return STATUS_SUCCESS upon success
 * and the caller must check cur->data -- if it is zero then the thread is not considered
 * "waiting" and an appropriate wait function should be called.
 *
 * RETURNS
 *  STATUS_SUCCESS
 *  STATUS_FILE_CORRUPT_ERROR
 *  STATUS_SEMAPHORE_LIMIT_EXCEEDED
 *  STATUS_WAS_LOCKED -- tryonly was non-zero and the semaphore is not signaled (count is not decremented)
 *
 * NOTE: fast path roughly 336 bytes on 64-bit with two function calls to hash28()
 */
NTSTATUS __hybrid_semaphore_op(struct hybrid_semaphore *sem, union shm_sync_value *pre_ptr, int change)
{
    struct hybrid_sync_object *ho = &sem->ho;
    enum shm_sync_value_result result;
    union shm_sync_value post;

    /* get can only decrement by one */
    assert( change >= 0 || change == -1 );

    do {
        /* initial volatile read */
        atomic_read( pre_ptr, ho->value );
        result = check_data( ho, pre_ptr, TRUE );
    } while (result == SHM_SYNC_VALUE_AGAIN);

    if (result)
        goto exit_error;

    do {
        int cur_value = pre_ptr->data;
        int new_value = cur_value + change;
        int flags     = 0;

        if (cur_value > (int)sem->max)
        {
            sync_fail(ho, "ERROR %s: data exceeds maximum value, (bug or corruption)\n", __func__);
            return STATUS_FILE_CORRUPT_ERROR;
        }

        /* check for overflow */
        if (new_value > (int)sem->max || (change > 0 ? new_value < cur_value : new_value > cur_value ))
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;

        /* trying to acquire signal, but not signaled */
        if (change < 0 && cur_value == 0)
        {
            /* server always uses transaction for (try)wait */
            assert(!WINE_SYNC_IS_SERVER);

            /* client will fail the operation */
            return STATUS_WAS_LOCKED;
        }

        result = sync_try_op(ho, pre_ptr, &post, new_value, flags);
    } while (result == SHM_SYNC_VALUE_AGAIN);

    if (result)
exit_error:
        return wine_sync_value_result_to_ntstatus(result);

    return STATUS_SUCCESS;
}

/******************************************************************
 *              hybrid_semaphore_release
 *
 * Do a semaphore post
 *
 * PARAMS
 *  sem     [I]  The semaphore
 *  count   [I]  Number of posts (since windows allows this to be > 1)
 *  prev    [O]  (Optional) the previous value of the semaphore
 *
 * NOTE: There is a possible issue here which may cause applications to sometimes behave differently
 * than on windows. We first perform a futex wake followed by a server wake. This may give processes
 * performing a local wait operation more of a chance of grabbing a contended semaphore than those
 * waiting on the server (e.g., thread A waiting locally for a single semaphore vs thread B waiting
 * on the server for multiple objects).
 *
 * We may want to consider some mechanism of deciding rather we wake a local or server thread
 * (possibly some round-robin) when we know that a thread is waiting on the server as well.
 */
NTSTATUS hybrid_semaphore_release(struct hybrid_semaphore *sem, unsigned int count, unsigned int *prev, int do_wake)
{
    NTSTATUS ret;
    union shm_sync_value pre;

    if (count > INT_MAX)
        return STATUS_INVALID_PARAMETER;

    ret = __hybrid_semaphore_op(sem, &pre, count);
    if (ret)
        return ret;

    if (prev)
        *prev = pre.data;

    if (do_wake)
        futex_wake(&sem->ho.value->data, count);

    if (pre.flags_hash & SHM_SYNC_VALUE_NOTIFY_SVR)
        return SHM_SYNC_VALUE_NOTIFY_SVR;
    else
        return STATUS_SUCCESS;
}

#define ONE_BILLION 1000000000ll

/* TODO: ugly copy/pasted from server, perhaps there's a better place for this as a non-static */
static void get_time(struct timespec *dest)
{
#ifdef HAVE_CLOCK_GETTIME
# ifdef CLOCK_MONOTONIC_RAW
    if (!clock_gettime( CLOCK_MONOTONIC_RAW, dest ))
        return;
# endif
    if (!clock_gettime( CLOCK_MONOTONIC, dest ))
        return;
#elif defined(__APPLE__)
    uint64_t now;
    static mach_timebase_info_data_t timebase;

    if (!timebase.denom)
        mach_timebase_info( &timebase );

    now = mach_absolute_time() * timebase.numer / timebase.denom;
    dest->tv_sec  = now / ONE_BILLION;
    dest->tv_nsec = now % ONE_BILLION;
    return;
# error FIXME: untested
#else
# error oops
#endif
    assert(0);
}

static void timespec_sub(struct timespec *dest, const struct timespec *a, const struct timespec *b)
{
    dest->tv_sec  = a->tv_sec  - b->tv_sec;
    dest->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (dest->tv_nsec < 0)
    {
        dest->tv_sec  -= 1;
        dest->tv_nsec += ONE_BILLION;
    }
}

static inline void timespec_remain(struct timespec *dest, const struct timespec *start, const struct timespec *duration)
{
    get_time(dest);
    timespec_sub(dest, dest, start);
    timespec_sub(dest, duration, dest);
}

/*
 * NOTE: fast path is 108 bytes with calls to get_time() and __hybrid_semaphore_op()
 *       contended path is 354 bytes
 *       eats 64 bytes of stack because struct timespec is huge
 */
NTSTATUS hybrid_semaphore_wait(struct hybrid_semaphore *sem, const struct timespec *timeout)
{
    union shm_sync_value pre;
    struct timespec start;
    struct timespec t;
    NTSTATUS ret;

    get_time(&start);

    for (;;) {
        int result;

        ret = __hybrid_semaphore_op(sem, &pre, -1);

        if (ret != STATUS_WAS_LOCKED)
            return ret;

        /* (re)calculate wait time */
        if (timeout)
        {
            timespec_remain(&t, &start, timeout);

            if (t.tv_sec < 0l)
                return STATUS_TIMEOUT;
        }

        result = futex_wait(&sem->ho.value->data, pre.data, timeout ? &t : NULL);
//fprintf(stderr, "%s: futex_wait completed with %d, volatile read flags = %x\n", __func__, result,
//    *((volatile int*)&sem->ho.value->flags_hash) & 0xf);
        if (!result)
            continue;

        switch (-result) {
            /* repeat if value changes or we are interrupted by a signal */
            case EINTR:
            case EWOULDBLOCK:
                continue;

            case ETIMEDOUT:
                return STATUS_TIMEOUT;
        }
    }
    return ret;
}

/* dump functions */
static void wine_sync_value_dump(const union shm_sync_value *value, char **start, const char *const end)
{
    int count;

    assert(start && *start && end);
    assert(end > *start);

    if (!value)
        count = snprintf(*start, end - *start, "(NULL)");
    else
        count = snprintf(*start, end - *start,
                         "%p {.data = 0x%08x, .flags_hash = 0x%08x}",
                         value, value->data, value->flags_hash);

    if (count < 0)
        perror("snprintf");
    else
        *start += count;
}

void hybrid_object_dump(const struct hybrid_sync_object *ho, char **start, const char *const end)
{
    int count;

    assert(start && *start && end);
    assert(end > *start);

    if (!ho)
        count = snprintf(*start, end - *start, "(NULL)");
    else
    {
        count = snprintf(*start, end - *start, "%p {value = %s", ho, ho->value ? "" : "(NULL)");
        if (count < 0)
            goto error;

        *start += count;

        if (ho->value)
            wine_sync_value_dump(ho->value, start, end);

        if (ho->value == &ho->private_value)
            count = snprintf(*start, end - *start,
                             " (--> &private_value), "
                             "flags_refcount = 0x%08x (.flags = 0x%02x, .refcount = %d)}",
                             ho->flags_refcount,
                             ho->flags_refcount & HYBRID_SYNC_FLAGS_MASK,
                             (int)(ho->flags_refcount) >> HYBRID_SYNC_FLAGS_BITS);
        else
            count = snprintf(*start, end - *start,
                             ", "
                             "flags_refcount = 0x%08x (.flags = 0x%02x, .refcount = %d), "
                             "hash_base = 0x%08x}",
                             ho->flags_refcount,
                             ho->flags_refcount & HYBRID_SYNC_FLAGS_MASK,
                             (int)(ho->flags_refcount) >> HYBRID_SYNC_FLAGS_BITS,
                             ho->hash_base);
    }

    if (count < 0)
error:
        perror("snprintf");
    else
        *start += count;
}

void hybrid_semaphore_dump(const struct hybrid_semaphore *sem, char **start, const char *const end)
{
    int count;

    assert(start && *start && end);
    assert(end > *start);

    if (!sem)
        count = snprintf(*start, end - *start, "(NULL)");
    else
    {
        count = snprintf(*start, end - *start, "%p {ho = ", sem);
        if (count < 0)
            goto error;

        *start += count;

        hybrid_object_dump( &sem->ho, start, end );
        count = snprintf(*start, end - *start, ", max = %08x}", sem->max);
    }

    if (count < 0)
error:
        perror("snprintf");
    else
        *start += count;
}

/* TODO: refactor wasteful duplicated code */
void hybrid_mutex_dump(const struct hybrid_mutex *mutex, char **start, const char *const end)
{
    int count;

    assert(start && *start && end);
    assert(end > *start);

    if (!mutex)
        count = snprintf(*start, end - *start, "(NULL)");
    else
    {
        count = snprintf(*start, end - *start, "%p {ho = ", mutex);
        if (count < 0)
            goto error;

        *start += count;

        hybrid_object_dump( &mutex->ho, start, end );
        count = snprintf(*start, end - *start, ", recursion_count = %u}", mutex->recursion_count);
    }

    if (count < 0)
error:
        perror("snprintf");
    else
        *start += count;
}

void shm_object_info_dump(const struct shm_object_info *info, char **start, const char *const end)
{
    int count;

    assert(start && *start && end);
    assert(end > *start);

    count = snprintf(*start, end - *start,
                     "%p {"
                     "shm_id = %016llx, "
                     "offset = %08x, "
                     "size = %08x, "
                     "fd = %d, "
                     "ptr = %p, "
                     "flags = %08x, "
                     "hash_base = %08x}",
                     info,
                     (long long)info->shm_id,
                     info->offset,
                     info->size,
                     info->fd,
                     info->ptr,
                     info->flags,
                     info->hash_base);

    if (count < 0)
        perror("snprintf");
    else
        *start += count;
}
