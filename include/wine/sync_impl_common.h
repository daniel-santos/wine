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

#ifdef IDE_PARSER
/* Aids to KDevelop parsing.  */
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
static enum shm_sync_value_result
check_data_anomalous(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
		     enum shm_sync_value_result flags, int wait_lock);

#if !WINESERVER /* client only */
static struct
{
    /* Function to get the new shared memory and change the value pointer. This
     * is callable by any function that attempts to dereference the value
     * pointer via the path check_data --> check_data_trans -->
     * check_data_anomalous --> hybrid_object_do_move */
    NTSTATUS (*move)( struct hybrid_sync_object *ho, struct shm_object_info *info );
    NTSTATUS (*destroy)( struct hybrid_sync_object *ho );
    void (*server_wake)( struct hybrid_sync_object *ho );
} hybrid_object_client_fns = { NULL, NULL };
#endif /* !WINESERVER (client only) */

/* where the server writes the last CPU number and the client reads it */
static volatile unsigned int *last_server_cpu_ptr = NULL;

/******************************************************************
 *              sync_impl_init
 *
 * Initialize static values in sync_impl.h translation unit. Call (at least) once from the .c file
 * you include this from.
 */
static void sync_impl_init( NTSTATUS (*move)( struct hybrid_sync_object *ho, struct shm_object_info *info ),
                            NTSTATUS (*destroy)( struct hybrid_sync_object *ho ),
			    void (*server_wake)( struct hybrid_sync_object *ho ),
                            volatile unsigned int *_last_server_cpu_ptr )
{
#if !WINESERVER
    hybrid_object_client_fns.move    	   = move;
    hybrid_object_client_fns.destroy	   = destroy;
    hybrid_object_client_fns.server_wake = server_wake;
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
    barrier();

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

static inline int hso_client_futex_wait( union hso_atomic *atomic, union hso_atomic *pre,
                                         struct timespec *timeout )
{
    return futex_wait( hso_atomic_get_wait_addr( atomic ),
                       *hso_atomic_get_wait_addr( pre ),
                       timeout);
}

static inline int hso_client_futex_wake( union hso_atomic *atomic )
{
    return futex_wake( hso_atomic_get_wait_addr( atomic ), INT_MAX);
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

    if (0)
    {
	/* slight modification of algo for speed, but probably poor uniqueness */
	base ^= data;
	base *= FNV_32_PRIME;
	base ^= flags;
	base *= FNV_32_PRIME;

	return (base << SHM_SYNC_VALUE_FLAGS_BITS) | flags;
    }
    else
    {
	/* This implementation would be slower, but use the FVN-1a unmodified */
	unsigned char in[5];
	*((unsigned int*)in) = data;
	in[4] = (unsigned char)flags;

	return (fnv1a_hash32(base, in, sizeof(in)) << SHM_SYNC_VALUE_FLAGS_BITS) | flags;
    }
}

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
    if (SYNC_DEBUG_ASSERTS)
        assert(0);

    /* this bit lets all processes know that we're corrupted */
    interlocked_test_and_set_bit(&ho->atomic.value->flags_hash, SHM_SYNC_VALUE_CORRUPTED_BIT);

    /* this bit is for the local process, because now we don't trust that the
     * shared bit will not be overwritten */
    interlocked_test_and_set_bit((int*)&ho->atomic.flags_refcounts, HYBRID_SYNC_BAD);

    return SHM_SYNC_VALUE_CORRUPTED;
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





/* TODO: Move to port.h.  */
static inline __int64 locked_read64( __int64 *addr )
{
#if 0 && (defined(__x86_64__) || defined(__aarch64__) || defined(_WIN64))
    __int64 ret;
    __asm__ __volatile__( "lock; movq (%1),%0": "=r" (ret) : "r"(addr) : );
    return ret;
#else
    return interlocked_cmpxchg64( addr, *addr, *addr );
#endif
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
 * maybe_stale  [I] Set to true if the pre value was obtained by a normal
 *                  read, false if it was obtained by an atomic instruction.
 *                  When true, anomalous conditions result in
 *                  SHM_SYNC_VALUE_AGAIN.
 *
 * Returns
 *      SHM_SYNC_VALUE_SUCCESS          if the caller should proceed as normal
 *      SHM_SYNC_VALUE_AGAIN            restart operation
 *      SHM_SYNC_VALUE_CORRUPTED        object is corrupt
 *      SHM_SYNC_VALUE_FAIL             client: object is unusable due to error in migration
 */
static FORCEINLINE enum shm_sync_value_result
check_data(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr, int maybe_stale, int wait_lock)
{
    int flags;
    int flags_hash;
    int hash_base            = ho->hash_base;
    int anomalous_flags_mask = SHM_SYNC_VALUE_MOVED | SHM_SYNC_VALUE_CORRUPTED;

    if (0)
    {
again:
        pre_ptr->int64 = locked_read64( &ho->atomic.value->int64 );
        maybe_stale = FALSE;
    }

    /* verify no corruption */
    flags      = pre_ptr->flags_hash & SHM_SYNC_VALUE_FLAGS_MASK;
    flags_hash = (int)hash28(hash_base, flags, pre_ptr->data);
    if (unlikely(pre_ptr->flags_hash != flags_hash))
    {
        if (maybe_stale)
            goto again;

        bad_hash(ho, pre_ptr, flags_hash);
        return SHM_SYNC_VALUE_CORRUPTED;
    }

    if (!WINESERVER)
        anomalous_flags_mask |= SHM_SYNC_VALUE_LOCKED;

    if (pre_ptr->flags_hash & anomalous_flags_mask)
    {
        if (maybe_stale)
            goto again;

        return check_data_anomalous(ho, pre_ptr, pre_ptr->flags_hash, wait_lock);
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
sync_try_op(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr, int maybe_stale,
            union shm_sync_value *post_ptr, int data, int flags)
{
    union shm_sync_value new_value;
    union shm_sync_value updated_value;
    enum shm_sync_value_result ret = SHM_SYNC_VALUE_SUCCESS;

    ret = check_data( ho, pre_ptr, maybe_stale, TRUE );
    if (ret)
        return ret;

    if (!WINESERVER)
        /* if any of these flags are set, client should not be attempting any operation */
        assert(!(flags & (SHM_SYNC_VALUE_LOCKED | SHM_SYNC_VALUE_MOVED | SHM_SYNC_VALUE_CORRUPTED)));

    new_value.flags_hash = hash28(ho->hash_base, flags, data);
    new_value.data = data;

    updated_value.int64 = interlocked_cmpxchg64(&ho->atomic.value->int64,
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
 *  info        [I]     If private is set, ptr should be NULL and the object will be initialized
 *                      as a stub that simply indicates server calls should be used.  Otherwise,
 *                      ptr, should point to the shared memory object, and shm_id and offset
 *                      should be set.
 */
static void hybrid_object_init(struct hybrid_sync_object *ho, struct shm_object_info *info)

{
    /* Must either be private or have a pointer to shared memory. */
    assert( !!info->private ^ !!info->ptr );

    if (info->private) {
        ho->atomic.value = NULL;
        ho->hash_base = 0;
    } else {
        ho->atomic.value = info->ptr;
        ho->hash_base = fnv1a_hash32( FNV1A_32_INIT, info->hash_base_in,
                                      sizeof(info->hash_base_in) );
    }
    /* Server does not use ho->atomic.flags_refcount for reference counting, but client
     * does, so increment it only for client. */
    ho->atomic.flags_refcounts = hso_atomic_make_flags_refcounts(0, !WINESERVER, 0);
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
    union shm_sync_value *value = sem->ho.atomic.value;

    assert( value );
    if (max > (unsigned int)INT_MAX || initial > max)
        return STATUS_INVALID_PARAMETER;

    value->data       = initial;
    value->flags_hash = hash28(sem->ho.hash_base, 0, initial);
    sem->max          = max;

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
    case SHM_SYNC_VALUE_FAIL:
	/* TODO: handle failure with retry?  */
    case SHM_SYNC_VALUE_CORRUPTED:
        return STATUS_FILE_CORRUPT_ERROR;

    /* a few NTSTATUS codes to pass on */
    case STATUS_TOO_MANY_THREADS:
    case STATUS_FILE_CORRUPT_ERROR:
        return (NTSTATUS)value;

    /* all other values should be managed by check_data */
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
NTSTATUS __hybrid_semaphore_op(struct hybrid_semaphore *sem, union shm_sync_value *pre_ptr, int maybe_stale, int change)
{
    struct hybrid_sync_object *ho = &sem->ho;
    enum shm_sync_value_result result;
    union shm_sync_value post;
    NTSTATUS ret;

    /* get can only decrement by one */
    assert( change >= 0 || change == -1 );

    do {
        int cur_value  = pre_ptr->data;         /* Current (known) value.  */
        int new_value  = cur_value + change;    /* Proposed new value.  */
        int swap_value = cur_value;             /* Value to be used in swap.  */
        int flags      = 0;

        ret = STATUS_SUCCESS;

        if (cur_value > (int)sem->max)
            ret = STATUS_FILE_CORRUPT_ERROR;

        /* Check for overflow.  */
        else if (new_value > (int)sem->max || (change > 0 ? new_value < cur_value
                                                          : new_value > cur_value ))
            ret = STATUS_SEMAPHORE_LIMIT_EXCEEDED;

        /* Trying to acquire signal, but not signaled.  */
        else if (change == -1 && cur_value == 0)
        {
            /* server always uses transaction for (try)wait */
            assert(!WINESERVER);

            /* client will fail the operation */
            ret = STATUS_WAS_LOCKED;
        }
        else
            swap_value = new_value;

        result = sync_try_op(ho, pre_ptr, maybe_stale, &post, swap_value, flags);
        maybe_stale = FALSE;
    } while (result == SHM_SYNC_VALUE_AGAIN);

    if (result)
        return wine_sync_value_result_to_ntstatus(result);
    else if (ret)
    {
        if (ret == STATUS_FILE_CORRUPT_ERROR)
            sync_fail(ho, "ERROR %s: data exceeds maximum value, (bug or corruption)\n", __func__);
        return ret;
    }
    else
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
NTSTATUS hybrid_semaphore_release( struct hybrid_semaphore *sem, unsigned int count,
                                   unsigned int *prev )
{
    NTSTATUS ret;
    union shm_sync_value pre = *sem->ho.atomic.value;

    if (count > INT_MAX)
        return STATUS_INVALID_PARAMETER;


    ret = __hybrid_semaphore_op(sem, &pre, TRUE, count);
    if (ret)
        return ret;

    if (prev)
        *prev = pre.data;

#if !WINESERVER
    if (pre.flags_hash & SHM_SYNC_VALUE_WAKE_SERVER)
        hybrid_object_client_fns.server_wake( &sem->ho );
#endif

    futex_wake(&sem->ho.atomic.value->data, count);
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

NTSTATUS hybrid_semaphore_wait(struct hybrid_semaphore *sem, const struct timespec *timeout)
{
    union shm_sync_value pre = *sem->ho.atomic.value;
    struct timespec start;
    struct timespec t;
    NTSTATUS ret;

    get_time(&start);

    for (;;) {
        int result;
        ret = __hybrid_semaphore_op(sem, &pre, TRUE, -1);

        if (ret != STATUS_WAS_LOCKED)
            return ret;

        /* (re)calculate wait time */
        if (!timeout)
            ;
        else if (timeout->tv_sec == 0 && timeout->tv_nsec == 0)
            return STATUS_TIMEOUT;
        else
        {
            /* TODO: Refactor this.  We only need to calculate the end time at the start of the
             * function and then test to see if we've reached that time. */
            timespec_remain(&t, &start, timeout);

            if (t.tv_sec < 0l)
                return STATUS_TIMEOUT;
        }

        result = futex_wait(&sem->ho.atomic.value->data, pre.data, timeout ? &t : NULL);
	pre = *(volatile union shm_sync_value*)sem->ho.atomic.value;
        switch (-result) {
	    case 0:
		continue;

            /* repeat if value changes or we are interrupted by a signal */
            case EWOULDBLOCK:
            case EINTR:
                continue;

            case ETIMEDOUT:
                return STATUS_TIMEOUT;
        }
    }
    return ret;
}




#if 0

/******************************************************************************
 *              __hybrid_mutex_op
 *
 * Perform any operation on a mutex object.
 */
NTSTATUS __hybrid_mutex_op(struct hybrid_mutex *mutex, union shm_sync_value *pre_ptr, int maybe_stale, int change)
{
    struct hybrid_sync_object *ho = &mutex->ho;
    enum shm_sync_value_result result;
    union shm_sync_value post;
    NTSTATUS ret;

    assert( change == 1 || change == -1 );

    do {
        int cur_owner  = pre_ptr->data;         /* Current (known) value.  */
        int new_value  = cur_value + change;    /* Proposed new value.  */
        int swap_value = cur_value;             /* Value to be used in swap.  */
        int flags      = 0;
#if 0
#endif
        ret = STATUS_SUCCESS;

        if (cur_value > (int)sem->max)
            ret = STATUS_FILE_CORRUPT_ERROR;

        /* Check for overflow.  */
        else if (new_value > (int)sem->max || (change > 0 ? new_value < cur_value
                                                          : new_value > cur_value ))
            ret = STATUS_SEMAPHORE_LIMIT_EXCEEDED;

        /* Trying to acquire signal, but not signaled.  */
        else if (change < 0 && cur_value == 0)
        {
            /* server always uses transaction for (try)wait */
            assert(!WINESERVER);

            /* client will fail the operation */
            ret = STATUS_WAS_LOCKED;
        }
        else
            swap_value = new_value;

        result = sync_try_op(ho, pre_ptr, maybe_stale, &post, swap_value, flags);
        maybe_stale = FALSE;
    } while (result == SHM_SYNC_VALUE_AGAIN);

    if (result)
        return wine_sync_value_result_to_ntstatus(result);
    else if (ret)
    {
        if (ret == STATUS_FILE_CORRUPT_ERROR)
            sync_fail(ho, "ERROR %s: data exceeds maximum value, (bug or corruption)\n", __func__);
        return ret;
    }
    else
        return STATUS_SUCCESS;
}

#endif

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
        count = snprintf(*start, end - *start, "%p {value = %s", ho, ho->atomic.value ? "" : "(NULL)");
        if (count < 0)
            goto error;

        *start += count;

        if (ho->atomic.value)
            wine_sync_value_dump(ho->atomic.value, start, end);

        count = snprintf(*start, end - *start,
                         ", "
                         "flags_refcounts = 0x%08lx (.flags = 0x%02lx, .refcount = %lu, .waiters = %lu), "
                         "hash_base = 0x%08x}",
                         ho->atomic.flags_refcounts,
                         hso_atomic_get_flags( &ho->atomic ),
                         hso_atomic_get_refcount( &ho->atomic ),
                         hso_atomic_get_waitcount( &ho->atomic ),
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
