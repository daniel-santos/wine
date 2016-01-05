/*
 * Client implementation for hybrid, migratory synchronization objects.
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

#define WINE_SYNC_IS_SERVER 0
#include "wine/sync_impl_common.h"


/**************** client-only functions ****************/

static __must_check NTSTATUS hybrid_object_release(struct hybrid_sync_object *ho);
static __must_check NTSTATUS hybrid_object_grab(struct hybrid_sync_object *ho);
static __must_check enum shm_sync_value_result hybrid_object_do_move(struct hybrid_sync_object *ho);
static __noinline void hybrid_object_do_move_wait(struct hybrid_sync_object *ho);
static enum shm_sync_value_result hybrid_object_wait_global_lock(struct hybrid_sync_object *ho,
                                                                 union shm_sync_value *pre_ptr);

/* change accessible bit and return the previous value */
static inline int hybrid_object_mark_accessible( struct hybrid_sync_object *ho, int value )
{
    return value
        ? interlocked_test_and_set_bit  ( (int*)&ho->flags_refcount, HYBRID_SYNC_ACCESSIBLE_BIT )
        : interlocked_test_and_reset_bit( (int*)&ho->flags_refcount, HYBRID_SYNC_ACCESSIBLE_BIT );
}

/* cold portion of check_data */
static __cold __noinline enum shm_sync_value_result
check_data_anomalous(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
                     enum shm_sync_value_result flags, int wait_lock)
{
    if (flags & SHM_SYNC_VALUE_CORRUPTED)
        return sync_fail(ho, "ERROR %s: corrupted bit set\n", __func__);

    if (flags & SHM_SYNC_VALUE_LOCKED)
    {
        if (wait_lock)
            return hybrid_object_wait_global_lock(ho, pre_ptr);
        else
            return SHM_SYNC_VALUE_LOCKED;
    }

    if (flags & SHM_SYNC_VALUE_MOVED)
            return hybrid_object_do_move(ho);

    unreachable();
    assert(0);
    for(;;);
}


/* wait for ho->value->flags_hash & SHM_SYNC_VALUE_LOCKED to clear
 *
 * The calling thread should have made a successful call to hybrid_object_grab() prior to calling
 * this function (ho->value pointer is accessed non-atomically).
 *
 * RETURNS:
 *  SHM_SYNC_VALUE_CORRUPTED    If the corrupted bit was set
 *  SHM_SYNC_VALUE_AGAIN        In all other cases
 */
static enum shm_sync_value_result hybrid_object_wait_global_lock(struct hybrid_sync_object *ho,
                                                                 union shm_sync_value *pre_ptr)
{
    enum shm_sync_value_result result;
    const unsigned int MAX_SPIN_COUNT = 128;
    unsigned int spincount            = MAX_SPIN_COUNT;
    unsigned int curcpu               = sched_getcpu();
    unsigned int server_cpu           = last_server_cpu_ptr ? *last_server_cpu_ptr : -1u;

    assert( !hybrid_object_is_server_private(ho) );

    /* This function is optimized to expect the server to generally not be prepempted in the middle
     * of a hybrid object transaction, so will first spin waiting for the lock bit to clear.
     * However, we skip this and to straight to a futex wait if:
     *  * the machine is uniprocessor,
     *  * sched_getcpu() fails,
     *  * the server was last running on this CPU, or
     *  * we spin MAX_SPIN_COUNT times.
     */

    if (NtCurrentTeb()->Peb->NumberOfProcessors == 1 || curcpu != -1u || server_cpu == curcpu)
        spincount = 0;

    for(;;)
    {
        atomic_read(&pre_ptr->int64, &ho->value->int64);
        result = check_data(ho, pre_ptr, FALSE);
        if (result != SHM_SYNC_VALUE_LOCKED)
            return (result == SHM_SYNC_VALUE_SUCCESS) ? SHM_SYNC_VALUE_AGAIN : result;

        if (likely(spincount))
        {
            --spincount;
            cpu_relax();    /* use less power if CPU is capable */
        }
        else
        {
            struct timespec timeout;

            timeout.tv_sec = 60;
            timeout.tv_nsec = 0;

            /* we wait on the flags/hash because that is what will change and be
            * notified when the server is done */
            result = futex_wait( (int*)&ho->value->flags_hash, (int)pre_ptr->flags_hash, &timeout);
            switch (-result)
            {
                case ETIMEDOUT:
                    fprintf(stderr, "%s: WARNING: waiting server lock for more than 60 seconds "
                                    "(system busy, server hung, or shm data corrupted). "
                                "pid=%d, tid=%ld, ho=%p, ho->value=%p *ho->value=%016llx\n",
                                __func__, getpid(), syscall(SYS_gettid), ho, ho->value,
                                (long long)ho->value->int64);

                case EWOULDBLOCK:
                case EINTR:
                    break;
            }
        }
    }
}

/* wait for another thread of this process to get the new shm location
 * of the sync object, set the new ho->value pointer and clear the
 * HYBRID_SYNC_LOCKED_BIT
 *
 * this is where client threads wait for another thread in the process to complete a move
 */
static void __noinline hybrid_object_do_move_wait(struct hybrid_sync_object *ho)
{
    struct timespec timeout;
    unsigned int curfr;

    timeout.tv_sec = 60;
    timeout.tv_nsec = 0;

    /* the move operation requires a server call so there's no sense in spinning for this lock */

    for (;;)
    {
        int result;

        curfr = interlocked_xchg_add((int*)&ho->flags_refcount, 0);
        //atomic_read(&curfr, (int*)&ho->flags_refcount);
        if (!(curfr & HYBRID_SYNC_LOCKED_BIT))
            break;

        result = futex_wait( (int*)&ho->flags_refcount, curfr, &timeout );
        if (unlikely(result))
        {
            switch (-result)
            {
            case ETIMEDOUT:
                fprintf(stderr, "%s: WARNING: waiting local lock for more than 60 seconds "
                                "(system busy, server hung, or memory corrupted). "
                                "pid=%d, tid=%ld, ho=%p, ho->flags_refcount=%08x\n",
                                __func__, getpid(), syscall(SYS_gettid), ho, ho->flags_refcount);
            case EWOULDBLOCK:
            case EINTR:
                break;
            }
        }
    }
}

/* do_move() and do_move_wait() are sloppy but will be re-written so that all of
 * the futex/sleeping/signaling stuff done here and in criticalsection.c are
 * using the same code.
 *
 * this is only called when refcount (flags_refcount) is already incremented
 *
 *
 */
static __must_check enum shm_sync_value_result hybrid_object_do_move( struct hybrid_sync_object *ho )
{
    int locked;
    struct timespec timeout;
    unsigned int curfr;
    unsigned int count;
    int skip_wake = 0;
    enum shm_sync_value_result ret = SHM_SYNC_VALUE_AGAIN;

    locked = interlocked_test_and_set_bit((int *)&ho->flags_refcount, HYBRID_SYNC_LOCKED_BIT);

    /* if already locked, then another thread is doing it, wait */
    if (locked)
    {
        NTSTATUS result;
//fprintf(stderr, "%s: late bird\n", __func__);

assert_not_doing_move(ho);
        if ((result = hybrid_object_release(ho)))
            return result;

        hybrid_object_do_move_wait( ho );

        if ((result = hybrid_object_grab(ho)))
            return result;

assert_not_doing_move(ho);
        return SHM_SYNC_VALUE_AGAIN;
    }
//fprintf(stderr, "%s: early bird\n", __func__);

    /* else, we got the lock, so are responsible for the move */

    timeout.tv_sec  = 4;
    timeout.tv_nsec = 100 * 1000 * 1000; /* 100 milliseconds should be a typical max under normal circumstances */

    /* Get all other threads of this process out of the object -- wake threads
     * that are sleeping on &ho->value.data so that they can decrement
     * ho->flags_count (by 1 << HYBRID_SYNC_FLAGS_BITS of course) and then wait
     * on that address. Once they are out, we can do the move and then wake
     * them back up to complete their operations using the modified object.
     *
     * waking on &ho->value.data can result in us waking threads of other
     * processes too, but that's OK.
     *
     * NOTE: this could possibly be optimized with FUTEX_CMP_REQUEUE, but nobody cares.
     */
    for (;;)
    {
        int result;

        curfr = interlocked_xchg_add((int*)&ho->flags_refcount, 0);
//    fprintf(stderr, " %lx:%p:%08x ", syscall(SYS_gettid), ho, curfr);

        //atomic_read( &curfr, &ho->flags_refcount );
        count = curfr >> HYBRID_SYNC_FLAGS_BITS;
        if (count == 1) /* one because we don't decrement for *this* thread */
            break;

        /* we only know the number of threads in this process that have grabbed the object (and
         * thus, possibly waiting on ho->value) so this may need to be repeated. */
        if (!skip_wake)
            futex_wake( &ho->value->data, INT_MAX );

        skip_wake = 0;

        /* wait on the process-local ho->flags_refcount value */
        result = futex_wait((int *)&ho->flags_refcount, curfr, &timeout);
        if (result)
        {
            switch (-result)
            {
            case EWOULDBLOCK:
                /* value changed, we only need to re-read and repeat, but as we
                 * haven't slept since the last call to wake, we will not call
                 * wake again. */
                skip_wake = 1;
            case ETIMEDOUT:
            case EINTR:
                continue;
            }
        }
    }
    assert(!interlocked_test_and_set_bit((int *)&ho->flags_refcount, HYBRID_SYNC_DBG_DOING_MOVE_BIT));

//    atomic_read( dest, &ho->value->int64 );

    /* in this state only the current thread has the right to change the
     * ho->value pointer. It is now the below callback function's responsibility
     * to:
     * . release the shared memory via virtual.c (or at least the reference to it)
     * . make the server call to
     *   * inform server that the previous shared memory is no longer being used.
     *   * request the new storage of the sync object. This may be that it has
     *     become private in server memory (server calls for all operations) or
     *     a different fd and offset in another shared memory location.
     * . finally, the callback will obtain the shared memory from virtual.c (if
     *   applicable) and upset the value pointer. It will be NULL if the object
     *   has moved to the server (as a server-private object) and point to the
     *   new location in shared memory otherwise.
     *
     * When the callback returns, the object will be useable again (unless an
     * error occurs).
     */

    if (hybrid_object_client_fns.move( ho ))
    {
        interlocked_test_and_set_bit( (int *)&ho->flags_refcount, HYBRID_SYNC_BAD_BIT );
        ret = SHM_SYNC_VALUE_FAIL;
    }

    assert(interlocked_test_and_reset_bit((int *)&ho->flags_refcount, HYBRID_SYNC_DBG_DOING_MOVE_BIT));

    /* This interlocked provides implicit barrier for changing the value pointer and hash_base
     * in do_move(). */
    interlocked_test_and_reset_bit( (int *)&ho->flags_refcount, HYBRID_SYNC_LOCKED_BIT );
    futex_wake( (int *)&ho->flags_refcount, INT_MAX);

    return ret;
}

/***********************************************************************
 *           hybrid_object_grab
 *
 * Begin a client-side operation, incrementing refcount and managing exceptional
 * conditions.
 *
 * PARAMS
 *  ho          [I]    The object
 *
 * A successful call to this function allows the thread to safely read and
 * dereference the ho->value pointer. Each successful call to this function
 * should be paired by a call to hybrid_object_release(). If another thread
 * (of this process) has the object locked (via ho->flags_refcount &
 * HYBRID_SYNC_LOCKED) then this function will block until the condition is
 * cleared.
 *
 * RETURN
 *  SUCCESS: 0
 *  FAILURE:
 *     STATUS_FILE_CORRUPT_ERROR        shared memory data is corrupt
 *     STATUS_TOO_MANY_THREADS          more than 134m threads or unpaired begin/end calls
 *
 * NOTE: fast path built with gcc on x86_64 is 65 bytes
 */
static __must_check NTSTATUS hybrid_object_grab(struct hybrid_sync_object *ho)
{
    unsigned int curfr;
    unsigned int oldfr;
    unsigned int newfr;

start_over:
    curfr = interlocked_xchg_add((int *)&ho->flags_refcount, 0);
    //atomic_read( &curfr, &ho->flags_refcount );

    do {
        unsigned int refcount = curfr >> HYBRID_SYNC_FLAGS_BITS;

        if (unlikely(curfr & HYBRID_SYNC_BAD))
            return STATUS_FILE_CORRUPT_ERROR;

        /* should actually only occur due to an error in the code (134 million is a lot of threads) */
        /* TODO: decide: fail an assert or return STATUS_TOO_MANY_THREADS? */
        if (1)
            assert( refcount < HYBRID_SYNC_MAX_REFCOUNT );
        else if (unlikely(refcount >= HYBRID_SYNC_MAX_REFCOUNT))
            return STATUS_TOO_MANY_THREADS;

        if (unlikely(curfr & HYBRID_SYNC_LOCKED))
        {
            hybrid_object_do_move_wait(ho);
            goto start_over;
        }

        oldfr  = newfr = curfr;
        newfr += 1u << HYBRID_SYNC_FLAGS_BITS;

        curfr = interlocked_cmpxchg((int *)&ho->flags_refcount, newfr, curfr);
    } while (unlikely( curfr != oldfr ));
    //fprintf(stderr, " %lx:%p:begin ", syscall(SYS_gettid), ho);

    return STATUS_SUCCESS;
}

/* End a client-side operation, decrementing refcount
 *
 * RETURN
 *  SUCCESS: 0
 *  FAILURE:
 *     STATUS_FILE_CORRUPT_ERROR        shared memory data is corrupt
 *     STATUS_TOO_MANY_THREADS          more than 134m threads or unpaired begin/end calls
 *
 * fast path built with gcc on x86_64 is 61 bytes
 */
static __must_check NTSTATUS hybrid_object_release(struct hybrid_sync_object *ho)
{
    unsigned int curfr;
    unsigned int oldfr;
    unsigned int newfr;

    curfr = interlocked_xchg_add((int *)&ho->flags_refcount, 0);
    //atomic_read( &curfr, &ho->flags_refcount );

    do {
        unsigned int refcount = curfr >> HYBRID_SYNC_FLAGS_BITS;

        if (unlikely( curfr & HYBRID_SYNC_BAD ))
            return STATUS_FILE_CORRUPT_ERROR;

        /* should always be at least one here */
        assert(refcount > 0);

        oldfr = newfr = curfr;
        newfr -= 1u << HYBRID_SYNC_FLAGS_BITS;

        /* we can't use xadd for this because we need to know if HYBRID_SYNC_LOCKED
         * gets set by another thread */
        curfr = interlocked_cmpxchg((int *)&ho->flags_refcount, newfr, curfr);
    } while (unlikely( curfr != oldfr ));

    /* if refcount is zero and both HYBRID_SYNC_ACCESSIBLE and HYBRID_SYNC_LOCKED bits are cleared
     * then this object is ready to destroy */
    if ((newfr >> HYBRID_SYNC_FLAGS_BITS) == 0 && !(newfr & (HYBRID_SYNC_ACCESSIBLE | HYBRID_SYNC_LOCKED)))
        hybrid_object_client_fns.destroy( ho );

    return STATUS_SUCCESS;
}
