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

#include "wine/sync_impl_common.h"

// struct hso_client_opdata {}; */


/**************** client-only functions ****************/

static __must_check NTSTATUS hybrid_object_release(struct hybrid_sync_object *ho, int delist);
static __must_check NTSTATUS hybrid_object_grab(struct hybrid_sync_object *ho);
static __must_check NTSTATUS hybrid_object_do_move( struct hybrid_sync_object *ho, union hso_atomic *pre );
static __noinline void hybrid_object_do_move_wait(struct hybrid_sync_object *ho, union hso_atomic *pre);
static enum shm_sync_value_result hybrid_object_wait_global_lock(struct hybrid_sync_object *ho,
                                                                 union shm_sync_value *pre_ptr);
typedef enum shm_sync_value_result (*hso_client_op_callback_t)(union hso_atomic *pre, union hso_atomic *_new, NTSTATUS *ret);

/* cold portion of check_data */

/*
 * returns
 * 	SHM_SYNC_VALUE_LOCKED
 * 	SHM_SYNC_VALUE_AGAIN
 * 	SHM_SYNC_VALUE_CORRUPTED
 *
 */
static __cold __noinline enum shm_sync_value_result
check_data_anomalous(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
                     enum shm_sync_value_result flags, int wait_lock)
{
    if (flags & SHM_SYNC_VALUE_CORRUPTED)
        return sync_fail(ho, "ERROR %s: corrupted bit set\n", __func__);

    if (flags & SHM_SYNC_VALUE_LOCKED)
    {
        if (wait_lock)
            return hybrid_object_wait_global_lock( ho, pre_ptr );
        else
            return SHM_SYNC_VALUE_LOCKED;
    }

    if (flags & SHM_SYNC_VALUE_MOVED)
    {
        union hso_atomic client_value = ho->atomic;
	NTSTATUS nts = hybrid_object_do_move( ho, &client_value );
	switch (nts)
	{
	    case STATUS_SUCCESS:
                pre_ptr->int64 = locked_read64( &ho->atomic.value->int64 );
		return SHM_SYNC_VALUE_AGAIN;

	    //case STATUS_TOO_MANY_THREADS:
	    //case STATUS_WAS_LOCKED:
	    case STATUS_FILE_CORRUPT_ERROR:
		return SHM_SYNC_VALUE_CORRUPTED;

	    default:
                fprintf(stderr, "hybrid_object_do_move returned %08x\n", nts);
		/* no other values expected */
		assert (0);
	}
    }

    unreachable();
    assert( 0 );
    exit( -1 );
}


enum hso_client_op_enum {
    HSO_CLIENT_OP_LIST,
    HSO_CLIENT_OP_RELEASE_DELIST,
    HSO_CLIENT_OP_GRAB,
    HSO_CLIENT_OP_RELEASE,
    HSO_CLIENT_OP_LOCK,
    HSO_CLIENT_OP_LOCK_WAIT_BEGIN,
    HSO_CLIENT_OP_LOCK_WAIT_END,

//    HSO_CLIENT_OP_LOCK_WAIT_REFCOUNT,
//    HSO_CLIENT_OP_WAIT_MOVE,
    HSO_CLIENT_OP_UNLOCK
};

/*
 * Possible return values:
 *	STATUS_SUCCESS
 * 	STATUS_FILE_CORRUPT_ERROR	value's HYBRID_SYNC_BAD bit set (any operation except
 * 					HSO_CLIENT_OP_RELEASE_DELIST, case HSO_CLIENT_OP_RELEASE or
 * 					HSO_CLIENT_OP_UNLOCK)
 * 	STATUS_WAS_LOCKED		client object was locked (any operation except HSO_CLIENT_OP_UNLOCK)
 * 	STATUS_TOO_MANY_THREADS		Only on HSO_CLIENT_OP_GRAB
 */
static __must_check NTSTATUS
hso_client_op( struct hybrid_sync_object *ho, union hso_atomic *pre, enum hso_client_op_enum op,
               union shm_sync_value **ret_value, union shm_sync_value *new_value )
{
    int repeat;
    union hso_atomic _new;


    //fprintf(stderr, "hso_client_op START, %p, %p, %d\n", ho, pre, op);

    do {
        unsigned long old;
        unsigned long flags    = hso_atomic_get_flags( pre );
	unsigned long refcount = hso_atomic_get_refcount( pre );
        unsigned long waiters  = hso_atomic_get_waitcount( pre );


	/* Validate accessible bit.  */
	if (op == HSO_CLIENT_OP_LIST)
	    assert( !(flags & HYBRID_SYNC_ACCESSIBLE) );
	else if (!(flags & HYBRID_SYNC_ACCESSIBLE))
	    switch (op)
	    {/* FIXME: dunno */
	    case HSO_CLIENT_OP_GRAB:
		//return STATUS_INVALID_HANDLE;
	    default: break;
	    }

	/* Validate refcount.  */
	switch (op) {
	case HSO_CLIENT_OP_LIST:
	    assert( refcount == 1 );
	    break;
	case HSO_CLIENT_OP_UNLOCK:
	    assert( refcount == 1 );
	    break;

        case HSO_CLIENT_OP_LOCK_WAIT_END:
            assert( waiters > 0 );
            break;

        case HSO_CLIENT_OP_LOCK_WAIT_BEGIN:
	case HSO_CLIENT_OP_LOCK:
	case HSO_CLIENT_OP_RELEASE:
	case HSO_CLIENT_OP_RELEASE_DELIST:
	    assert( refcount > 0 );
	    break;

	case HSO_CLIENT_OP_GRAB:
	    break;
	};

	/* Check for bad object.  */
        if (unlikely(flags & HYBRID_SYNC_BAD))
	    switch (op) {
	    case HSO_CLIENT_OP_LIST:
	    case HSO_CLIENT_OP_GRAB:
	    case HSO_CLIENT_OP_LOCK:
            case HSO_CLIENT_OP_LOCK_WAIT_BEGIN:
            case HSO_CLIENT_OP_LOCK_WAIT_END:
		return STATUS_FILE_CORRUPT_ERROR;

	    case HSO_CLIENT_OP_RELEASE_DELIST:
	    case HSO_CLIENT_OP_RELEASE:
	    case HSO_CLIENT_OP_UNLOCK:
		break;
	    };

	/* Check if object is locked.  */
	if (unlikely( flags & HYBRID_SYNC_LOCKED ))
        {
	    switch (op)
	    {
            case HSO_CLIENT_OP_GRAB:
            case HSO_CLIENT_OP_LOCK:
            case HSO_CLIENT_OP_LIST:
            case HSO_CLIENT_OP_LOCK_WAIT_END:
		return STATUS_WAS_LOCKED;

	    case HSO_CLIENT_OP_UNLOCK:
	    case HSO_CLIENT_OP_RELEASE:
	    case HSO_CLIENT_OP_RELEASE_DELIST:
            case HSO_CLIENT_OP_LOCK_WAIT_BEGIN:
		break;
	    }
        } else if (op == HSO_CLIENT_OP_LOCK_WAIT_BEGIN)
            return STATUS_NOT_LOCKED;
        _new.value = pre->value;

	/* TODO: x86 does not read __int64 atomically, should we redirect any failure on x86 to
         * repeat after an interlocked read?  */
	switch (op) {
	case HSO_CLIENT_OP_LIST:
	    flags |= HYBRID_SYNC_ACCESSIBLE;
	    break;

	case HSO_CLIENT_OP_GRAB:
	    if (unlikely(refcount == HYBRID_SYNC_REFCOUNT_MAX))
		return STATUS_TOO_MANY_THREADS;

            ++refcount;
	    break;

	case HSO_CLIENT_OP_RELEASE_DELIST:
	    flags &= ~HYBRID_SYNC_ACCESSIBLE;
            /* Fallthrough */
	case HSO_CLIENT_OP_RELEASE:
            --refcount;
	    break;

	case HSO_CLIENT_OP_LOCK:
	    flags |= HYBRID_SYNC_LOCKED;
	    break;

	case HSO_CLIENT_OP_UNLOCK:
	    flags &= ~HYBRID_SYNC_LOCKED;
	    //_new.value = new_value;
            ho->atomic.value = new_value;
	    break;

        case HSO_CLIENT_OP_LOCK_WAIT_BEGIN:
            --refcount;
            ++waiters;
            break;

        case HSO_CLIENT_OP_LOCK_WAIT_END:
            ++refcount;
            --waiters;
            break;

        default:
            assert (0);
	};
        _new.flags_refcounts = hso_atomic_make_flags_refcounts( flags, refcount, waiters );

        old = pre->flags_refcounts;
        if (sizeof(long) == 8)
        {
            pre->flags_refcounts = interlocked_cmpxchg64((long*)&ho->atomic.flags_refcounts, _new.flags_refcounts, pre->flags_refcounts);
        }
        else if (sizeof(long) == 4)
        {
            pre->flags_refcounts = interlocked_cmpxchg((long*)&ho->atomic.flags_refcounts, _new.flags_refcounts, pre->flags_refcounts);
        }
        else
            assert(0);

        repeat = pre->flags_refcounts != old;
#if 0
	//fprintf(stderr, "hso_client_op TRY, pre=%x, _new=%x\n", pre->flags_refcount, _new.flags_refcount);
#if 0
        /* FIXME: need 32-bit version.  */
	{
            union hso_atomic old = *pre;
            pre->flags_refcounts = interlocked_cmpxchg64((long*)&ho->atomic.flags_refcounts,
                                                         (long)_new.flags_refcounts,
                                                         (long)pre->flags_refcounts);
            repeat = pre->flags_refcounts != old.flags_refcounts;
	}
#else
        if (sizeof(void*) == 8 /* HSO_ATOMIC_QWORDS == 2 */)
            repeat = !interlocked_cmpxchg128(ho->atomic.int64,
					     _new.int64[1],
					     _new.int64[0],
					     pre->int64);
        else
        {
            union hso_atomic old = *pre;
assert(0);
            pre->int64[0] = interlocked_cmpxchg64(ho->atomic.int64, _new.int64[0], pre->int64[0]);
            repeat = pre->int64[0] != old.int64[0];
        }
#endif
#endif

    } while (unlikely( repeat ));

    if (ret_value)
	*ret_value = _new.value;


    /* if refcount is zero and both HYBRID_SYNC_ACCESSIBLE and HYBRID_SYNC_LOCKED bits are cleared
     * then this object is ready to destroy */

    //fprintf(stderr, "hso_client_op FINISH, %x --> %x\n", pre->flags_refcount, _new.flags_refcount);

    return STATUS_SUCCESS;
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
 * dereference the ho->atomic.value pointer. Each successful call to this function
 * should be paired by a call to hybrid_object_release(). If another thread
 * (of this process) has the object locked (via ho->atomic.flags_refcount &
 * HYBRID_SYNC_LOCKED) then this function will block until the condition is
 * cleared.
 *
 * RETURN
 *  SUCCESS: 0
 *  FAILURE:
 *     STATUS_FILE_CORRUPT_ERROR        shared memory data is corrupt
 *     STATUS_TOO_MANY_THREADS          more than 134m threads or unpaired begin/end calls
 *
 */

static __must_check NTSTATUS hybrid_object_grab(struct hybrid_sync_object *ho)
{
    NTSTATUS result;
    union hso_atomic pre = ho->atomic;

    do {
	result = hso_client_op( ho, &pre, HSO_CLIENT_OP_GRAB, NULL, NULL );

	if (result != STATUS_WAS_LOCKED)
	    break;

	hybrid_object_do_move_wait( ho, &pre );
    } while (1);

    return result;
}


/* End a client-side operation, decrementing refcount
 *
 * RETURN
 *  SUCCESS: 0
 *  FAILURE:
 *     STATUS_FILE_CORRUPT_ERROR        shared memory data is corrupt
 *
 * fast path built with gcc on x86_64 is 61 bytes
 */
static __must_check NTSTATUS hybrid_object_release(struct hybrid_sync_object *ho, int delist)
{
    union hso_atomic pre = ho->atomic;
    NTSTATUS result;

    result = hso_client_op( ho, &pre, delist ? HSO_CLIENT_OP_RELEASE_DELIST : HSO_CLIENT_OP_RELEASE, NULL, NULL );
    if (!(hso_atomic_get_flags( &pre ) & (HYBRID_SYNC_ACCESSIBLE | HYBRID_SYNC_LOCKED))
            && hso_atomic_get_refcount( &pre ) == 1
            && hso_atomic_get_waitcount( &pre ) == 0)
        hybrid_object_client_fns.destroy( ho );

    return result;
}


/* do_move() and do_move_wait() are sloppy but will be re-written so that all of
 * the futex/sleeping/signaling stuff done here and in criticalsection.c are
 * using the same code.
 *
 * this is only called when refcount (flags_refcount) is already incremented
 *
 *
 */
static __must_check NTSTATUS hybrid_object_do_move( struct hybrid_sync_object *ho, union hso_atomic *pre )
{
    struct timespec timeout;
    int do_wake;
    NTSTATUS result;
    struct shm_object_info info;
    union shm_sync_value *orig;

    result = hso_client_op( ho, pre, HSO_CLIENT_OP_LOCK, NULL, NULL );

    /* if already locked, then another thread is doing it, wait */
    if (result == STATUS_WAS_LOCKED)
    {
        //putc('L', stderr);
	result = hso_client_op( ho, pre, HSO_CLIENT_OP_LOCK_WAIT_BEGIN, NULL, NULL );
        if (result == STATUS_NOT_LOCKED)
	    return STATUS_SUCCESS;
        else if (result)
            return result;

        orig = pre->value;
        hso_client_futex_wake( &ho->atomic);

        do {
            hybrid_object_do_move_wait( ho, pre );
            result = hso_client_op( ho, pre, HSO_CLIENT_OP_LOCK_WAIT_END, NULL, NULL );
        } while (result == STATUS_WAS_LOCKED);

        return result;
    }
    else if (result)
	return result;
    /* else, we got the lock, so are responsible for the move */

    timeout.tv_sec  = 4;
    timeout.tv_nsec = 100 * 1000 * 1000;

    /* Get all other threads of this process out of the object -- wake threads
     * that are sleeping on &ho->atomic.value.data so that they can decrement
     * ho->flags_count (by 1 << HYBRID_SYNC_FLAGS_BITS of course) and then wait
     * on that address. Once they are out, we can do the move and then wake
     * them back up to complete their operations using the modified object.
     *
     * waking on &ho->atomic.value.data can result in us waking threads of other
     * processes too, but that's OK.
     *
     * NOTE: this could possibly be optimized with FUTEX_CMP_REQUEUE, but nobody cares.
     */
    for (do_wake = 1; hso_atomic_get_refcount( pre ) > 1;)
    {
        int futex_result;

        /* we only know the number of threads in this process that have grabbed the object (and
         * thus, possibly waiting on ho->atomic.value) so this may need to be repeated. */
        if (do_wake)
            futex_wake( &ho->atomic.value->data, INT_MAX );

        do_wake = 1;

        /* wait on the process-local ho->atomic.flags_refcount value */

        futex_result = hso_client_futex_wait( &ho->atomic, pre, &timeout );
        barrier();
        *pre = *(volatile union hso_atomic*)&ho->atomic;
	switch (-futex_result)
	{
	case 0:
	    break;

	case EAGAIN:
	    /* Value changed, we only need to re-read and repeat, but as we
	     * haven't slept since the last call to wake, we will not call
	     * wake again. */
	    do_wake = 0;
	case ETIMEDOUT:
	case EINTR:
	    continue;
	}
    }

    /* In this state only the current thread has the right to change the
     * ho->atomic.value pointer. It is now the below callback function's responsibility
     * to:
     * . Release the shared memory via virtual.c (or at least the reference to it)
     * . make the server call to
     *   * inform server that the previous shared memory is no longer being used.
     *   * request the new storage of the sync object. This may be that it has
     *     become private in server memory (server calls for all operations) or
     *     a different fd and offset in another shared memory location.
     * . Finally, the callback will obtain the shared memory from virtual.c (if
     *   applicable) and get the new pointer. It will be NULL if the object
     *   has moved to the server (as a server-private object) and point to the
     *   new location in shared memory otherwise.
     */

    info = shm_object_info_init( );

    result = hybrid_object_client_fns.move( ho, &info );
    if (result)
    {
        /* FIXME: broken on big endian */
        interlocked_test_and_set_bit( (int *)&ho->atomic.flags_refcounts, HYBRID_SYNC_BAD_BIT );
        result = STATUS_FILE_CORRUPT_ERROR;
	assert (0);
    }

    ho->hash_base = fnv1a_hash32( FNV1A_32_INIT, info.hash_base_in, sizeof (info.hash_base_in) );
    orig = pre->value;

    result = hso_client_op( ho, pre, HSO_CLIENT_OP_UNLOCK, NULL, info.ptr );
    /* If the server returned the same shared memory, then some error has led us to here. */
    assert( orig != ho->atomic.value );
    assert( !result );
    hso_client_futex_wake( &ho->atomic );

    return result;
}


/* wait for another thread of this process to get the new shm location
 * of the sync object, set the new ho->atomic.value pointer and clear the
 * HYBRID_SYNC_LOCKED_BIT
 *
 * this is where client threads wait for another thread in the process to complete a move
 */
static void __noinline hybrid_object_do_move_wait(struct hybrid_sync_object *ho, union hso_atomic *pre)
{
    /* the move operation requires a server call so there's no sense in spinning for this lock */
    do
    {
	struct timespec timeout;
        int result;

        timeout.tv_sec  = 60;
        timeout.tv_nsec = 0;

        result = hso_client_futex_wait( &ho->atomic, pre, &timeout );
        barrier();
        *pre = *(volatile union hso_atomic*)&ho->atomic;
        if (result)
        {
            switch (-result)
            {
            case ETIMEDOUT:
                fprintf(stderr, "%s: WARNING: waiting local lock for more than 60 seconds "
                                "(system busy, server hung, or memory corrupted). "
                                "pid=%d, tid=%ld, ho=%p, ho->atomic.flags_refcount=%08lx\n",
                                __func__, getpid(), syscall(SYS_gettid), ho, ho->atomic.flags_refcounts);
	    case EAGAIN:
            case EINTR:
                break;
            }
        }
    } while (hso_atomic_get_flags( pre ) & HYBRID_SYNC_LOCKED);
}


/* wait for ho->atomic.value->flags_hash & SHM_SYNC_VALUE_LOCKED to clear
 *
 * Wait for the server to finish whatever it's doing (edit).
 *
 * The calling thread should have made a successful call to hybrid_object_grab() prior to calling
 * this function (ho->atomic.value pointer is accessed non-atomically).
 *
 * RETURNS:
 *  SHM_SYNC_VALUE_CORRUPTED    If the corrupted bit was set
 *  SHM_SYNC_VALUE_AGAIN        In all other cases
 */
static enum shm_sync_value_result hybrid_object_wait_global_lock(struct hybrid_sync_object *ho,
                                                                 union shm_sync_value *pre)
{
    enum shm_sync_value_result result;
    const unsigned int MAX_SPIN_COUNT = 128;
    unsigned int spincount            = MAX_SPIN_COUNT;
    unsigned int curcpu               = sched_getcpu();
    unsigned int server_cpu           = last_server_cpu_ptr ? *last_server_cpu_ptr : -1u;


//    union hso_atomic atomic_pre = ho->atomic;

    /* This function is optimized to expect the server to generally not be prepempted in the middle
     * of a hybrid object transaction, so will first spin waiting for the lock bit to clear.
     * If we exceed our spin count, then we will resort to a futex wait.
     * However, we skip the spin and go straight to a futex wait if:
     *  * the machine is uniprocessor,
     *  * sched_getcpu() fails, or
     *  * the server was last running on this CPU.
     */

    if (NtCurrentTeb()->Peb->NumberOfProcessors == 1 || curcpu != -1u || server_cpu == curcpu)
        spincount = 0;

    for(;;)
    {
        result = check_data(ho, pre, FALSE, FALSE);
        switch (result)
        {
        case SHM_SYNC_VALUE_LOCKED:
            break;

        case SHM_SYNC_VALUE_SUCCESS:
            *pre = *(volatile union shm_sync_value*)ho->atomic.value;
            return SHM_SYNC_VALUE_AGAIN;

        default:
            return result;
        }

        if (likely(spincount))
        {
            --spincount;
            cpu_relax();    /* use less power if CPU is capable */
            barrier();
            *pre = *(volatile union shm_sync_value*)ho->atomic.value;
        }
        else
        {
            struct timespec timeout;
	    int futex_result;

            timeout.tv_sec = 60;
            timeout.tv_nsec = 0;

            /* we wait on the flags_hash because that is what will change and be
             * notified when the server is done */

            futex_result = futex_wait( (int*)&ho->atomic.value->flags_hash, (int)pre->flags_hash, &timeout);
            *pre = *(volatile union shm_sync_value*)ho->atomic.value;
            switch (-futex_result)
            {
            case 0:
                break;
	    case ETIMEDOUT:
		fprintf(stderr, "%s: WARNING: waiting server lock for more than 60 seconds "
				"(system busy, server hung, or shm data corrupted). "
				"pid=%d, tid=%ld, ho=%p, ho->atomic.value=%p *ho->atomic.value=%016llx\n",
				__func__, getpid(), syscall(SYS_gettid), ho, ho->atomic.value,
				(long long)ho->atomic.value->int64);
                /* Fallthrough */
	    case EAGAIN:
	    case EINTR:
		continue;
            }
        }
    }
}
