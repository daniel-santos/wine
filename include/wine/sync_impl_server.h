/*
 * Server implementation for hybrid, migratory synchronization objects.
 *
 * Copyright (C) 2015-2017 Daniel Santos
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

/******************************** server-only functions ********************************/


static __noinline __cold enum shm_sync_value_result
check_data_anomalous( struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
                      enum shm_sync_value_result flags, int wait_lock )
{
    if (flags & SHM_SYNC_VALUE_CORRUPTED)
        return sync_fail( ho, "wineserver: ERROR %s: corrupted bit set\n", __func__ );

    if (flags & SHM_SYNC_VALUE_MOVED)
        return sync_fail( ho, "wineserver: ERROR %s: moved bit set when it shouldn't be\n",
                          __func__ );

    unreachable();
    assert( 0 );
    exit( -1 );
}

static const char *opstr[HYBRID_SYNC_TRANS_OP_COUNT] =
{
    "begin trans",
    "commit",
    "rollback"
};

/******************************************************************************
 *              hybrid_object_op_trans
 *
 * Perform a transactional operation on a hybrid object
 *
 * PARAMS
 *  ho           [I] The object to operate on
 *  pre_ptr      [O] Where the pre-operation value will be stored (required)
 *  maybe_stale  [I] Value at pre_ptr may be from a stale read.
 *  post_ptr     [O] Where the post-operation value will be stored (optional)
 *  last_ptr     [I] Pointer to value when transaction started (optional)
 *  type         [I] The transaction type (migration, semaphore, mutex or event)
 *  op           [I] The operation (begin trans, commit or rollback)
 *  clear_notify [I] (only for commit & rollback) rather or not to clear the server notify flag
 *
 * This is only called by the server and locks/unlocks the object and allows for
 * a transactional change followed by either a commit or rollback, assuring that
 * no foreign programs can alter the object until it is completed.
 *
 * The do_trans_op function manages what the specific type needs to do.
 *
 * RETURNS
 *  STATUS_SUCCESS              on success
 *  STATUS_WAS_LOCKED           for a begin trans when the object is not signaled
 *  STATUS_FILE_CORRUPT_ERROR   for any corruption of state inconsistency
 */
static FORCEINLINE NTSTATUS hybrid_object_trans_op( struct hybrid_sync_object *ho,
                                                    union shm_sync_value *pre_ptr,
                                                    int maybe_stale,
                                                    union shm_sync_value *post_ptr,
                                                    const union shm_sync_value *last_ptr,
                                                    enum hybrid_sync_trans_type type,
                                                    enum hybrid_sync_trans_op op,
                                                    int clear_notify)
{
    enum shm_sync_value_result result;
    union shm_sync_value new_val;
    NTSTATUS ret;
    int is_begin_trans = (op == HYBRID_SYNC_TRANS_OP_BEGIN);

    if (is_begin_trans && last_server_cpu_ptr)
        *last_server_cpu_ptr = sched_getcpu();

    if (0)
    {
again:
        pre_ptr->int64 = locked_read64( &ho->atomic.value->int64 );
        maybe_stale = FALSE;
    }

    /* Exchange and compare loop */
    do {
        int locked         = pre_ptr->flags_hash & SHM_SYNC_VALUE_LOCKED;
        new_val.data       = pre_ptr->data;
        new_val.flags_hash = pre_ptr->flags_hash & SHM_SYNC_VALUE_FLAGS_MASK;
        ret                = STATUS_SUCCESS;

        if (!!is_begin_trans ^ !locked)
        {
            if (maybe_stale)
                goto again;

            sync_fail(ho, "wineserver: ERROR %s: attempt to %s when object %slocked\n",
                      __func__, opstr[op], locked ? "" : "not ");
            return STATUS_FILE_CORRUPT_ERROR;
        }

        /* The base of all transactions is to lock the object upon begin and
         * unlock it upon commit or rollback.  */
        switch (op) {
        case HYBRID_SYNC_TRANS_OP_BEGIN:
            new_val.flags_hash |= SHM_SYNC_VALUE_LOCKED;
            break;

        case HYBRID_SYNC_TRANS_OP_ROLLBACK:
        case HYBRID_SYNC_TRANS_OP_COMMIT:
            new_val.flags_hash &= ~SHM_SYNC_VALUE_LOCKED;
            if (clear_notify)
                new_val.flags_hash &= ~SHM_SYNC_VALUE_WAKE_SERVER;
            break;
        }

        switch (type)
        {

        /******** Migration Transactions ********/
        case HYBRID_SYNC_TRANS_TYPE_MIGRATION:
            switch (op) {
            case HYBRID_SYNC_TRANS_OP_BEGIN:
                break;

            case HYBRID_SYNC_TRANS_OP_ROLLBACK:
                assert( 0 ); /* no rollback */

            case HYBRID_SYNC_TRANS_OP_COMMIT:
                new_val.flags_hash |= SHM_SYNC_VALUE_MOVED;
                /* Must alter data since client will futex wait on this.  */
                new_val.data = ~new_val.data;
                break;
            }
            break;

        /******** Semaphore Transactions ********/
        case HYBRID_SYNC_TRANS_TYPE_SEMAPHORE:
            {
                struct hybrid_semaphore *sem = (struct hybrid_semaphore *)ho;
                switch (op) {
                case HYBRID_SYNC_TRANS_OP_BEGIN:
                    if (new_val.data == 0)
                    {
                        /* If semaphore cannot be obtained, do not start the transaction, but
                         * instead mark the WAKE_SERVER bit so that clients know to notify the
                         * server when the semaphore is released.  NOTE: STATUS_WAS_LOCKED is for
                         * the logical semaphore and not the hybrid_sync_object's server lock
                         * bit. */
                        new_val.flags_hash &= ~SHM_SYNC_VALUE_LOCKED;
                        new_val.flags_hash |= SHM_SYNC_VALUE_WAKE_SERVER;
                        ret = STATUS_WAS_LOCKED;
                    }
                    else
                        --new_val.data;
                    break;

                case HYBRID_SYNC_TRANS_OP_ROLLBACK:
                    ++new_val.data;
                    break;

                case HYBRID_SYNC_TRANS_OP_COMMIT:
                    break;
                }

                /* overflow should be impossible here */
                if (unlikely( new_val.data <= (int)sem->max ))
                {
                    if (maybe_stale)
                        goto again;
                    else
                        assert(new_val.data <= (int)sem->max);
                }
                break;
            }
#if 0
        /******** Mutex Transactions ********/
        case HYBRID_SYNC_TRANS_TYPE_MUTEX:
            {
                struct hybrid_mutex *mutex = (struct hybrid_mutex *)ho;
                switch (op) {
                case HYBRID_SYNC_TRANS_OP_BEGIN:
                    if (new_val.data != 0 && new_val.data != tid)
                    {
                        new_val.flags_hash &= ~SHM_SYNC_VALUE_LOCKED;
                        new_val.flags_hash |= SHM_SYNC_VALUE_WAKE_SERVER;
                        ret = STATUS_WAS_LOCKED;
                    }
                    else
                        new_val.data = tid;
                    break;

                case HYBRID_SYNC_TRANS_OP_ROLLBACK:
                    new_val.data = last_ptr->data;
                    break;

                case HYBRID_SYNC_TRANS_OP_COMMIT:
                    break;
                }
            }
            break;

        case HYBRID_SYNC_TRANS_TYPE_MUTEX:
            break;
#endif

        default:
            assert( 0 );
        }

        result = sync_try_op(ho, pre_ptr, maybe_stale, post_ptr, new_val.data, new_val.flags_hash);
        maybe_stale = FALSE;
    /* only loop when we haven't already locked the object */
    } while (is_begin_trans && result == SHM_SYNC_VALUE_AGAIN);

    if (!is_begin_trans)  /* commit, rollback or end */
    {
        if (result == SHM_SYNC_VALUE_AGAIN || (last_ptr && pre_ptr->int64 != last_ptr->int64))
        {
            sync_fail(ho, "wineserver: ERROR %s: object modified while locked\n", __func__);
            return STATUS_FILE_CORRUPT_ERROR;
        }

        /* wake any threads waiting for this transaction to complete */
        futex_wake( (int*)&ho->atomic.value->flags_hash, INT_MAX );
    }

    if (result)
        return wine_sync_value_result_to_ntstatus(result);

    return ret;
}

static NTSTATUS hybrid_object_clear_notify( struct hybrid_sync_object *ho )
{
    enum shm_sync_value_result result;
    union shm_sync_value pre = *ho->atomic.value;
    int maybe_stale = TRUE;

    do {
        int flags = pre.flags_hash & SHM_SYNC_VALUE_FLAGS_MASK & ~SHM_SYNC_VALUE_WAKE_SERVER;
        result    = sync_try_op( ho, &pre, maybe_stale, NULL, pre.data, flags );
        maybe_stale = FALSE;
    } while (result == SHM_SYNC_VALUE_AGAIN);

    if (result)
        return wine_sync_value_result_to_ntstatus( result );

    return STATUS_SUCCESS;
}

/* Singular expansion of hybrid_object_trans_op inline used for all semaphore transactions. */
NTSTATUS __attribute__((noinline))
__hybrid_semaphore_trywait_trans_op( struct hybrid_semaphore *sem,
                                     union shm_sync_value *trans_state,
                                     enum hybrid_sync_trans_op op, int clear_notify )
{
    union shm_sync_value pre = *sem->ho.atomic.value;
    union shm_sync_value *post_ptr = NULL;
    union shm_sync_value *last_ptr = NULL;

    if (op == HYBRID_SYNC_TRANS_OP_BEGIN)
        post_ptr = trans_state;
    else
        last_ptr = trans_state;

    return hybrid_object_trans_op( &sem->ho, &pre, TRUE, post_ptr, last_ptr,
                                   HYBRID_SYNC_TRANS_TYPE_SEMAPHORE, op, clear_notify );
}
#if 0
/* Singular expansion of hybrid_object_trans_op inline used for all semaphore transactions. */
NTSTATUS __attribute__((noinline))
__hybrid_mutex_trywait_trans_op( struct hybrid_mutex *mutex, union shm_sync_value *trans_state,
                                 enum hybrid_sync_trans_op op, int clear_notify )
{
    union shm_sync_value pre = *mutex->ho.atomic.value;
    union shm_sync_value *post_ptr = NULL;
    union shm_sync_value *last_ptr = NULL;

    if (op == HYBRID_SYNC_TRANS_OP_BEGIN)
        post_ptr = trans_state;
    else
        last_ptr = trans_state;

    return hybrid_object_trans_op( &mutex->ho, &pre, TRUE, post_ptr, last_ptr,
                                   HYBRID_SYNC_TRANS_TYPE_MUTEX, op, clear_notify );
}
#endif
/* Singular expansion of hybrid_object_trans_op inline used for all migration transactions.  This
 * function is rather large and we don't want hybrid_object_migrate to expand it twice.  */
static NTSTATUS __attribute__((noinline))
hybrid_object_migrate_trans_op( struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
                                int maybe_stale, union shm_sync_value *post_ptr,
                                union shm_sync_value *last_ptr, enum hybrid_sync_trans_op op )
{
    return hybrid_object_trans_op( ho, pre_ptr, maybe_stale, post_ptr, last_ptr,
                                   HYBRID_SYNC_TRANS_TYPE_MIGRATION, op, FALSE );
}

/* Perform the migration to the new shared memory and calculate the new hash_base.  The new
 * pointer is in info.
 */
static NTSTATUS hybrid_object_migrate( struct hybrid_sync_object *ho, struct shm_object_info *info )
{
    union shm_sync_value pre = *ho->atomic.value;
    union shm_sync_value post;
    unsigned int new_flags;
    union shm_sync_value *to = info->ptr;
    NTSTATUS result;

    memset( &post, 0x55, sizeof(post) );

    /* Set lock bit with begin trans. */
    result = hybrid_object_migrate_trans_op(ho, &pre, TRUE, &post, NULL, HYBRID_SYNC_TRANS_OP_BEGIN);
    if (result)
        return result;

    /* Use all normal writes because the preceeding sync_try_op() will provide a memory barrier. */
    info->hash_base = fnv1a_hash32( FNV1A_32_INIT, info->hash_base_in, sizeof(info->hash_base_in) );
    new_flags       = (post.flags_hash & SHM_SYNC_VALUE_FLAGS_MASK) & ~SHM_SYNC_VALUE_LOCKED;
    to->data        = post.data;
    to->flags_hash  = hash28( info->hash_base, new_flags, to->data );

    /* commit the migration */
    pre = post;
    result = hybrid_object_migrate_trans_op( ho, &pre, FALSE, NULL, &post, HYBRID_SYNC_TRANS_OP_COMMIT );
    if (result)
        return result;

    /* Wake any threads that were waiting on the object so they will get the new address from
     * the server */
    /* FIXME: doing wake twice? */
    futex_wake( &ho->atomic.value->data, INT_MAX );
    ho->atomic.value = to;
    ho->hash_base = info->hash_base;
    return STATUS_SUCCESS;
}




