/*
 * Server implementation for hybrid, migratory synchronization objects.
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

#define WINE_SYNC_IS_SERVER 1
#include "wine/sync_impl_common.h"

/******************************** server-only functions ********************************/


static __noinline __cold enum shm_sync_value_result
check_data_anomalous(struct hybrid_sync_object *ho, union shm_sync_value *pre_ptr,
                     enum shm_sync_value_result flags, int wait_lock)
{
    if (flags & SHM_SYNC_VALUE_CORRUPTED)
        return sync_fail(ho, "wineserver: ERROR %s: corrupted bit set\n", __func__);

    if (flags & SHM_SYNC_VALUE_MOVED)
        return sync_fail(ho, "wineserver: ERROR %s: moved bit set when it shouldn't be\n", __func__);

    unreachable();
    assert(0);
    for(;;);
}

static const char *opstr[HYBRID_SYNC_TRANS_OP_COUNT] =
{
    "begin trans",
    "commit",
    "rollback"
};


typedef NTSTATUS (*do_trans_op_fn_t)(union hybrid_object_any *any, enum hybrid_sync_trans_op op, union shm_sync_value *new_ptr);

static FORCEINLINE NTSTATUS do_trans_op_sem(union hybrid_object_any *any,
                                            enum hybrid_sync_trans_op op,
                                            union shm_sync_value *new_ptr)
{
    /* overflow should be impossible here */
    assert(new_ptr->data <= (int)any->sem.max);

    switch (op) {
    case HYBRID_SYNC_TRANS_OP_BEGIN:
        if (new_ptr->data == 0)
            return STATUS_WAS_LOCKED;
        --new_ptr->data;
        break;

    case HYBRID_SYNC_TRANS_OP_ROLLBACK:
        ++new_ptr->data;
        assert(new_ptr->data <= (int)any->sem.max); /* should be impossible here */
        break;

    case HYBRID_SYNC_TRANS_OP_COMMIT:
        break;
    }

    return STATUS_SUCCESS;
}


static FORCEINLINE NTSTATUS do_trans_op_migrate(union hybrid_object_any *any,
                                                enum hybrid_sync_trans_op op,
                                                union shm_sync_value *new_ptr)
{
    if (op == HYBRID_SYNC_TRANS_OP_COMMIT)
        new_ptr->flags_hash |= SHM_SYNC_VALUE_MOVED;
    return STATUS_SUCCESS;
}


#if 0
static NTSTATUS FORCEINLINE mutex_do_trans(union hybrid_object_any *any, enum hybrid_sync_trans_op op,
                                         union shm_sync_value *new_ptr)
{
    struct hybrid_mutex *mutex = &any->mutex;
    NTSTATUS ret = STATUS_SUCCESS;

    /* shouldn't enter this part of the transaction unless nobody owns the mutex */

    switch (op) {
    case HYBRID_SYNC_TRANS_OP_BEGIN:
        if (new_ptr->data)
            return STATUS_WAS_LOCKED;
        new_ptr->data = -1; /* the current thread id */
        //mutex->recursion_count = 1;
        break;

    case HYBRID_SYNC_TRANS_OP_ROLLBACK:
        //++mutex->recursion_count;
        //new_ptr->data
        break;

    case HYBRID_SYNC_TRANS_OP_COMMIT:
        break;
    }

    return STATUS_SUCCESS;
}
#endif

/******************************************************************************
 *              hybrid_object_op_trans
 *
 * Perform a transactional operation on a hybrid object
 *
 * PARAMS
 *  ho           [I] The object to operate on
 *  pre_ptr      [O] Where the pre-operation value will be stored (required)
 *  post_ptr     [O] Where the post-operation value will be stored (optional)
 *  last_ptr     [I] Pointer to value when transaction started (optional)
 *  op           [I] The operation (begin trans, commit or rollback)
 *  do_trans_op  [I] Pointer to the type-specific do_trans_op function
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
static FORCEINLINE NTSTATUS hybrid_object_trans_op(struct hybrid_sync_object *ho,
                                                   union shm_sync_value *pre_ptr,
                                                   union shm_sync_value *post_ptr,
                                                   const union shm_sync_value *last_ptr,
                                                   enum hybrid_sync_trans_op op,
                                                   do_trans_op_fn_t do_trans_op, int clear_notify)
{
    enum shm_sync_value_result result;
    union shm_sync_value new_val;
    NTSTATUS ret;
    int is_begin_trans = (op == HYBRID_SYNC_TRANS_OP_BEGIN);

    if (is_begin_trans && last_server_cpu_ptr)
    {
        unsigned int cur_cpu = sched_getcpu();
        atomic_write( last_server_cpu_ptr, &cur_cpu );
    }

    /* initial volatile read */
    atomic_read( pre_ptr, ho->value );

    /* exchange & compare loop */
    do {
        int locked         = pre_ptr->flags_hash & SHM_SYNC_VALUE_LOCKED;
        new_val.data       = pre_ptr->data;
        new_val.flags_hash = pre_ptr->flags_hash & SHM_SYNC_VALUE_FLAGS_MASK;

        if (!hybrid_object_is_server_private(ho) && (is_begin_trans ? locked : !locked))
        {
            sync_fail(ho, "wineserver: ERROR %s: attempt to %s when object %slocked\n",
                      __func__, opstr[op], locked ? "" : "not ");
            return STATUS_FILE_CORRUPT_ERROR;
        }

        ret = do_trans_op((union hybrid_object_any *)ho, op, &new_val);

        switch (op) {
        case HYBRID_SYNC_TRANS_OP_BEGIN:
            if (ret)
                new_val.flags_hash |= SHM_SYNC_VALUE_NOTIFY_SVR;
            else
                new_val.flags_hash |= SHM_SYNC_VALUE_LOCKED;
            break;

        case HYBRID_SYNC_TRANS_OP_ROLLBACK:
        case HYBRID_SYNC_TRANS_OP_COMMIT:
            if (clear_notify)
                new_val.flags_hash &= ~SHM_SYNC_VALUE_NOTIFY_SVR;
            new_val.flags_hash &= ~SHM_SYNC_VALUE_LOCKED;
            break;
        }

        result = sync_try_op(ho, pre_ptr, post_ptr, new_val.data, new_val.flags_hash);
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
        futex_wake( (int*)&ho->value->flags_hash, INT_MAX );
    }

    if (result)
        return wine_sync_value_result_to_ntstatus(result);

    return ret;
}

static NTSTATUS hybrid_object_clear_notify(struct hybrid_sync_object *ho)
{
    enum shm_sync_value_result result;
    union shm_sync_value pre;

    atomic_read(&pre, ho->value);
    do {
        int flags = pre.flags_hash & SHM_SYNC_VALUE_FLAGS_MASK & ~SHM_SYNC_VALUE_NOTIFY_SVR;
        result    = sync_try_op(ho, &pre, NULL, pre.data, flags);
    } while (result == SHM_SYNC_VALUE_AGAIN);

    if (result)
        return wine_sync_value_result_to_ntstatus(result);

    return STATUS_SUCCESS;
}


/* expansion of hybrid_object_trans_op */
NTSTATUS __hybrid_semaphore_trans_op(struct hybrid_semaphore *sem,
                                     union shm_sync_value *trans_state,
                                     enum hybrid_sync_trans_op op, int clear_notify)
{
    union shm_sync_value pre;
    union shm_sync_value *post_ptr = NULL;
    union shm_sync_value *last_ptr = NULL;

    if (op == HYBRID_SYNC_TRANS_OP_BEGIN)
        post_ptr = trans_state;
    else
        last_ptr = trans_state;

    return hybrid_object_trans_op(&sem->ho, &pre, post_ptr, last_ptr, op, do_trans_op_sem, clear_notify);
}


/* expansion of hybrid_object_trans_op */
static NTSTATUS hybrid_object_migrate_trans_op(struct hybrid_sync_object *ho,
                                               union shm_sync_value *pre_ptr,
                                               union shm_sync_value *post_ptr,
                                               union shm_sync_value *last_ptr,
                                               enum hybrid_sync_trans_op op)
{
    return hybrid_object_trans_op(ho, pre_ptr, post_ptr, last_ptr, op, do_trans_op_migrate, FALSE);
}


static NTSTATUS hybrid_object_migrate( struct hybrid_sync_object *ho, struct shm_object_info *info )
{
    union shm_sync_value pre;
    union shm_sync_value post;
    unsigned int new_hash_base;
    unsigned int new_flags;
    union shm_sync_value *to = info->ptr;
    NTSTATUS result;

#ifdef DEBUG_OBJECTS
    memset( &post, 0x55, sizeof(post) );
#endif
//fprintf(stderr, "%s: %p --> %p\n", __func__, ho->value, info->ptr);

    /* initial volatile read */
    atomic_read( &pre, ho->value );

    /* set lock bit with begin trans */
    result = hybrid_object_migrate_trans_op(ho, &pre, &post, NULL, HYBRID_SYNC_TRANS_OP_BEGIN);
    if (result)
        return result;

    new_hash_base  = fnv1a_hash32(FNV1A_32_INIT, info->hash_base_in, sizeof(info->hash_base_in));
    new_flags      = post.flags_hash & (SHM_SYNC_VALUE_FLAGS_MASK & ~SHM_SYNC_VALUE_LOCKED);

    /* Use simple write because nobody has this yet and the preceeding sync_try_op() will provide
     * a memory barrier anyway. */
    to->data            = post.data;
    to->flags_hash      = hash28(new_hash_base, new_flags, to->data);

    /* commit the migration */
    result = hybrid_object_migrate_trans_op(ho, &pre, NULL, &post, HYBRID_SYNC_TRANS_OP_COMMIT);
    if (result)
        return result;

    /* wake any threads that were waiting on the object so they will get the new address from
     * the server */
    futex_wake( &ho->value->data, INT_MAX );

    /* update the local object */
    ho->value           = info->ptr;
    ho->hash_base       = new_hash_base;
    return STATUS_SUCCESS;
}




