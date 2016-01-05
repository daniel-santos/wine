/*
 * Low level functions & objects for hybrid, migratory, user-space
 * synchronization objects. This of course calls for some definitions:
 * - Hybrid:    Composed of data in both private and shared memory.
 * - Migratory: The shared memory portion of the object is moveable.
 *
 * Copyright (C) 2015-2016 Daniel Santos
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

#ifndef __WINE_SYNC_H
#define __WINE_SYNC_H

#include <limits.h>
#include <stdio.h>

/* FIXME: not sure if these next three lines are correct -- need type NTSTATUS. */
#define WIN32_NO_STATUS
#include "winternl.h"           /* for NTSTATUS */
#include "windef.h"             /* for __int64 */

#ifndef SYNC_H_ATTR
# define SYNC_H_ATTR
#endif

/******************************************************************************
 *              union shm_sync_value
 *
 * The data portion of a synchronization object that may reside in either shared
 * or private memory.
 */
union shm_sync_value
{
    __int64 int64;
    struct
    {
        int data;       /* data for synchronization object */
        int flags_hash; /* bits 0-3: flags, bits 4-31: hash */
    };
};

/* macros for flags portion of union shm_sync_value::flags_hash */
#define SHM_SYNC_VALUE_FLAGS_BITS    4
#define SHM_SYNC_VALUE_FLAGS_MASK    ((1 << SHM_SYNC_VALUE_FLAGS_BITS) - 1)
#define SHM_SYNC_VALUE_HASH_MASK     (~SHM_SYNC_VALUE_FLAGS_MASK)
#define SHM_SYNC_VALUE_CORRUPTED_BIT 2

/* union shm_sync_value::flags_hash flags and return codes */
enum shm_sync_value_result
{

    /* locked by server, either for a move or a wait-multi operation */
    SHM_SYNC_VALUE_LOCKED      = 1,

    /* Flag set by wineserver to indicate that the object has moved to another
     * shared memory location. The client should communicate with the wineserver
     * to obtain the new location and perform any mmapping that is needed to
     * access the object at its new location */
    SHM_SYNC_VALUE_MOVED       = 2,

    /* Flag set by either the wineserver or client to indicate that some form of
     * corruption has occured in the shared data or consistency of a processes'
     * private data associated with the shared data and any further calls
     * associated with this object should fail. */
    SHM_SYNC_VALUE_CORRUPTED   = 4,

    /* A thread (somewhere) is waiting on the server to complete a wait
     * operation that includes this object. Therefore, if the object is
     * signaled, the server needs to be notified.
     */
    SHM_SYNC_VALUE_NOTIFY_SVR  = 8,

    SHM_SYNC_VALUE_SUCCESS     = 0,
    SHM_SYNC_VALUE_AGAIN       = 5,
    SHM_SYNC_VALUE_FAIL        = 6,
};

/******************************************************************************
 *              struct hybrid_sync_object
 *
 * An abstract synchronization object that contains portions of its data in
 * private and (potentially) shared memory.
 *
 * TODO: we can shrinkthis if we do all value reads via a function that first
 * checks to see if the data is private and then reads from the correct
 * location.
 */
struct hybrid_sync_object
{
    union shm_sync_value    *value;             /* location where actual value is stored */
    unsigned int             flags_refcount;    /* bits 0-5 contain flags (HYBRID_SYNC_*), bits 6-31
                                                 * contain client-side operation-in-progress count. */
    union {
        union shm_sync_value private_value;     /* only when (flags_count HYBRID_SYNC_PRIVATE),
                                                 * value points here if not null */
        int                  hash_base;         /* only when !wine_sync_is_private(), base value for
                                                 * hash (computed at init) */
    };
};

/* flags for struct hybrid_sync_object::flags_refcount */
#define HYBRID_SYNC_SERVER_PRIVATE      0x01 /* Object resides on the server and does not use shared memory. */
#define HYBRID_SYNC_LOCKED              0x02 /* (client) Lock bit for performing move. */
#define HYBRID_SYNC_LOCKED_BIT             1
#define HYBRID_SYNC_ACCESSIBLE          0x04 /* (client) Set if indexed in handle database. */
#define HYBRID_SYNC_ACCESSIBLE_BIT         2
#define HYBRID_SYNC_BAD                 0x08 /* Object is bad */
#define HYBRID_SYNC_BAD_BIT                3
#define HYBRID_SYNC_DBG_DOING_MOVE      0x10 /* REMOVE: for debugging race conditions only! */
#define HYBRID_SYNC_DBG_DOING_MOVE_BIT     4


#define HYBRID_SYNC_FLAGS_BITS   5
#define HYBRID_SYNC_FLAGS_MASK   ((1 << HYBRID_SYNC_FLAGS_BITS) - 1)
#define HYBRID_SYNC_MAX_REFCOUNT (((unsigned int)INT_MAX >> HYBRID_SYNC_FLAGS_BITS) - 1)
#define HYBRID_SYNC_INIT_MASK   HYBRID_SYNC_SERVER_PRIVATE

struct hybrid_semaphore
{
    struct hybrid_sync_object ho;
    unsigned int max;
};

struct hybrid_mutex
{
    struct hybrid_sync_object ho;
    int recursion_count;
};

/******************************************************************************
 *              union hybrid_object_any
 *
 * An fusion of union shm_sync_value-derived types to simplify subclassing.
 *
 * currently 20/24 bytes (for x86 32/64)
 */
union hybrid_object_any
{
    struct {
        union shm_sync_value *value;
        unsigned int          flags_refcount;
    };
    struct hybrid_sync_object ho;
    struct hybrid_semaphore   sem;
    struct hybrid_mutex       mutex;
};

/******************************************************************************
 *              struct shm_object_info
 *
 * Value object used to optimize and simplify function calls related to hybrid
 * synchronization objects. Not all functions that use this struct will populate
 * or read all members.
 */
struct shm_object_info
{
    union {
        struct
        {
            __int64      shm_id;        /* Unique id for the shared memory. */
            unsigned int offset;        /* Offset from start of shared memory to object. */
        };
        unsigned char hash_base_in[12];  /* input for calculating hash_base */
    };
    unsigned int size;                  /* Size of shared memory block in bytes. */
    int          fd;
    void        *ptr;                   /* Pointer to either shm_blk or object (dependent upon context). */
    unsigned int flags;                 /* struct hybrid_sync_object::flags_refcount & SHM_SYNC_VALUE_FLAGS_MASK. */
    unsigned int hash_base;             /* Hash product of shm_id and offset. */
};

/* init function just to mark it as uninitialized for debugging */
static FORCEINLINE struct shm_object_info shm_object_info_init(struct shm_object_info *info)
{
    memset( info, 0x55, sizeof(*info) );
    return *info;
}

static inline int hybrid_object_is_server_private(struct hybrid_sync_object *ho)
{
    return ho->flags_refcount & HYBRID_SYNC_SERVER_PRIVATE;
}

static inline int hybrid_object_bad(struct hybrid_sync_object *ho)
{
    return ho->flags_refcount & HYBRID_SYNC_BAD;
}

enum hybrid_sync_trans_op
{
    HYBRID_SYNC_TRANS_OP_BEGIN,
    HYBRID_SYNC_TRANS_OP_COMMIT,
    HYBRID_SYNC_TRANS_OP_ROLLBACK
};
#define HYBRID_SYNC_TRANS_OP_COUNT 3

extern NTSTATUS hybrid_semaphore_init(struct hybrid_semaphore *sem, unsigned int initial, unsigned int max) SYNC_H_ATTR;
extern NTSTATUS hybrid_semaphore_release(struct hybrid_semaphore *sem, unsigned int count, unsigned int *prev, int do_wake) SYNC_H_ATTR;
extern NTSTATUS __hybrid_semaphore_op(struct hybrid_semaphore *sem, union shm_sync_value *pre_ptr, int change) SYNC_H_ATTR;
extern NTSTATUS __hybrid_semaphore_trans_op(struct hybrid_semaphore *sem, union shm_sync_value *trans_state, enum hybrid_sync_trans_op op, int clear_notify) SYNC_H_ATTR;

extern void hybrid_semaphore_dump(const struct hybrid_semaphore *sem, char **start, const char *const end) SYNC_H_ATTR;
extern NTSTATUS hybrid_semaphore_wait(struct hybrid_semaphore *sem, const struct timespec *timeout) SYNC_H_ATTR;

static inline NTSTATUS hybrid_semaphore_trywait(struct hybrid_semaphore *sem)
{
    union shm_sync_value pre;
    return __hybrid_semaphore_op(sem, &pre, -1);
}

static inline NTSTATUS hybrid_semaphore_trywait_begin_trans(struct hybrid_semaphore *sem,
                                                            union shm_sync_value *trans_state)
{
    return __hybrid_semaphore_trans_op( sem, trans_state, HYBRID_SYNC_TRANS_OP_BEGIN, FALSE );
}

static inline NTSTATUS hybrid_semaphore_trywait_commit(struct hybrid_semaphore *sem,
                                                       union shm_sync_value *trans_state, int clear_notify)
{
    return __hybrid_semaphore_trans_op( sem, trans_state, HYBRID_SYNC_TRANS_OP_COMMIT, clear_notify );
}

static inline NTSTATUS hybrid_semaphore_trywait_rollback(struct hybrid_semaphore *sem,
                                                         union shm_sync_value *trans_state)
{
    return __hybrid_semaphore_trans_op( sem, trans_state, HYBRID_SYNC_TRANS_OP_ROLLBACK, FALSE );
}

extern NTSTATUS hybrid_mutex_init(struct hybrid_mutex *mutex, pid_t initial_owner) SYNC_H_ATTR;
extern NTSTATUS hybrid_mutex_release(struct hybrid_mutex *mutex, pid_t tid) SYNC_H_ATTR;
extern NTSTATUS hybrid_mutex_trywait(struct hybrid_mutex *mutex, pid_t tid) SYNC_H_ATTR;

/* dump functions */
extern void hybrid_object_dump(const struct hybrid_sync_object *ho, char **start, const char *const end) SYNC_H_ATTR;
extern void hybrid_semaphore_dump(const struct hybrid_semaphore *sem, char **start, const char *const end) SYNC_H_ATTR;
extern void hybrid_mutex_dump(const struct hybrid_mutex *mutex, char **start, const char *const end) SYNC_H_ATTR;
extern void shm_object_info_dump(const struct shm_object_info *info, char **start, const char *const end) SYNC_H_ATTR;

#endif /* __WINE_SYNC_H */
