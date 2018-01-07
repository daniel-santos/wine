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


/*****************************************************************************
 * Outstanding Issues and TODOs
 * ----------------------------
 *
 * o Client uses a separate hybrid_object for each handle instead of managing a one
 *   one-to-many (objects to handles) relationship in the handles tree.  This can work
 *   fine as long as the server is keeping track of how many handles the client has,
 *   but it should be reexamined at some point.
 *
 * o Need a complete, clean and formalized debugging scheme enabled via cpp macros.
 *
 *   Client Catagories:
 *   + Races
 *   + Object & handle trees.
 *   + Shared memory and file descriptors.
 *
 *   Server Catagories:
 *   + Shared memory and file descriptors.
 *   + Shared memory slab cacle allocator.
 *
 */


#ifndef __WINE_SYNC_H
#define __WINE_SYNC_H

#include <limits.h>
#include <stdio.h>
#include <assert.h>

/* FIXME: not sure if these next three lines are correct -- need type NTSTATUS. */
#define WIN32_NO_STATUS
#include "winternl.h"           /* for NTSTATUS */
#include "windef.h"             /* for __int64 */

#ifndef WINESERVER
# define WINESERVER 0
#endif

#ifndef SYNC_H_ATTR
# define SYNC_H_ATTR
#endif


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
    SHM_SYNC_VALUE_WAKE_SERVER  = 8,

    SHM_SYNC_VALUE_SUCCESS     = 0,
    SHM_SYNC_VALUE_AGAIN       = 5,
    SHM_SYNC_VALUE_FAIL        = 6,
};

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


/* flags for struct hybrid_sync_object::atomic::flags_refcounts */
//#define HYBRID_SYNC_SERVER_PRIVATE      0x01 /* Object resides on the server and does not use shared memory. */
#define HYBRID_SYNC_LOCKED              0x01 /* (client) Lock bit for performing move. */
#define HYBRID_SYNC_ACCESSIBLE          0x02 /* (client) Set if indexed in handle database. */
#define HYBRID_SYNC_BAD                 0x04 /* Object is bad */
#define HYBRID_SYNC_BAD_BIT                2
//#define HYBRID_SYNC_DBG_DOING_MOVE      0x10 /* REMOVE: for debugging race conditions only! */

#define HYBRID_SYNC_FLAGS_BITS      3
#define HYBRID_SYNC_FLAGS_MASK      ((1ul << HYBRID_SYNC_FLAGS_BITS) - 1ul)
#define HYBRID_SYNC_REFCOUNT_BITS   ((sizeof(long) * 8 + HYBRID_SYNC_FLAGS_BITS) / 2)
#define HYBRID_SYNC_REFCOUNT_MAX    ((1ul << HYBRID_SYNC_REFCOUNT_BITS) - 1ul)
#define HYBRID_SYNC_INIT_MASK       HYBRID_SYNC_SERVER_PRIVATE

#define HSO_ATOMIC_QWORDS (sizeof (void*) / 4)
union hso_atomic {
    __int64 int64[HSO_ATOMIC_QWORDS];
    struct {
	union shm_sync_value *value;           /* location where actual value is stored */
	unsigned long         flags_refcounts;
        /* If bitfields data layout were standardized, this would be:
         * unsigned long flags:4;
         * unsigned long refcount:HYBRID_SYNC_REFCOUNT_BITS;    14 or 30 bits
         * unsigned long waitcount:HYBRID_SYNC_REFCOUNT_BITS;
         */
    };
}__attribute__((aligned(HSO_ATOMIC_QWORDS * 8)));

/* Always bits 0-3. */
static inline unsigned long
hso_atomic_get_flags( const union hso_atomic *atomic )
{
    return atomic->flags_refcounts & HYBRID_SYNC_FLAGS_MASK;
}

/* 32-bit: bits 4-17
 * 64-bit: bits 4-33 */
static inline unsigned long
hso_atomic_get_refcount( const union hso_atomic *atomic )
{
    return (atomic->flags_refcounts >> HYBRID_SYNC_FLAGS_BITS) & HYBRID_SYNC_REFCOUNT_MAX;
}

/* 32-bit: bits 18-31
 * 64-bit: bits 34-63 */
static inline unsigned long
hso_atomic_get_waitcount( const union hso_atomic *atomic )
{
     return atomic->flags_refcounts >> (HYBRID_SYNC_FLAGS_BITS + HYBRID_SYNC_REFCOUNT_BITS);
}

static inline unsigned long
hso_atomic_make_flags_refcounts( unsigned long flags, unsigned long refcount,
                                 unsigned long waitcount)
{
    unsigned long ret;
    assert (!(flags & (~HYBRID_SYNC_FLAGS_MASK)));
    assert (refcount < HYBRID_SYNC_REFCOUNT_MAX);
    assert (waitcount < HYBRID_SYNC_REFCOUNT_MAX);

    ret   = waitcount;
    ret <<= HYBRID_SYNC_REFCOUNT_BITS;
    ret  |= refcount;
    ret <<= HYBRID_SYNC_FLAGS_BITS;
    ret  |= flags;
    return ret;
}

static inline int *hso_atomic_get_wait_addr( const union hso_atomic *atomic )
{
        /* FIXME: not portable.  */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const size_t wait_addr_offset = 0;
#else
    const size_t wait_addr_offset = sizeof(long) / sizeof(int) - 1;
#endif
    return (int*)&atomic->flags_refcounts + wait_addr_offset;
}



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
    union hso_atomic atomic;
    int                  hash_base;
};

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
 * An fusion of union shm_sync_value-derived types to simplify polymoprhism.
 */
union hybrid_object_any
{
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
    } __attribute__((packed));
    unsigned int size;                  /* Size of shared memory block in bytes. */
    int          fd;
    void        *ptr;                   /* Pointer to either shm_blk or object (dependent upon context). */
    unsigned int flags:31;              /* struct hybrid_sync_object::flags_refcount & SHM_SYNC_VALUE_FLAGS_MASK. */
    unsigned int private:1;
    unsigned int hash_base;             /* Hash product of shm_id and offset. */
    union
    {
        struct
        {
            unsigned max;
        } sem;
    };
};

/* Init function to mark all fields as uninitialized (to aid debugging). */
static FORCEINLINE struct shm_object_info shm_object_info_init( void )
{
    struct shm_object_info prototype;
    memset( &prototype, 0x55, sizeof(prototype) );
    return prototype;
}

static inline int hybrid_object_bad(struct hybrid_sync_object *ho)
{
    return ho->atomic.flags_refcounts & HYBRID_SYNC_BAD;
}

enum hybrid_sync_trans_type
{
    HYBRID_SYNC_TRANS_TYPE_MIGRATION,
    HYBRID_SYNC_TRANS_TYPE_SEMAPHORE,
    HYBRID_SYNC_TRANS_TYPE_MUTEX,
    HYBRID_SYNC_TRANS_TYPE_EVENT,

    HYBRID_SYNC_TRANS_TYPE_COUNT
};

enum hybrid_sync_trans_op
{
    HYBRID_SYNC_TRANS_OP_BEGIN,
    HYBRID_SYNC_TRANS_OP_COMMIT,
    HYBRID_SYNC_TRANS_OP_ROLLBACK
};
#define HYBRID_SYNC_TRANS_OP_COUNT 3

/* Semaphore Functions */
extern NTSTATUS hybrid_semaphore_init(struct hybrid_semaphore *sem, unsigned int initial, unsigned int max) SYNC_H_ATTR;
extern NTSTATUS hybrid_semaphore_release(struct hybrid_semaphore *sem, unsigned int count, unsigned int *prev) SYNC_H_ATTR;
extern NTSTATUS __hybrid_semaphore_op(struct hybrid_semaphore *sem, union shm_sync_value *pre_ptr, int maybe_stale, int change) SYNC_H_ATTR;
extern NTSTATUS __hybrid_semaphore_trywait_trans_op(struct hybrid_semaphore *sem, union shm_sync_value *trans_state, enum hybrid_sync_trans_op op, int clear_notify) SYNC_H_ATTR;

extern void hybrid_semaphore_dump(const struct hybrid_semaphore *sem, char **start, const char *const end) SYNC_H_ATTR;
extern NTSTATUS hybrid_semaphore_wait(struct hybrid_semaphore *sem, const struct timespec *timeout) SYNC_H_ATTR;

static inline NTSTATUS hybrid_semaphore_trywait(struct hybrid_semaphore *sem)
{
    union shm_sync_value pre = *sem->ho.atomic.value;
    return __hybrid_semaphore_op(sem, &pre, TRUE, -1);
}

static inline NTSTATUS hybrid_semaphore_trywait_begin_trans(struct hybrid_semaphore *sem,
                                                            union shm_sync_value *trans_state)
{
    return __hybrid_semaphore_trywait_trans_op( sem, trans_state, HYBRID_SYNC_TRANS_OP_BEGIN, FALSE );
}

static inline NTSTATUS hybrid_semaphore_trywait_commit(struct hybrid_semaphore *sem,
                                                       union shm_sync_value *trans_state, int clear_notify)
{
    return __hybrid_semaphore_trywait_trans_op( sem, trans_state, HYBRID_SYNC_TRANS_OP_COMMIT, clear_notify );
}

static inline NTSTATUS hybrid_semaphore_trywait_rollback(struct hybrid_semaphore *sem,
                                                         union shm_sync_value *trans_state)
{
    return __hybrid_semaphore_trywait_trans_op( sem, trans_state, HYBRID_SYNC_TRANS_OP_ROLLBACK, FALSE );
}

/* Mutex Functions */
extern NTSTATUS hybrid_mutex_init(struct hybrid_mutex *mutex, pid_t initial_owner) SYNC_H_ATTR;
extern NTSTATUS hybrid_mutex_release(struct hybrid_mutex *mutex, pid_t tid) SYNC_H_ATTR;
extern NTSTATUS hybrid_mutex_trywait(struct hybrid_mutex *mutex, pid_t tid) SYNC_H_ATTR;

/* dump functions */
extern void hybrid_object_dump(const struct hybrid_sync_object *ho, char **start, const char *const end) SYNC_H_ATTR;
extern void hybrid_semaphore_dump(const struct hybrid_semaphore *sem, char **start, const char *const end) SYNC_H_ATTR;
extern void hybrid_mutex_dump(const struct hybrid_mutex *mutex, char **start, const char *const end) SYNC_H_ATTR;
extern void shm_object_info_dump(const struct shm_object_info *info, char **start, const char *const end) SYNC_H_ATTR;

static inline void assert_sizes( void )
{
    assert( sizeof(long) == sizeof(void*) );
}

#endif /* __WINE_SYNC_H */
