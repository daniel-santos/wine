/*
 *      Hybrid Object management functions
 *
 * Copyright 2015-2016 Daniel Santos
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

#include "config.h"
#include "wine/port.h"

/* TODO: trim down includes */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_IO_H
# include <io.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/debug.h"
#include "windef.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/server.h"
#include "wine/rbtree.h"
#include "wine/sync.h"
#include "wine/sync_impl_client.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdllobj);

# ifndef __linux__
#  error "This experimental patch set does not yet supported on your OS."
# else
# endif /* __linux__ */

static DECLSPEC_COLD void rwlock_fail( const char *op, int err, const char *file, unsigned line )
{
    errno = err;
    perror( op );
    ERR( "%s failed with %d from %s:%u\n", op, err, file, line );
    assert( 0 );
}

static void __rwlock_begin_read( pthread_rwlock_t *rwlock, sigset_t *sigset, const char *file,
                                 unsigned line )
{
    int ret;
    struct timespec timeout;

    timeout.tv_sec = 60;
    timeout.tv_nsec = 0;

    pthread_sigmask( SIG_BLOCK, &server_block_set, sigset );
    for (;;)
    {
        ret = pthread_rwlock_timedrdlock( rwlock, &timeout );
        if (ret == ETIMEDOUT)
            WARN( "timeout, retrying: pid %d, tid %ld\n", getpid(), syscall(SYS_gettid) );
        else
            break;
    }
    if (ret)
        rwlock_fail( "pthread_rwlock_timedrdlock", ret, file, line );
}

static void __rwlock_begin_write( pthread_rwlock_t *rwlock, sigset_t *sigset, const char *file,
                                  unsigned line )
{
    int ret;
    struct timespec timeout;

    timeout.tv_sec = 60;
    timeout.tv_nsec = 0;

    pthread_sigmask( SIG_BLOCK, &server_block_set, sigset );
    for (;;)
    {
        ret = pthread_rwlock_timedwrlock( rwlock, &timeout );
        if (ret == ETIMEDOUT)
            WARN( "timeout, retrying: pid %d, tid %ld\n", getpid(), syscall(SYS_gettid) );
        else
            break;
    }
    if (ret)
        rwlock_fail( "pthread_rwlock_timedwrlock", ret, file, line );
}

static inline void __rwlock_end( pthread_rwlock_t *rwlock, sigset_t *sigset, const char *file,
                                 unsigned line )
{
    int ret = pthread_rwlock_unlock( rwlock );

    if (ret)
        rwlock_fail( "pthread_rwlock_unlock", ret, file, line );
    pthread_sigmask( SIG_SETMASK, sigset, NULL );
}

#define rwlock_begin_read(  rwlock, sigset ) __rwlock_begin_read(  rwlock, sigset, __FILE__, __LINE__ )
#define rwlock_begin_write( rwlock, sigset ) __rwlock_begin_write( rwlock, sigset, __FILE__, __LINE__ )
#define rwlock_end(         rwlock, sigset ) __rwlock_end(         rwlock, sigset, __FILE__, __LINE__ )

/*
 * Theory of Operation
 * -------------------
 *
 * Hybrid objects have a representation on both the client and server. The client-side
 * representation is an object of type struct ntdll_object. A handle-to-object database is
 * maintained in this file so that operations on such objects can be carried out locally when
 * appropriate. Calls that cannot be serviced locally are forwarded to the server.
 *
 * Client object to server object mapping
 * --------------------------------------
 *
 * There are many ways for a single process to obtain multiple handles to a the same object.
 * This implementation maps a single ntdll_object to a single handle.  Multiple ntdll_objects may
 * exist in the same process that utilize the same shared memory location such that concurrency is
 * no different than two processes accessing the same object in shared memory.
 */


/* FIXME: portability */
static __thread char *tls_debug_buffer = NULL;
#define NTDLL_DEBUG_BUFFER_SIZE 0x400

static const char *const obj_type_desc[NTDLL_OBJ_TYPE_ID_MAX] = {
    "async I/O",                                /* NTDLL_OBJ_TYPE_ID_ASYNC */
    "event",                                    /* NTDLL_OBJ_TYPE_ID_EVENT */
    "I/O completion ports",                     /* NTDLL_OBJ_TYPE_ID_COMPLETION */
    "file",                                     /* NTDLL_OBJ_TYPE_ID_FILE */
    "mail slot",                                /* NTDLL_OBJ_TYPE_ID_MAILSLOT */
    "mutex",                                    /* NTDLL_OBJ_TYPE_ID_MUTEX */
    "message queue",                            /* NTDLL_OBJ_TYPE_ID_MSG_QUEUE */
    "process",                                  /* NTDLL_OBJ_TYPE_ID_PROCESS */
    "semaphore",                                /* NTDLL_OBJ_TYPE_ID_SEMAPHORE */
    "thread",                                   /* NTDLL_OBJ_TYPE_ID_THREAD */
    "waitable timer",                           /* NTDLL_OBJ_TYPE_ID_WAITABLE_TIMER */
};

/* List containing all process-locally known objects */
static struct {
    struct list         list;   /* list of all struct ntdll_object ojbects */
    pthread_rwlock_t    rwlock; /* lock for reading/modifying list */

} objects = {
    {NULL, NULL},
    PTHREAD_RWLOCK_INITIALIZER
};

/*************************************************************************
 * ntdll_object_new
 *
 * Allocates and initializes a new struct ntdll_object object.
 *
 * PARAMS
 *  dest       [O]
 *  h          [I] Handle of the object.
 *  size       [I] Number of bytes to allocate.
 *  type       [I] Pointer to function table & type information.
 *  info       [IO]
 *
 * RETURNS
 *  Success:
 *      STATUS_SUCCESS
 *  Failure:
 *      STATUS_NO_MEMORY
 *      TODO: finish list
 *
 * NOTES
 *  Allocates and initialises a struct ntdll_object object and adds it to
 *  process-global list. Initial refcount is 1. After the derived-type
 *  initialises its members the object should be added to the handle database
 *  by calling ntdll_handle_add(), which will increase set its
 *  HYBRID_SYNC_ACCESSIBLE flag. Once this is done, the object should be
 *  released with ntdll_object_release().
 *
 * LOCKING
 *  objects.rwlock
 *
 * info needs to have initialized:
 *      private
 *      shm_id   - if not private
 *      offset   - if not private
 */

NTSTATUS ntdll_object_new( struct ntdll_object **dest, const HANDLE h, size_t size,
                           struct ntdll_object_type *type, struct shm_object_info *info )
{
    struct ntdll_object *obj;
    sigset_t sigset;
    NTSTATUS ret;

    assert( size >= sizeof(*obj) );
    assert( type->id < NTDLL_OBJ_TYPE_ID_MAX );
#if 0
    if (TRACE_ON(ntdllobj))
    {
        char buf[0x400];
        char *start = buf;
        shm_object_info_dump(info, &start, &buf[0x400]);
        //TRACE_(ntdllobj)
        fprintf(stderr, "%p, %zu, %u (%s), %p, info = %s\n", h, size, type->id,
                obj_type_desc[type->id], type, buf);
    }
#endif
    obj = RtlAllocateHeap( GetProcessHeap(), HEAP_CREATE_ALIGN_16, size );
    if (!obj)
    {
        ERR_(ntdllobj)( "Failed to alloc %zu bytes\n", sizeof(*obj) );
        *dest = NULL;
        return STATUS_NO_MEMORY;
    }

    memset( obj, 0x55, size );

    obj->type    = type;
    obj->h       = h;
    obj->private = info->private;
//
    if (info->private)
    {
#if 0
        info->ptr       = NULL;
        info->hash_base = 0;
        info->offset    = 0;
#endif
    }
    else
    {
        info->ptr = NULL;
        ret = server_get_object_shared_memory( h, info );

        if (ret || !info->ptr)
        {
            ERR_(ntdllobj)( "server_get_object_shared_memory returned %08x\n", ret );
            goto exit_error;
        }
if (0)
{
    char buf[0x400];
    char *start = buf;
    shm_object_info_dump( info, &start, &buf[0x400] );
    //TRACE_(ntdllobj)
    fprintf( stderr, "%s: %p, %zu, %u (%s), %p, info = %s\n", __func__, h, size, type->id,
             obj_type_desc[type->id], type, buf );
}
        hybrid_object_init( &obj->any.ho, info );
    }

if (0)
{
    char buf[0x400];
    char *start = buf;
    obj->type->dump( obj, &start, &buf[0x400] );
    //TRACE_(ntdllobj)
    fprintf( stderr, "%s: %s\n", __func__, buf );
}

    rwlock_begin_write( &objects.rwlock, &sigset );
    list_add_tail( &objects.list, &obj->list_entry );
    rwlock_end( &objects.rwlock, &sigset );

    /* tree node left uninitialized */

    *dest = obj;
    return STATUS_SUCCESS;

exit_error:
    RtlFreeHeap( GetProcessHeap(), 0, obj );
    *dest = NULL;
    return ret;
}

/* This is a hook to give the object a chance to do anything special that needs
 * to happen when the shared memory portion of the object is moved */
static NTSTATUS ntdll_object_move( struct hybrid_sync_object *ho, struct shm_object_info *info )
{
    /* upcast */
    struct ntdll_object *obj = LIST_ENTRY( ho, struct ntdll_object, any );
    void *old_ptr = ho->atomic.value;
    NTSTATUS result;

    info->ptr    = NULL; /* let virtual.c decide where to put it */
    info->shm_id = 0;    /* we need the new location */

    if ((result = server_get_object_shared_memory( obj->h, info )))
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus( result );

    if (old_ptr)
        virtual_release_shared_memory( old_ptr );
#if 0
fprintf(stderr, "shm %p %08x %08x\n", info->ptr, ((union shm_sync_value*)info->ptr)->data, ((union shm_sync_value*)info->ptr)->flags_hash);
if (1)
{
char buf[0x400];
char *start = buf;
const char *end = &buf[0x400];
shm_object_info_dump( info, &start, end);
fprintf(stderr, "%s: %s\n", __func__, buf);
}
#endif
    return result;
}

static NTSTATUS ntdll_object_destroy( struct hybrid_sync_object *ho )
{
    struct ntdll_object *obj = LIST_ENTRY( ho, struct ntdll_object, any );
    sigset_t sigset;

    assert( !(hso_atomic_get_flags( &ho->atomic ) & HYBRID_SYNC_ACCESSIBLE) );
    assert( hso_atomic_get_refcount( &ho->atomic ) == 0 );
    assert( hso_atomic_get_waitcount( &ho->atomic ) == 0 );

    TRACE_(ntdllobj)( "Removing & freeing object %s\n", ntdll_object_dump(obj) );
    rwlock_begin_write( &objects.rwlock, &sigset );
    list_remove( &obj->list_entry );
    rwlock_end( &objects.rwlock, &sigset );
    if (obj->type->close)
        obj->type->close( obj );

    if (ho->atomic.value)
        virtual_release_shared_memory( ho->atomic.value );

//#if defined(DEBUG) || defined(DEBUG_OBJECTS)
    memset( obj, 0xaa, sizeof(struct ntdll_object) );
//#endif
    RtlFreeHeap( GetProcessHeap(), 0, obj );

    return 0;
}

static void ntdll_object_server_wake(struct hybrid_sync_object *ho)
{
    struct ntdll_object *obj = LIST_ENTRY(ho, struct ntdll_object, any);
    server_wake( obj->h );
}

/*************************************************************************
 * ntdll_object_grab
 *
 * Increases refcount by one and a LOT of other stuff I haven't documented.
 *
 * PARAMS
 *  obj        [I] The object.
 *
 * RETURN
 *  SUCCESS: 0
 *  FAILURE:
 *     STATUS_FILE_CORRUPT_ERROR        shared memory data is corrupt
 *     STATUS_TOO_MANY_THREADS          more than 134m threads or unpaired begin/end calls
 */
NTSTATUS DECLSPEC_MUST_CHECK ntdll_object_grab( struct ntdll_object *obj )
{
    NTSTATUS ret = hybrid_object_grab( &obj->any.ho );
    if (ret)
        ERR_(ntdllobj)( "hybrid_object_grab failed with %08x", ret );

    return ret;
}

/*************************************************************************
 * ntdll_object_release
 *
 * Decrease refcount by one, possibly destroying the object
 *
 * PARAMS
 *  obj        [I] The object.
 *
 * NOTES
 *  While using an object, it is possible for another thread to call
 *  CloseHandle(), removing it from the handle database (and decreasing its
 *  refcount). Therefore you should not use the pointer after a call to
 *  ntdll_object_release() returns.
 *
 * LOCKING
 *  objects.rwlock
 */
NTSTATUS DECLSPEC_MUST_CHECK ntdll_object_release( struct ntdll_object *obj )
{
    NTSTATUS ret = hybrid_object_release( &obj->any.ho, FALSE, NULL );
    if (ret)
        ERR_(ntdllobj)( "hybrid_object_release failed with %08x", ret );

    return ret;
}

/*************************************************************************
 * ntdll_object_dump_base
 *
 * Called by derived-class to dump a text description of base class members.
 *
 * PARAMS
 *  obj         [I]  The object to dump
 *  start       [IO] Pointer to a pointer to the next write position.
 *  end         [I]  Pointer to one byte past the end of the buffer.
 *
 * NOTES
 *  Called by derived class to dump struct ntdll_object to a string buffer.
 *  The pointer that start points to will be updated to the new end of the
 *  text so that subsequent writes may begin there.
 */
void ntdll_object_dump_base( const struct ntdll_object *obj, char **start, const char *const end )
{
    int count;

    assert( start && *start && end );
    assert( end > *start );

    if (!obj)
        count = snprintf( *start, end - *start, "(NULL)" );
    else
    {
        const char *any_str;
        assert( obj->type->id < NTDLL_OBJ_TYPE_ID_MAX );
        switch ( obj->type->id )
        {
        case NTDLL_OBJ_TYPE_ID_SEMAPHORE:
            any_str = "sem";
            break;

        case NTDLL_OBJ_TYPE_ID_MUTEX:
            any_str = "mutex";
            break;

        default:
            any_str = "ho";
            break;
        }

        count = snprintf( *start, end - *start,
                          "%p {"
                          "type = %p (type->id = %u (%s)), "
                          "any.%s = ",
                          obj,
                          obj->type, obj->type->id, obj_type_desc[obj->type->id],
                          any_str );
        if (count < 0)
            goto error;
        *start += count;

        switch (obj->type->id)
        {
        case NTDLL_OBJ_TYPE_ID_SEMAPHORE:
            hybrid_semaphore_dump( &obj->any.sem, start, end );
            break;

        case NTDLL_OBJ_TYPE_ID_MUTEX:
            hybrid_mutex_dump( &obj->any.mutex, start, end );
            break;

        default:
            hybrid_object_dump( &obj->any.ho, start, end );
            break;
        }

        count = snprintf( *start, end - *start,
//                          ", shm = %p, "
                          ", h = %p, "
                          "tree_entry = {left = %p, right = %p, flags = 0x%x}, "
                          "list_entry = {next = %p, prev = %p}"
                          "}",
//                          obj->shm,
                          obj->h,
                          obj->tree_entry.left, obj->tree_entry.right, obj->tree_entry.flags,
                          obj->list_entry.next, obj->list_entry.prev );
    }

    if (count < 0)
    {
error:
        perror( "snprintf" );
        return;
    }

    *start += count;
}

/* return a thread-local buffer for dumping object descriptions to */
static void *ntdll_object_get_debug_buffer( size_t *size )
{
    /* FIXME: free this on thread exit (not sure where that is hooked) */
    if (!tls_debug_buffer)
        tls_debug_buffer = RtlAllocateHeap( GetProcessHeap(), 0, NTDLL_DEBUG_BUFFER_SIZE );

    if (size)
        *size = tls_debug_buffer ? NTDLL_DEBUG_BUFFER_SIZE : 0;
    return tls_debug_buffer;
}

/*************************************************************************
 * ntdll_object_dump
 *
 * Dumps a text description of the object to a thread-local buffer.
 *
 * PARAMS
 *  obj         [I]  The object to dump
 *
 * RETURNS
 *  A pointer to a text description of the object.
 *
 * NOTES
 *  Because this function uses a thread-local buffer, you must use the result
 *  before calling it again. For instance, this code will not work:
 *
 *  ERR("%s will look the same as %s\n", ntdll_object_dump(o1), ntdll_object_dump(02));
 */
const char *ntdll_object_dump(const struct ntdll_object *obj)
{
    char *start;
    const char *ret;
    size_t size;

    if (!(start = ntdll_object_get_debug_buffer(&size)))
        return NULL;

    ret = start;
    if (!obj)
        snprintf(start, size, "(NULL)");
    else if (obj->type->dump)
        obj->type->dump(obj, &start, start + size);
    else
        ntdll_object_dump_base(obj, &start, start + size);

    return ret;
}


void ntdll_object_dump_by_handle(const HANDLE h)
{
    const char *ret = NULL;
    struct ntdll_object *obj = ntdll_handle_find( h );
    if (obj)
    {
	NTSTATUS result;
	ret = ntdll_object_dump (obj);
	result = ntdll_object_release (obj);
	if (!result)
	    fprintf(stderr, "ERROR: ntdll_object_release returned %d (0x%04x)\n", result, result);
    }
    else
	ret = "ntdll object not found\n";

    fputs(ret, stderr);
    //return ret;
}

/* red-black tree functions for handle table */
static inline void *ntdll_handle_rb_alloc(size_t size)
{
    return RtlAllocateHeap(GetProcessHeap(), 0, size);
}

static inline void *ntdll_handle_rb_realloc(void *ptr, size_t size)
{
    return RtlReAllocateHeap(GetProcessHeap(), 0, ptr, size);
}

static inline void ntdll_handle_rb_free(void *ptr)
{
    RtlFreeHeap(GetProcessHeap(), 0, ptr);
}

static inline int ntdll_handle_compare(const void *key, const struct wine_rb_entry *entry)
{
    const HANDLE *_a = key;
    const HANDLE *_b = &WINE_RB_ENTRY_VALUE(entry, const struct ntdll_object, tree_entry)->h;

    return *_a > *_b ? 1 : (*_a < *_b ? -1 : 0);
}

/* Tree mapping all process-locally known kernel handles to a struct ntdll_object */
static struct {
    struct wine_rb_tree tree;
    pthread_rwlock_t    rwlock;
} handles = {
    { ntdll_handle_compare, NULL},
    PTHREAD_RWLOCK_INITIALIZER
};

/*************************************************************************
 * ntdll_handle_add
 *
 * Adds the object to the ntdll handle database
 *
 * PARAMS
 *  obj        [I] The object.
 *
 * NOTES
 *  Adds the object to the handle database, increasing its reference count to
 *  account for it being referenced by the handle tree.
 *
 * LOCKING
 *  handles.rwlock
 *  ?? for use only when object is accessible by a single thread (not mt safe) ??
 *
 * noinline because we're instantiating wine_rb_put here
 *
 */
__attribute__((noinline)) NTSTATUS ntdll_handle_add(struct ntdll_object *obj)
{
    NTSTATUS ret;
    sigset_t sigset;

    TRACE_(ntdllobj)("%p\n", obj);

    rwlock_begin_write(&handles.rwlock, &sigset);

    /* ret != 0 could be due to either a duplicate key or out of memory */
    ret = wine_rb_put(&handles.tree, &obj->h, &obj->tree_entry);

    /* mark object HYBRID_SYNC_ACCESSIBLE */
    if (ret == 0)
    {
        //ret = hybrid_object_mark_accessible( &obj->any.ho, TRUE );
	struct hybrid_sync_object *ho = &obj->any.ho;
	union hso_atomic pre = ho->atomic;
	//fprintf(stderr, "asdf flags_refcount %08x\n", ho->atomic.flags_refcount);
	//assert (ho->atomic.flags_refcount >> 4 == 1);
	ret = hso_client_op( ho, &pre, TRUE, HSO_CLIENT_OP_LIST, NULL, NULL );

	//if (!ret)
//	    assert (ho->atomic.flags_refcount & HYBRID_SYNC_ACCESSIBLE);

    }
    rwlock_end(&handles.rwlock, &sigset);
//    if (ret)

    if (unlikely(ret))
    {
        /* FIXME: most of this is debugging stuff, probably remove it all */
        NTSTATUS result;

        struct ntdll_object *existing = ntdll_handle_find(obj->h);
        ERR_(ntdllobj)("Failed to insert object into handle tree. status = %08x, %s\n", RtlGetLastNtStatus(), ntdll_object_dump(obj));

        if (existing)
        {
            ERR_(ntdllobj)("Existing object: %s\n", ntdll_object_dump(existing));
            result = ntdll_object_release(existing);
            if (result)
                ERR_(ntdllobj)("Error releasing object %08x\n", result);
        }
        else
        {
            ERR_(ntdllobj)("No other object found with that handle...status %08x\n", RtlGetLastNtStatus());
        }
        ERR_(ntdllobj)("New object: %s\n", ntdll_object_dump(obj));

        assert(0);
        return STATUS_DUPLICATE_NAME;
    }

    TRACE_(ntdllobj)("h = %p, obj = %s\n", obj->h, ntdll_object_dump(obj));

    return ret;
}

/*************************************************************************
 * ntdll_handle_remove
 *
 *  Remove an object from the handle database.
 *
 * PARAMS
 *  h           [I] A handle to remove.
 *
 * NOTES
 *  If no object with the specified handle is found then nothing is done.
 *
 * LOCKING
 *  handles.rwlock
 */
__attribute__((noinline))
NTSTATUS ntdll_handle_remove( const HANDLE h )
{
    struct ntdll_object *obj = ntdll_handle_find( h );
    unsigned refs;
    NTSTATUS ret;
    //NTSTATUS result, result_release;
    //int accessible;
    sigset_t sigset;

    if (!obj)
        return STATUS_INVALID_HANDLE;

    TRACE_(ntdllobj)("h = %p, obj = %s\n", h, ntdll_object_dump( obj ));

    rwlock_begin_write( &handles.rwlock, &sigset );
    wine_rb_remove( &handles.tree, &obj->tree_entry );
    rwlock_end( &handles.rwlock, &sigset );

    ret = hybrid_object_release( &obj->any.ho, TRUE, &refs );
    if (!ret && !refs)
    SERVER_START_REQ( close_handle )
    {
        req->handle = wine_server_obj_handle( h );
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;

    return ret;
}

/*************************************************************************
 * ntdll_handle_find
 *
 *  Searches the process-local handle database for the specified object.
 *
 * PARAMS
 *  h           [I] Handle of an object.
 *
 * NOTES
 *  If an object with a matching handle is found then the object's refcount is
 *  incremented and a pointer to the object is returned. It is then the
 *  responsibility of the caller to release the object when done.
 *
 * RETURNS
 *  Success: A pointer to the object.
 *  Failure: NULL and NtCurrentTeb()->LastStatusValue is set to the error
 *
 * LOCKING
 *  handles.rwlock
 *
 */
struct ntdll_object *ntdll_handle_find( const HANDLE h )
{
    struct wine_rb_entry *entry;
    struct ntdll_object *ret = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;

    rwlock_begin_read(&handles.rwlock, &sigset);
    entry = wine_rb_get(&handles.tree, &h);

    if (entry)
    {
        ret = WINE_RB_ENTRY_VALUE(entry, struct ntdll_object, tree_entry);

        /* ntdll_object_grab is MT safe, but if we release the rwlock prior to grabbing the object
         * then we'll have a race -- we could get preempted prior to grab completing and another
         * thread calls NtClose() thereby removing it from the handle db and the object being
         * destroyed while we still have a pointer to it. */
        if ((status = ntdll_object_grab(ret)))
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
    }
    rwlock_end(&handles.rwlock, &sigset);

    //TRACE_(ntdllobj)("(%p) result: status = %08x, obj = %p\n", h, status, ret);

    return status ? NULL : ret;
}


__attribute__((optimize(2)))
static void ntdll_object_whose_use_cb(struct wine_rb_entry *entry, void *context)
{
    struct ntdll_object *obj = WINE_RB_ENTRY_VALUE(entry, struct ntdll_object, tree_entry);
    size_t *nhandles = (size_t *)context;
    if (!list_has( &objects.list, &obj->list_entry ))
        WARN_(ntdllobj)("In handle tree, but not object list: %s\n", ntdll_object_dump(obj));
//    unsigned refcount;

    ++(*nhandles);
}

void ntdll_object_whose_use(void *ptr)
{
    size_t nhandles = 0;
    size_t nobjects = 0;
    size_t shm_count;
    struct shm_dbg *shm_blocks;
    struct ntdll_object *obj;
    sigset_t sigset;
    shm_count = virtual_shared_memory_dumpeth( &shm_blocks, GetProcessHeap() );

    assert( shm_blocks ); //ENOMEM

    TRACE_(ntdllobj)("\n");
    rwlock_begin_read(&handles.rwlock, &sigset);
    wine_rb_for_each_entry(&handles.tree, ntdll_object_whose_use_cb, &nhandles);
    rwlock_end(&handles.rwlock, &sigset);

#if 1
    rwlock_begin_read(&objects.rwlock, &sigset);
    //nobjects = list_count(&objects.list);

    LIST_FOR_EACH_ENTRY( obj, &objects.list, struct ntdll_object , list_entry )
    {
        size_t i;
        const char* p = *(const char* volatile*)&obj->any.ho.atomic.value;

        ++nobjects;
        for (i = 0; i < shm_count; ++i) {
            const char *start = (const char*)shm_blocks[i].base;
            const char *end = start + shm_blocks[i].size;
            if (p >= start && p < end)
            {
                fprintf(stderr, "ntdll_object %p uses %p in block %p (size %u, refcount %u)\n",
                        obj, p, shm_blocks[i].base, shm_blocks[i].size, shm_blocks[i].refcount);
                break;
            }
        }
        if (i == shm_count)
            fprintf(stderr, "WARNING: not found ntdll_object %p using %p\n", obj, p);
        //ERR_(ntdllobj)("Leaked object: %s\n", ntdll_object_dump(obj));
    }
    rwlock_end(&objects.rwlock, &sigset);

    fprintf(stderr, "%zu objects, %zu handles\n\n", nobjects, nhandles);

    RtlFreeHeap( GetProcessHeap(), 0, shm_blocks );
#endif
}



/* callback for ntdll_objects_cleanup()
 *
 * LOCKING
 *  Locks objects.rwlock (via ntdll_object_release())
 *  Called when handles.rwlock already locked
 */

static void ntdll_objects_cleanup_cb(struct wine_rb_entry *entry, void *context)
{
    struct ntdll_object *obj = WINE_RB_ENTRY_VALUE(entry, struct ntdll_object, tree_entry);
    size_t *leaked_handles = (size_t *)context;
//    unsigned refcount;

    ++(*leaked_handles);

    WARN_(ntdllobj)("Leaked object handle: %s\n", ntdll_object_dump(obj));

#if 0
    refcount = obj->any.ho.atomic.flags_refcount >> HYBRID_SYNC_FLAGS_BITS;
    if (refcount)
        ERR_(ntdllobj)("object %p has refcount = %\n", obj, refcount);

    /* handles.rwlock already locked */
    wine_rb_remove(&handles.tree, &obj->h);
#endif
}

/* atexit() cleanup
 *
 * Locking:
 *      Locks handles.rwlock --> then objects.rwlock
 */
static void ntdll_objects_cleanup(void)
{
    size_t leaked_handles = 0;
    size_t leaked_objects = 0;
    sigset_t sigset;

    TRACE_(ntdllobj)("\n");
    rwlock_begin_write(&handles.rwlock, &sigset);
    wine_rb_for_each_entry(&handles.tree, ntdll_objects_cleanup_cb, &leaked_handles);
    rwlock_end(&handles.rwlock, &sigset);

    rwlock_begin_write(&objects.rwlock, &sigset);
    leaked_objects = list_count(&objects.list);
    if (leaked_objects)
    {
        struct ntdll_object *obj;
        //struct list *i;
        LIST_FOR_EACH_ENTRY( obj, &objects.list, struct ntdll_object , list_entry )
        {
            ERR_(ntdllobj)("Leaked object: %s\n", ntdll_object_dump(obj));
        }
    }
    rwlock_end(&objects.rwlock, &sigset);

    if (leaked_handles || leaked_objects)
        ERR_(ntdllobj)("*** %zu leaked handles found, %zu leaked objects remain.\n",
                        leaked_handles, leaked_objects);

}

int shm_sync_enabled;
#if 0
typedef struct
{
    void           *unknown;    /* 00 unknown */
    UNICODE_STRING *exe_name;   /* 04 exe module name */

    /* the following fields do not exist under Windows */
    UNICODE_STRING  exe_str;    /* exe name string pointed to by exe_name */
    CURDIR          curdir;     /* current directory */
    WCHAR           curdir_buffer[MAX_PATH];
} WIN16_SUBSYSTEM_TIB;
#endif


extern char **__wine_main_argv;
/*************************************************************************
 * ntdll_object_db_init
 *
 *  Initialize objects list and handles tree
 *
 * NOTES
 *  Called via __wine_process_init() in loader.c
 *
 * LOCKING
 *  First locks objects.rwlock, then releases and locks handles.rwlock
 */
NTSTATUS ntdll_object_db_init(void)
{
    NTSTATUS ret = 0;
    sigset_t sigset;
/* FIXME: this is really terrible...  */
    shmglobal_t *shmglobal    = NtCurrentTeb()->Reserved5[1];
    const char *shm_val       = getenv( "STAGING_SHARED_MEMORY" );
    const char *shm_sync_val  = getenv( "STAGING_SHM_SYNC" );
    const char *shm_sync_imgs = getenv( "STAGING_SHM_SYNC_TARGETS" );

#if defined(__linux__) && (defined(__i386__) || defined(__x86_64__))
    shm_sync_enabled = shm_val
                    && shm_sync_val
                    && atoi(shm_val)
                    && atoi(shm_sync_val);
#else
    shm_sync_enabled = 0;
#endif

    shared_sync_assert_sizes(); /* blow up if type sizes and offsets fail to match assumptions. */

    /* If using STAGING_SHM_SYNC_TARGETS, disable if not one of the listed images.  */
    if (shm_sync_enabled && shm_sync_imgs)
    {
	char *imgs = RtlAllocateHeap(GetProcessHeap(), 0, strlen(shm_sync_imgs) + 1);
	char *img = RtlAllocateHeap(GetProcessHeap(), 0, strlen(shm_sync_imgs) + 1);
	char *p;

	if (!(imgs && img))
	    return ERROR_OUTOFMEMORY;

	strcpy (imgs, shm_sync_imgs);
	strcpy (img, __wine_main_argv[1]);
	if (strchr (img, '.'))
	    *strchr (img, '.') = 0;

	shm_sync_enabled = 0;
	for (p = strtok(imgs, ","); p; p = strtok(NULL, ","))
	{
	    if (!strcmp (p, img))
		shm_sync_enabled = 1;
	}
	fprintf(stderr, "\n\nHybrid Sync %sabled for process %s\n", shm_sync_enabled ? "EN" : "DIS", img);
	RtlFreeHeap(GetProcessHeap(), 0, img);
	RtlFreeHeap(GetProcessHeap(), 0, imgs);

    }
    sync_impl_init( ntdll_object_move, ntdll_object_destroy, ntdll_object_server_wake,
                    shmglobal ? &shmglobal->last_server_cpu : NULL );

    TRACE_(ntdllobj)("\n");

    /* init objects list if not already inited */
    rwlock_begin_write(&objects.rwlock, &sigset);
    if (!objects.list.next)
        list_init(&objects.list);
    rwlock_end(&objects.rwlock, &sigset);

    atexit(ntdll_objects_cleanup);

    return ret;
}