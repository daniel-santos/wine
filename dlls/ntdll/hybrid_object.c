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

#include "wine/sync.h"
#include "wine/sync_impl_client.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdllobj);

# ifndef __linux__
#  error "This proof of concept not supported on your OS. Maybe you should get a new one..."
# else
/* TODO: integrate futex_wait/wake with criticalsection.c */
# endif /* __linux__ */

static __cold void rwlock_fail( const char *op, int err, const char *file, unsigned line )
{
    errno = err;
    perror(op);
    ERR("%s failed with %d from %s:%u\n", op, err, file, line);
    assert(err);
}

static inline void __rwlock_begin_read( pthread_rwlock_t *rwlock, sigset_t *sigset, const char *file, unsigned line )
{
    int ret;
    pthread_sigmask( SIG_BLOCK, &server_block_set, sigset );
    ret = pthread_rwlock_rdlock( rwlock );
    if (ret)
        rwlock_fail( "pthread_rwlock_rdlock", ret, file, line );
}

static inline void __rwlock_begin_write( pthread_rwlock_t *rwlock, sigset_t *sigset, const char *file, unsigned line )
{
    int ret;
    pthread_sigmask( SIG_BLOCK, &server_block_set, sigset );
    ret = pthread_rwlock_wrlock( rwlock );
    if (ret)
        rwlock_fail( "pthread_rwlock_wrlock", ret, file, line );
}

static inline void __rwlock_end( pthread_rwlock_t *rwlock, sigset_t *sigset, const char *file, unsigned line )
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
 *      Hybrid Migratory Userspace Ojbects
 *
 * Definitions
 * ===========
 * hybrid object -
 *      an object composed of two portions: a private portion residing in private memory and a
 *      shared portion that (potentially) resides in shared memory.
 *
 * hybrid migratory object -
 *      a hybrid object who's shared portion can be moved on-the-fly to another location. All hybrid
 *      objects in this implementation are migratory, but we just call them "hybrid objects" for
 *      brivity.
 *
 * Design
 * ======
 *
 * Hybrid objects are designed to have two different storage strategies:
 *
 * o shared
 *      The object's "shared" portion resides in shared memory, with one or more clients and the
 *      server having references to it.
 *
 * o server-private
 *      an object who's "shared" portion resides only on the server in private memory. These are
 *      needed by critical sections and other code that is a part of synchronization library.
 *
 *
 * Process-local (client-side) object information management
 * =========================================================
 *
 * Theory of Operation
 * -------------------
 *
 * Hybrid objects have a representation on both the client and server. The client-side
 * representation is an object of type struct ntdll_object. A handle-to-object database is
 * maintained in this file so that operations on such objects can be carried out locally when
 * appropriate. Calls that cannot be serviced locally are deferred to the server.
 *
 * Client object to server object mapping
 * --------------------------------------
 *
 * There are a number of ways for a single process to obtain multiple handles to a the same object.
 * However, this design maps a single ntdll_object to a single handle. This is currently managed by
 * the fact client-private objects are not currently supported and multiple ntdll_objects operating
 * on the same shared memory behave the same as if
 * that client-private objects (i.e., objects where no shared memory is used and
 * Currently, each handle that a process has gets its own
 * ntdll_object. This
 * It is possible to have more than one handle to a single object
 *
 * Lifecycle of a struct ntdll_object object
 *
 * EDIT: we now use a combination of refcount and the HYBRID_SYNC_ACCESSIBLE bit in
 * struct struct hybrid_sync_object::flags_refcount.
 *
 * Rather than using a refcount
 * Below is an example of an object's lifecycle.
 *
 * Accesible  Refcount     Operation
 * (no object)              Execute a server call that creates an object & returns a handle.
 * 1            Call ntdll_object_new() passing handle to allocate a new struct ntdll_object.
 *              * allocates & zeros struct ntdll_object
 *              * adds to objects.list (double-linked list)
 * 1            Initialize derived-type data members
 * 2            Call ntdll_handle_add() to index handle in handles.tree (red-black tree)
 * 1            Call ntdll_object_release() when done with the object.
 * ....
 * (no object)  We receive an API call that we might be able to manage client-side
 * 2            Call ntdll_handle_find() on the handle and get the object
 * 2            Perform whatever we need to do locally
 * 1            Call ntdll_object_release() when done with the object.
 * ...
 * (no object)  We receive a call to NtClose (CloseHandle)
 * 2            Call ntdll_handle_find() on the handle and get the object
 * 1            Call ntdll_handle_remove() to remove it from handles.tree.
 * 0            Call ntdll_object_release()
 *              * object is removed from list
 *              * refcount reaches zero and destructor type->close() is called
 *              * memory is freed
 *
 * Because we're doing this in the multi-threaded environment of the client process instead of
 * the safety of the single-threaded server, things won't always go as above. It is possible
 * for a call to NtClose to be received while another thread is still using the object, so
 * that the object returned by Call ntdll_handle_find() may have a refcount of 3 or more.
 * However, the object should be immediately delisted, so we can have many live objects
 * with the same handle, but only one of those handles (the one in the tree) is the living
 * one.
 *
 * TODO: Make sure that UB is acceptable for when a program tries to use a stale handle, or
 * should we zero the handle when it's removed from the tree (NtClose returns).
 */


/* FIXME: portability */
static __thread char *tls_debug_buffer = NULL;
#define NTDLL_DEBUG_BUFFER_SIZE 0x400

static const char * const obj_type_desc[NTDLL_OBJ_TYPE_ID_MAX] = {
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
    PTHREAD_RWLOCK_INITIALIZER,
};

/*************************************************************************
 * ntdll_object_new
 *
 * Allocates and initializes a new struct ntdll_object object.
 *
 * PARAMS
 *  h          [I] Handle of the object.
 *  size       [I] Number of bytes to allocate.
 *  type       [I] Pointer to function table & type information.
 *
 * RETURNS
 *  Success: A pointer to the new object.
 *  Failure: Null, indicating a low memory condition.
 *
 * NOTES
 *  Allocates and initialises a struct ntdll_object object and adds it to
 *  process-global list. Initial refcount is 1. After the derived-type
 *  initialises its members the object should be added to the handle database
 *  by calling ntdll_handle_add(), which will increase its refcount to 2. Once
 *  this is done, the object should be released with ntdll_object_release().
 *  If you release it before that, the object will auto-destruct.
 *
 * LOCKING
 *  objects.rwlock
 *
 * info needs to have initialized:
 *      flags
 *      server_fd
 *      offset
 *
 */

NTSTATUS ntdll_object_new(struct ntdll_object **dest, const HANDLE h, size_t size,
                          struct ntdll_object_type *type, struct shm_object_info *info)
{
    struct ntdll_object *obj;
    sigset_t sigset;
    NTSTATUS ret;

    assert(size >= sizeof(*obj));
    assert(type->id < NTDLL_OBJ_TYPE_ID_MAX);

    if (TRACE_ON(ntdllobj))
    {
        char buf[0x400];
        char *start = buf;
        shm_object_info_dump(info, &start, &buf[0x400]);
        //TRACE_(ntdllobj)
        fprintf(stderr, "%p, %zu, %u (%s), %p, info = %s\n", h, size, type->id,
                          obj_type_desc[type->id], type, buf);
    }

    assert(!(info->flags & HYBRID_SYNC_SERVER_PRIVATE));

    obj = RtlAllocateHeap(GetProcessHeap(), 0, size);
    if (!obj)
    {
        ERR_(ntdllobj)("Failed to alloc %zu bytes\n", sizeof(*obj));
        *dest = NULL;
        return STATUS_NO_MEMORY;
    }

    memset(obj, 0x55, size);

    obj->type       = type;
    obj->h          = h;
//    obj->shm        = NULL;

    /* will this object use shared memory? */
    if (!(info->flags & HYBRID_SYNC_SERVER_PRIVATE))
    {
        info->ptr = NULL;
        ret = server_get_object_shared_memory(h, info);

        if (ret || !info->ptr)
        {
            ERR_(ntdllobj)("server_get_object_shared_memory returned %08x\n", ret);
            goto exit_error;
        }
        info->hash_base = fnv1a_hash32( FNV1A_32_INIT, info->hash_base_in, sizeof (info->hash_base_in) );
if (0)
{
    char buf[0x400];
    char *start = buf;
    shm_object_info_dump(info, &start, &buf[0x400]);
    //TRACE_(ntdllobj)
    fprintf(stderr, "%s: %p, %zu, %u (%s), %p, info = %s\n", __func__, h, size, type->id,
                        obj_type_desc[type->id], type, buf);
}

    }
    else
    {
        info->ptr       = NULL;
        info->hash_base = 0;
        info->offset    = 0;
    }

    hybrid_object_init(&obj->any.ho, info->ptr, info->flags, info->hash_base);
if (0)
{
    char buf[0x400];
    char *start = buf;
    obj->type->dump(obj, &start, &buf[0x400]);
    //TRACE_(ntdllobj)
    fprintf(stderr, "%s: %s\n", __func__, buf);
}

    rwlock_begin_write(&objects.rwlock, &sigset);
    list_add_tail(&objects.list, &obj->list_entry);
    rwlock_end(&objects.rwlock, &sigset);

    /* tree node left uninitialized */

    *dest = obj;
    return STATUS_SUCCESS;

exit_error:
    RtlFreeHeap(GetProcessHeap(), 0, obj);
    *dest = NULL;
    return ret;
}

/* This is a hook to give the object a chance to do anything special that needs
 * to happen when the shared memory portion of the object is moved */
static NTSTATUS ntdll_object_move(struct hybrid_sync_object *ho)
{
    struct ntdll_object *obj    = LIST_ENTRY(ho, struct ntdll_object, any);
    struct shm_object_info info = shm_object_info_init( &info );
    NTSTATUS result;

    info.ptr    = NULL; /* let virtual.c decide where to put it */
    info.shm_id = 0;    /* we need the new location */

    if ((result = server_get_object_shared_memory(obj->h, &info)))
    {
        ho->value     = NULL;
        ho->hash_base = 0;
        RtlSetLastWin32ErrorAndNtStatusFromNtStatus(result);
    }
    else
    {
        ho->value     = info.ptr;
        ho->hash_base = fnv1a_hash32( FNV1A_32_INIT, info.hash_base_in, sizeof (info.hash_base_in) );
    }
if (0)
{
char buf[0x400];
char *start = buf;
const char *end = &buf[0x400];
shm_object_info_dump( &info, &start, end);
fprintf(stderr, "%s: %s\n", __func__, buf);
}

    return result;
}

static NTSTATUS ntdll_object_destroy(struct hybrid_sync_object *ho)
{
    struct ntdll_object *obj = LIST_ENTRY(ho, struct ntdll_object, any);
    sigset_t sigset;
//fprintf(stderr, "\n\n*************************************** %s: %p\n\n", __func__, ho);
    /* accessible bit cleared and refcount == 0 */
    assert(! ((ho->flags_refcount & HYBRID_SYNC_ACCESSIBLE)
           || (ho->flags_refcount >> HYBRID_SYNC_FLAGS_BITS)));

    TRACE_(ntdllobj)("Removing & freeing object %s\n", ntdll_object_dump(obj));
    rwlock_begin_write(&objects.rwlock, &sigset);
    list_remove(&obj->list_entry);
    rwlock_end(&objects.rwlock, &sigset);
    if (obj->type->close)
        obj->type->close(obj);

    if (ho->value)
        virtual_release_shared_memory(ho->value);

//#if defined(DEBUG) || defined(DEBUG_OBJECTS)
    memset(obj, 0xaa, sizeof(struct ntdll_object));
//#endif
    RtlFreeHeap(GetProcessHeap(), 0, obj);

    return 0;
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
NTSTATUS __must_check ntdll_object_grab(struct ntdll_object *obj)
{
    NTSTATUS ret = hybrid_object_grab( &obj->any.ho );
    if (ret)
        ERR_(ntdllobj)("hybrid_object_grab failed with %08x", ret);

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
NTSTATUS __must_check ntdll_object_release(struct ntdll_object *obj)
{
    NTSTATUS ret = hybrid_object_release( &obj->any.ho );
    if (ret)
        ERR_(ntdllobj)("hybrid_object_release failed with %08x", ret);

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
void ntdll_object_dump_base(const struct ntdll_object *obj, char **start, const char *const end)
{
    int count;

    assert(start && *start && end);
    assert(end > *start);

    if (!obj)
        count = snprintf(*start, end - *start, "(NULL)");
    else
    {
        const char *any_str;
        assert(obj->type->id < NTDLL_OBJ_TYPE_ID_MAX);
        switch (obj->type->id)
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

        count = snprintf(*start, end - *start,
                         "%p {"
                         "type = %p (type->id = %u (%s)), "
                         "any.%s = ",
                         obj,
                         obj->type, obj->type->id, obj_type_desc[obj->type->id],
                         any_str);
        if (count < 0)
            goto error;
        *start += count;

        switch (obj->type->id)
        {
        case NTDLL_OBJ_TYPE_ID_SEMAPHORE:
            hybrid_semaphore_dump( &obj->any.sem, start, end);
            break;

        case NTDLL_OBJ_TYPE_ID_MUTEX:
            hybrid_mutex_dump( &obj->any.mutex, start, end);
            break;

        default:
            hybrid_object_dump( &obj->any.ho, start, end);
            break;
        }

        count = snprintf(*start, end - *start,
//                         ", shm = %p, "
                         ", h = %p, "
                         "tree_entry = {left = %p, right = %p, flags = 0x%x}, "
                         "list_entry = {next = %p, prev = %p}"
                         "}",
//                         obj->shm,
                         obj->h,
                         obj->tree_entry.left, obj->tree_entry.right, obj->tree_entry.flags,
                         obj->list_entry.next, obj->list_entry.prev);
    }

    if (count < 0)
    {
error:
        perror("snprintf");
        return;
    }

    *start += count;
}

/* return a thread-local buffer for dumping object descriptions to */
static void *ntdll_object_get_debug_buffer(size_t *size)
{
    /* FIXME: free this on thread exit (not sure where that is hooked) */
    if (!tls_debug_buffer)
        tls_debug_buffer = RtlAllocateHeap(GetProcessHeap(), 0, NTDLL_DEBUG_BUFFER_SIZE);

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

static const struct wine_rb_functions obj_handles_rb_ops =
{
    ntdll_handle_rb_alloc,
    ntdll_handle_rb_realloc,
    ntdll_handle_rb_free,
    ntdll_handle_compare,
};

/* Tree mapping all process-locally known kernel handles to a struct ntdll_object */
static struct {
    struct wine_rb_tree tree;
    pthread_rwlock_t    rwlock;
} handles = {
    { &obj_handles_rb_ops, NULL, {NULL, 0, 0}}, /* static initializer to aid -findirect-inline */
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
        int accessible = hybrid_object_mark_accessible( &obj->any.ho, TRUE );
        /* it shouldn't have previously been marked */
        assert (!accessible);
    }
    rwlock_end(&handles.rwlock, &sigset);

    if (unlikely(ret == -1))
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
NTSTATUS ntdll_handle_remove(const HANDLE h)
{
    struct ntdll_object *obj = ntdll_handle_find(h);
    int accessible;
    sigset_t sigset;

    if (!obj)
        return STATUS_SUCCESS;

    TRACE_(ntdllobj)("h = %p, obj = %s\n", h, ntdll_object_dump(obj));

    rwlock_begin_write(&handles.rwlock, &sigset);
    /* TODO: a more efficient wine_rb_remove_by_entry would be nice here */
    wine_rb_remove(&handles.tree, &h);
    rwlock_end(&handles.rwlock, &sigset);

    accessible = hybrid_object_mark_accessible( &obj->any.ho, FALSE );

    /* it should have previously been marked */
    assert (accessible);

    return ntdll_object_release(obj); /* release object (probably destroyed after this) */
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
struct ntdll_object *ntdll_handle_find(const HANDLE h)
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
        if ((status = ntdll_object_grab(ret)))
            RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
    }
    rwlock_end(&handles.rwlock, &sigset);

    //TRACE_(ntdllobj)("(%p) result: status = %08x, obj = %p\n", h, status, ret);

    return status ? NULL : ret;
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
    refcount = obj->any.ho.flags_refcount >> HYBRID_SYNC_FLAGS_BITS;
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
    shmglobal_t *shmglobal   = NtCurrentTeb()->Reserved5[0];
    const char *shm_val      = getenv( "STAGING_SHARED_MEMORY" );
    const char *shm_sync_val = getenv( "STAGING_SHM_SYNC" );

#if defined(__linux__) && (defined(__i386__) || defined(__x86_64__))
    shm_sync_enabled = shm_val
                    && shm_sync_val
                    && atoi(shm_val)
                    && atoi(shm_sync_val);
#else
    shm_sync_enabled = 0;
#endif

    sync_impl_init( ntdll_object_move, ntdll_object_destroy, &shmglobal->last_server_cpu);
    TRACE_(ntdllobj)("\n");

    /* init objects list if not already inited */
    rwlock_begin_write(&objects.rwlock, &sigset);
    if (!objects.list.next)
        list_init(&objects.list);
    rwlock_end(&objects.rwlock, &sigset);

    /* init red-black handle-to-object tree if not already inited */
    rwlock_begin_write(&handles.rwlock, &sigset);
    if (!handles.tree.stack.entries)
    {
        /* passing handles.tree.functions instead of obj_handles_rb_ops to aid -findirect-inline
         * (it might not matter) */
        if (wine_rb_init(&handles.tree, handles.tree.functions) == -1)
        {
            ERR("Failed to initialize ntdll object handle rbtree.\n");
            ret = ERROR_OUTOFMEMORY;
        }
        else
            atexit(ntdll_objects_cleanup);
    }
    rwlock_end(&handles.rwlock, &sigset);

    return ret;
}
