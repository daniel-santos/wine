/*
 * Server-side semaphore management
 *
 * Copyright (C) 1998 Alexandre Julliard
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "thread.h"
#include "request.h"
#include "security.h"
#include "file.h"
#include "process.h"
#include "process_group.h"
#include "shm_slab.h"
#include "wine/sync.h"

union semaphore;
struct semaphore_ops
{
    struct object_ops base;
    /* Release the semaphore. */
    int (*release)( union semaphore *sem, unsigned int count, unsigned int *prev );
    /* Query semaphore value. */
    void (*query)( union semaphore *sem, unsigned int *count, unsigned int *max );
};

struct private_semaphore
{
    struct object  obj;    /* object header */
    unsigned int   count;  /* current count */
    unsigned int   max;    /* maximum possible count */
};

union semaphore
{
    struct object  obj;                     /* common object header */
    struct
    {
        unsigned int                 dummy0;
        unsigned int                 dummy1;
        const struct semaphore_ops  *ops;   /* object ops cast as semaphore_ops */
    };
    struct private_semaphore private;
    struct hybrid_server_object shared;
};

/* Common semaphore functions.  */
static struct object_type *semaphore_get_type( struct object *obj );
static unsigned int semaphore_map_access( struct object *obj, unsigned int access );
static int semaphore_signal( struct object *obj, unsigned int access );

/* Private semaphore functions.  */
static void private_semaphore_dump( struct object *obj, int verbose );
static int private_semaphore_signaled( struct object *obj, struct wait_queue_entry *entry );
static void private_semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry );
static int private_semaphore_release( union semaphore *sem, unsigned int count,
                                      unsigned int *prev );
static void private_semaphore_query( union semaphore *sem, unsigned int *count, unsigned int *max );

static const struct semaphore_ops private_semaphore_ops =
{
    {
        sizeof(union semaphore),       /* size */
        private_semaphore_dump,        /* dump */
        semaphore_get_type,            /* get_type */
        add_queue,                     /* add_queue */
        remove_queue,                  /* remove_queue */
        private_semaphore_signaled,    /* signaled */
        private_semaphore_satisfied,   /* satisfied */
        semaphore_signal,              /* signal */
        no_get_fd,                     /* get_fd */
        semaphore_map_access,          /* map_access */
        default_get_sd,                /* get_sd */
        default_set_sd,                /* set_sd */
        no_lookup_name,                /* lookup_name */
        directory_link_name,           /* link_name */
        default_unlink_name,           /* unlink_name */
        no_open_file,                  /* open_file */
        no_close_handle,               /* close_handle */
        no_destroy,                    /* destroy */
        NULL,                          /* trywait_begin_trans */
        NULL,                          /* trywait_commit */
        NULL                           /* trywait_rollback */
    },
    private_semaphore_release,         /* release */
    private_semaphore_query            /* query */
};

/* Shared semaphore functions.  */
static void shared_semaphore_dump( struct object *obj, int verbose );
static void shared_semaphore_destroy(struct object *obj);
static NTSTATUS shared_semaphore_trywait_begin_trans( struct object *obj,
                                                      struct wait_queue_entry *entry );
static NTSTATUS shared_semaphore_trywait_commit( struct object *obj, int clear_notify );
static NTSTATUS shared_semaphore_trywait_rollback( struct object *obj );
static int shared_semaphore_release( union semaphore *sem, unsigned int count, unsigned int *prev );
static void shared_semaphore_query( union semaphore *sem, unsigned int *count, unsigned int *max );

static const struct semaphore_ops shared_semaphore_ops =
{
    {
        sizeof(union semaphore),              /* size */
        shared_semaphore_dump,                /* dump */
        semaphore_get_type,                   /* get_type */
        add_queue,                            /* add_queue */
        remove_queue,                         /* remove_queue */
        NULL,                                 /* signaled */
        NULL,                                 /* satisfied */
        semaphore_signal,                     /* signal */
        no_get_fd,                            /* get_fd */
        semaphore_map_access,                 /* map_access */
        default_get_sd,                       /* get_sd */
        default_set_sd,                       /* set_sd */
        no_lookup_name,                       /* lookup_name */
        directory_link_name,                  /* link_name */
        default_unlink_name,                  /* unlink_name */
        no_open_file,                         /* open_file */
        process_group_close_handle,           /* close_handle */
        shared_semaphore_destroy,             /* destroy */
        shared_semaphore_trywait_begin_trans, /* trywait_begin_trans */
        shared_semaphore_trywait_commit,      /* trywait_commit */
        shared_semaphore_trywait_rollback     /* trywait_rollback */
    },
    shared_semaphore_release,                 /* release */
    shared_semaphore_query                    /* query */
};


/*****************************************************************************
 *                  Common semaphore functions
 */

static struct object_type *semaphore_get_type( struct object *obj )
{
    static const WCHAR name[] = {'S','e','m','a','p','h','o','r','e'};
    static const struct unicode_str str = { name, sizeof(name) };
    return get_object_type( &str );
}

static unsigned int semaphore_map_access( struct object *obj, unsigned int access )
{
    if (access & GENERIC_READ)    access |= STANDARD_RIGHTS_READ | SEMAPHORE_QUERY_STATE;
    if (access & GENERIC_WRITE)   access |= STANDARD_RIGHTS_WRITE | SEMAPHORE_MODIFY_STATE;
    if (access & GENERIC_EXECUTE) access |= STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE;
    if (access & GENERIC_ALL)     access |= STANDARD_RIGHTS_ALL | SEMAPHORE_ALL_ACCESS;
    return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static union semaphore *create_semaphore( struct object *root, const struct unicode_str *name,
                                           unsigned int attr, unsigned int initial, unsigned int max,
                                           const struct security_descriptor *sd,
                                           struct shm_object_info *info, int *private )
{
    union semaphore *sem;
    int req_private = *private;
    const struct object_ops *ops_array[2];

    if (!max || (initial > max))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return NULL;
    }

    if (!have_shm() || !staging_sync_enabled())
        req_private = TRUE;

    ops_array[0] = req_private ? &private_semaphore_ops.base : &shared_semaphore_ops.base;
    ops_array[1] = req_private ? &shared_semaphore_ops.base  : &private_semaphore_ops.base;
    if ((sem = create_named_polytype_object( root, ops_array, 2, name, attr, sd )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            assert( !*private || sem->ops == &private_semaphore_ops );

            /* initialize it if it didn't already exist */
            if (sem->ops == &private_semaphore_ops)
            {
                *private = TRUE;
                sem->private.count = initial;
                sem->private.max   = max;
            }
            else
            {
                NTSTATUS result;
                assert( sem->ops == &shared_semaphore_ops );
                *private = FALSE;

                if (hybrid_server_object_init( &sem->shared, info, current->process ))
                    goto exit_error;

                /* init semaphore */
                result = hybrid_semaphore_init( &sem->shared.any.sem, initial, max );
                if (result == STATUS_SUCCESS)
                    return sem;

                set_error( result );
exit_error:
                release_object( &sem->obj );
                return NULL;
            }
        }
    }
    return sem;
}

static int semaphore_signal( struct object *obj, unsigned int access )
{
    union semaphore *sem = (union semaphore *)obj;
    assert( sem->ops == &private_semaphore_ops || sem->ops == &shared_semaphore_ops);

    if (!(access & SEMAPHORE_MODIFY_STATE))
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }
    return sem->ops->release( sem, 1, NULL );
}



/*****************************************************************************
 *                  Private semaphore functions
 */

__cold static void private_semaphore_dump( struct object *obj, int verbose )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops.base );
    fprintf( stderr, "Semaphore count=%d max=%d\n", sem->count, sem->max );
}

static int private_semaphore_signaled( struct object *obj, struct wait_queue_entry *entry )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops.base );
    return (sem->count > 0);
}

static void private_semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops.base );
    assert( sem->count );
    sem->count--;
}

static int private_semaphore_release( union semaphore *generic_sem, unsigned int count,
                                      unsigned int *prev )
{
    struct private_semaphore *sem = (struct private_semaphore *)generic_sem;

    assert( generic_sem->obj.ops == &private_semaphore_ops.base );
    if (prev) *prev = sem->count;
    if (sem->count + count < sem->count
        || sem->count + count > sem->max)
    {
        set_error( STATUS_SEMAPHORE_LIMIT_EXCEEDED );
        return 0;
    }
    else if (sem->count)
    {
        /* there cannot be any thread to wake up if the count is != 0 */
        sem->count += count;
    }
    else
    {
        sem->count = count;
        wake_up( &sem->obj, count );
    }
    return 1;
}

static void private_semaphore_query( union semaphore *generic_sem, unsigned int *current,
                                     unsigned int *max )
{
    struct private_semaphore *sem = (struct private_semaphore *)generic_sem;
    assert( generic_sem->obj.ops == &private_semaphore_ops.base );
    *current = sem->count;
    *max = sem->max;
}


/*****************************************************************************
 *                  Shared semaphore functions
 */

__cold static void shared_semaphore_dump( struct object *obj, int verbose )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    struct hybrid_semaphore *hs = &sem->any.sem;
    char buf[0x400];
    char *start = buf;

    assert( obj->ops == &shared_semaphore_ops.base );
    hybrid_semaphore_dump( hs, &start, &buf[sizeof(buf)]);
    fprintf( stderr, "Semaphore %p any.sem = %s, refcount %u, process_group = %p ", obj, buf, obj->refcount, sem->process_group );
    fputc( '\n', stderr );
}

static void shared_semaphore_destroy(struct object *obj)
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops.base );
    hybrid_server_object_destroy( sem );
}

static NTSTATUS shared_semaphore_trywait_begin_trans( struct object *obj, struct wait_queue_entry *wait )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops.base );
    return hybrid_semaphore_trywait_begin_trans( &sem->any.sem, &sem->trans_state );
}

static NTSTATUS shared_semaphore_trywait_commit( struct object *obj, int clear_notify )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops.base );
    return hybrid_semaphore_trywait_commit( &sem->any.sem, &sem->trans_state, clear_notify );
}

static NTSTATUS shared_semaphore_trywait_rollback( struct object *obj )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops.base );
    return hybrid_semaphore_trywait_rollback( &sem->any.sem, &sem->trans_state );
}

static int shared_semaphore_release( union semaphore *generic_sem, unsigned int count,
                                     unsigned int *prev_ret )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)generic_sem;
    unsigned int prev;
    NTSTATUS ret;

    assert( generic_sem->obj.ops == &shared_semaphore_ops.base );
    ret = hybrid_semaphore_release( &sem->any.sem, count, &prev );
    if (prev_ret)
        *prev_ret = prev;

    if (ret)
        set_error( ret );
    else if (!prev)
        wake_up( &sem->obj, count );

    hybrid_server_object_check( sem );

    return !ret;
}

static void shared_semaphore_query( union semaphore *generic_sem, unsigned int *current,
                                    unsigned int *max )
{
    NTSTATUS result;
    struct hybrid_server_object *sem = (struct hybrid_server_object *)generic_sem;
    assert( generic_sem->ops == &shared_semaphore_ops );
    if ((result = hybrid_server_object_query( sem, current )))
        set_error( result );
    *max = sem->any.sem.max;
}

/*****************************************************************************
 *                  Request Handlers
 */

/* create a semaphore */
DECL_HANDLER(create_semaphore)
{
    union semaphore *sem;
    struct unicode_str name;
    struct object *root;
    const struct security_descriptor *sd;
    const struct object_attributes *objattr = get_req_object_attributes( &sd, &name, &root );
    struct shm_object_info info             = shm_object_info_init( );
    unsigned int access                     = req->access & SYNC_OBJECT_ACCESS_MASK;
    int private                             = !!(req->access & SYNC_OBJECT_ACCESS_SERVER_ONLY);

    if (!objattr) return;

    if ((sem = create_semaphore( root, &name, objattr->attributes, req->initial, req->max, sd,
                                 &info, &private )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current->process, sem, access, objattr->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current->process, sem,
                                                          access, objattr->attributes );
        reply->private = !!private;
        reply->shm_id = info.shm_id;
        reply->offset = info.offset;
        release_object( sem );
    }

    if (root) release_object( root );
}

/* open a handle to a semaphore */
DECL_HANDLER(open_semaphore)
{
    struct unicode_str name = get_req_unicode_str();
    struct shm_object_info info = shm_object_info_init( );

    reply->handle = shared_object_open( current->process, req->rootdir, req->access,
                                        &private_semaphore_ops.base, &shared_semaphore_ops.base,
                                        &name, req->attributes, &info );

    reply->private = info.private;
    reply->shm_id  = info.shm_id;
    reply->offset  = info.offset;
    reply->max     = info.sem.max;
}

/* release a semaphore */
DECL_HANDLER(release_semaphore)
{
    const struct object_ops *ops[2] = {&private_semaphore_ops.base, &shared_semaphore_ops.base};
    union semaphore *sem;

    if ((sem = (union semaphore *)get_handle_polytype_obj( current->process, req->handle,
                                                           SEMAPHORE_MODIFY_STATE, ops, 2 )))
    {
        sem->ops->release( sem, req->count, &reply->prev_count);
        release_object( &sem->obj );
    }
}

/* query details about the semaphore */
DECL_HANDLER(query_semaphore)
{
    const struct object_ops *ops[2] = {&private_semaphore_ops.base, &shared_semaphore_ops.base};
    union semaphore *sem;

    if ((sem = (union semaphore *)get_handle_polytype_obj( current->process, req->handle,
                                                           SEMAPHORE_QUERY_STATE, ops, 2 )))
    {
        sem->ops->query( sem, &reply->current, &reply->max );
        release_object( &sem->obj );
    }
}
