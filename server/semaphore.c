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

struct private_semaphore
{
    struct object  obj;    /* object header */
    unsigned int   count;  /* current count */
    unsigned int   max;    /* maximum possible count */
};

union any_semaphore
{
    struct object  obj;    /* common object header */
    struct private_semaphore private;
    struct hybrid_server_object shared;
};

/* Common semaphore functions.  */
static struct object_type *semaphore_get_type( struct object *obj );
static unsigned int semaphore_map_access( struct object *obj, unsigned int access );

/* Private semaphore functions.  */
static void private_semaphore_dump( struct object *obj, int verbose );
static int private_semaphore_signaled( struct object *obj, struct wait_queue_entry *entry );
static void private_semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry );
static int private_semaphore_signal( struct object *obj, unsigned int access );

static const struct object_ops private_semaphore_ops =
{
    sizeof(union any_semaphore),   /* size */
    private_semaphore_dump,        /* dump */
    semaphore_get_type,            /* get_type */
    add_queue,                     /* add_queue */
    remove_queue,                  /* remove_queue */
    private_semaphore_signaled,    /* signaled */
    private_semaphore_satisfied,   /* satisfied */
    private_semaphore_signal,      /* signal */
    no_get_fd,                     /* get_fd */
    semaphore_map_access,          /* map_access */
    default_get_sd,                /* get_sd */
    default_set_sd,                /* set_sd */
    no_lookup_name,                /* lookup_name */
    directory_link_name,           /* link_name */
    default_unlink_name,           /* unlink_name */
    no_open_file,                  /* open_file */
    no_close_handle,               /* close_handle */
    no_destroy                     /* destroy */
};

/* Shared semaphore functions.  */
static void shared_semaphore_dump( struct object *obj, int verbose );
static void shared_semaphore_destroy(struct object *obj);
static NTSTATUS shared_semaphore_trywait_begin_trans( struct object *obj, struct wait_queue_entry *entry );
static NTSTATUS shared_semaphore_trywait_commit( struct object *obj, int clear_notify );
static NTSTATUS shared_semaphore_trywait_rollback( struct object *obj );

static const struct object_ops shared_semaphore_ops =
{
    sizeof(union any_semaphore),          /* size */
    shared_semaphore_dump,                /* dump */
    semaphore_get_type,                   /* get_type */
    add_queue,                            /* add_queue */
    remove_queue,                         /* remove_queue */
    NULL,                                 /* signaled */
    NULL,                                 /* satisfied */
    NULL,                                 /* signal */
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

static union any_semaphore *create_semaphore( struct object *root, const struct unicode_str *name,
                                           unsigned int attr, unsigned int initial, unsigned int max,
                                           const struct security_descriptor *sd,
                                           struct shm_object_info *info, int *private )
{
    union any_semaphore *sem;
    int req_private = *private;
    const struct object_ops *ops_array[2];

    if (!max || (initial > max))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return NULL;
    }

    if (!have_shm() || !staging_sync_enabled())
        req_private = TRUE;

    ops_array[0] = req_private ? &private_semaphore_ops : &shared_semaphore_ops;
    ops_array[1] = req_private ? &shared_semaphore_ops  : &private_semaphore_ops;
    if ((sem = create_named_polytype_object( root, ops_array, 2, name, attr, sd )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */
            if (sem->obj.ops == &private_semaphore_ops)
            {
                *private = TRUE;
                sem->private.count = initial;
                sem->private.max   = max;
            }
            else
            {
                NTSTATUS result;
                assert( sem->obj.ops == &shared_semaphore_ops );
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


/*****************************************************************************
 *                  Private semaphore functions
 */

__cold static void private_semaphore_dump( struct object *obj, int verbose )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops );
    fprintf( stderr, "Semaphore count=%d max=%d\n", sem->count, sem->max );
}

static int private_semaphore_signaled( struct object *obj, struct wait_queue_entry *entry )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops );
    return (sem->count > 0);
}

static void private_semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops );
    assert( sem->count );
    sem->count--;
}

static int private_semaphore_release( struct private_semaphore *sem, unsigned int count,
                                      unsigned int *prev )
{
    assert( sem->obj.ops == &private_semaphore_ops );
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

static int private_semaphore_signal( struct object *obj, unsigned int access )
{
    struct private_semaphore *sem = (struct private_semaphore *)obj;
    assert( obj->ops == &private_semaphore_ops );

    if (!(access & SEMAPHORE_MODIFY_STATE))
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }
    return private_semaphore_release( sem, 1, NULL );
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

    assert( obj->ops == &shared_semaphore_ops );
    hybrid_semaphore_dump( hs, &start, &buf[sizeof(buf)]);
    fprintf( stderr, "Semaphore %p any.sem = %s, refcount %u, process_group = %p ", obj, buf, obj->refcount, sem->process_group );
    fputc( '\n', stderr );
}

static void shared_semaphore_destroy(struct object *obj)
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops );

    hybrid_server_object_destroy( sem );
}

static NTSTATUS shared_semaphore_trywait_begin_trans( struct object *obj, struct wait_queue_entry *wait )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops );
    return hybrid_semaphore_trywait_begin_trans( &sem->any.sem, &sem->trans_state );
}

static NTSTATUS shared_semaphore_trywait_commit( struct object *obj, int clear_notify )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops );
    return hybrid_semaphore_trywait_commit( &sem->any.sem, &sem->trans_state, clear_notify );
}

static NTSTATUS shared_semaphore_trywait_rollback( struct object *obj )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &shared_semaphore_ops );
    return hybrid_semaphore_trywait_rollback( &sem->any.sem, &sem->trans_state );
}

#if 0
static int shared_release_semaphore( struct hybrid_server_object *sem, unsigned int count, unsigned int *prev_ret )
{
    unsigned int prev;
    NTSTATUS ret;

    assert( sem->obj.ops == &shared_semaphore_ops );
    ret = hybrid_semaphore_release( &sem->any.sem, count, &prev );
    if (prev_ret)
        *prev_ret = prev;

    if (ret)
        set_error( ret );
    else if (!prev)
        wake_up( &sem->obj, count );

    return !ret;
}
#endif


/*****************************************************************************
 *                  Request Handlers
 */

/* create a semaphore */
DECL_HANDLER(create_semaphore)
{
    union any_semaphore *sem;
    struct unicode_str name;
    struct object *root;
    const struct security_descriptor *sd;
    const struct object_attributes *objattr = get_req_object_attributes( &sd, &name, &root );
    struct shm_object_info info             = shm_object_info_init( );
    unsigned int access                     = req->access & SYNC_OBJECT_ACCESS_MASK;
    int private                             = req->access & SYNC_OBJECT_ACCESS_SERVER_ONLY;

    if (!objattr) return;

    if ((sem = create_semaphore( root, &name, objattr->attributes, req->initial, req->max, sd,
                                 &info, &private )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current->process, sem, access, objattr->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current->process, sem,
                                                          access, objattr->attributes );
        reply->private = private;
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
                                        &private_semaphore_ops, &shared_semaphore_ops,
                                        &name, req->attributes, &info );

    reply->private = info.private;
    reply->shm_id  = info.shm_id;
    reply->offset  = info.offset;
    reply->max     = info.sem.max;
}

/* release a semaphore */
DECL_HANDLER(release_semaphore)
{
    const struct object_ops *ops[2] = {&private_semaphore_ops, &shared_semaphore_ops};
    union any_semaphore *sem;

    if ((sem = (union any_semaphore *)get_handle_polytype_obj( current->process, req->handle,
                                                               SEMAPHORE_MODIFY_STATE, ops, 2 )))
    {
        if (sem->obj.ops == &private_semaphore_ops)
            private_semaphore_release( &sem->private, req->count, &reply->prev_count );
        else
        {
#if 1
            /* Client should perform locally.  */
            fprintf( stderr, "wineserver: WARNING: %s called for shared semaphore.\n", __func__ );
            set_error( STATUS_NOT_IMPLEMENTED );
            assert(0);
#else
            shared_release_semaphore( &sem->shared, req->count, &reply->prev_count );
            hybrid_server_object_check( &sem->shared );
#endif
        }
        release_object( &sem->obj );
    }
}

/* query details about the semaphore */
DECL_HANDLER(query_semaphore)
{
    const struct object_ops *ops[2] = {&private_semaphore_ops, &shared_semaphore_ops};
    union any_semaphore *sem;

    if ((sem = (union any_semaphore *)get_handle_polytype_obj( current->process, req->handle,
                                                               SEMAPHORE_QUERY_STATE, ops, 2 )))
    {
        if (sem->obj.ops == &private_semaphore_ops)
        {
            reply->current = sem->private.count;
            reply->max = sem->private.max;
        }
        else
        {
#if 1
            /* Client should perform query locally.  */
            fprintf( stderr, "wineserver: WARNING: %s called for shared semaphore.\n", __func__ );
            set_error( STATUS_NOT_IMPLEMENTED );
            assert(0);
#else
            asm volatile( "":::"memory" );
            reply->current = sem->shared.any.ho.atomic.value->data;
            reply->max = sem->shared.any.sem.max;
            hybrid_server_object_check( &sem->shared );
#endif
        }
        release_object( &sem->obj );
    }
}
