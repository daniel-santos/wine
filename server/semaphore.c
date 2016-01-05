/*
 * Server-side semaphore management
 *
 * Copyright (C) 1998 Alexandre Julliard
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

static void semaphore_dump( struct object *obj, int verbose );
static struct object_type *semaphore_get_type( struct object *obj );
static unsigned int semaphore_map_access( struct object *obj, unsigned int access );
static void semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry);
static int semaphore_signal( struct object *obj, unsigned int access );
static void semaphore_destroy(struct object *obj);
//static NTSTATUS semaphore_trywait( struct object *obj, struct wait_queue_entry *entry );
static NTSTATUS semaphore_trywait_begin_trans( struct object *obj, struct wait_queue_entry *entry );
static NTSTATUS semaphore_trywait_commit( struct object *obj, int clear_notify );
static NTSTATUS semaphore_trywait_rollback( struct object *obj );

static const struct object_ops semaphore_ops =
{
    sizeof(struct hybrid_server_object),      /* size */
    semaphore_dump,                /* dump */
    semaphore_get_type,            /* get_type */
    add_queue,                     /* add_queue */
    remove_queue,                  /* remove_queue */
    NULL,                          /* signaled */
    semaphore_satisfied,           /* satisfied */
    semaphore_signal,              /* signal */
    no_get_fd,                     /* get_fd */
    semaphore_map_access,          /* map_access */
    default_get_sd,                /* get_sd */
    default_set_sd,                /* set_sd */
    no_lookup_name,                /* lookup_name */
    no_open_file,                  /* open_file */
    process_group_close_handle,    /* close_handle */
    semaphore_destroy,             /* destroy */
    semaphore_trywait_begin_trans, /* trywait_begin_trans */
    semaphore_trywait_commit,      /* trywait_commit */
    semaphore_trywait_rollback     /* trywait_rollback */
};

static struct hybrid_server_object *
create_semaphore( struct directory *root, const struct unicode_str *name,
                  unsigned int attr, unsigned int initial, unsigned int max,
                  const struct security_descriptor *sd,
                  struct shm_object_info *info, int server_only )
{
    struct hybrid_server_object *sem;
    NTSTATUS ret;

    if (!max || (initial > max))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return NULL;
    }
    if ((sem = create_named_object_dir( root, name, attr, &semaphore_ops )))
    {
        struct object *obj = &sem->obj;
        struct hybrid_sync_object *ho = &sem->any.ho;

        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */

            if (sd) default_set_sd( &sem->obj, sd, OWNER_SECURITY_INFORMATION|
                                                   GROUP_SECURITY_INFORMATION|
                                                   DACL_SECURITY_INFORMATION|
                                                   SACL_SECURITY_INFORMATION );
//fprintf(stderr, "shmglobal = %p\n", shmglobal);
            /* init struct hybrid_server_object base (this will give us the shared or private object
             * sem->any). */
            if (hybrid_server_object_init( sem, info, server_only ? HYBRID_SYNC_SERVER_PRIVATE : 0 ))
                goto exit_error;
//fprintf(stderr, "FLAGS %x\n", sem->any.ho.flags_refcount);
            /* init semaphore */
            ret = hybrid_semaphore_init( &sem->any.sem, initial, max );
            if (ret)
            {
                set_error( ret );
                goto exit_error;
            }
            return sem;

exit_error:
            release_object( obj );
            return NULL;
        }
        else
        {
            assert( hybrid_object_is_server_private( ho ) || sem->process_group );

            /* if userspace requested a private server-side object, but the existing object isn't
             * one */
            if (server_only && !hybrid_object_is_server_private( ho ))
            {
                fprintf(stderr, "wineserver: ERROR: object not server-private\n");
                release_object( obj );
                set_error( STATUS_INVALID_PARAMETER );
                return NULL;
            }

            /* migration potentially triggered with this call */
            if (!hybrid_server_object_get_info( sem, info ))
                hybrid_server_object_check( sem );

            assert( hybrid_object_is_server_private( ho ) || sem->process_group );
        }
    }
    return sem;
}

static int release_semaphore( struct hybrid_server_object *sem, unsigned int count, unsigned int *prev )
{
    unsigned int _prev;
    union hybrid_object_any *any = &sem->any;
    int do_wake = !hybrid_object_is_server_private( &any->ho );
    NTSTATUS ret;

    ret = hybrid_semaphore_release( &any->sem, count, &_prev, do_wake );
    set_error( ret );

    if (prev)
        *prev = _prev;

    if (!ret)
        wake_up( &sem->obj, count );

    return !ret;
}

__cold static void semaphore_dump( struct object *obj, int verbose )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    struct hybrid_semaphore *hs = &sem->any.sem;
    char buf[0x400];
    char *start = buf;

    assert( obj->ops == &semaphore_ops );
    hybrid_semaphore_dump( hs, &start, &buf[sizeof(buf)]);
    fprintf( stderr, "Semaphore %p any.sem = %s, refcount %u, process_group = %p ", obj, buf, obj->refcount, sem->process_group );
    dump_object_name( &sem->obj );
    fputc( '\n', stderr );
}

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

static void semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry)
{
}

static int semaphore_signal( struct object *obj, unsigned int access )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &semaphore_ops );

    if (!(access & SEMAPHORE_MODIFY_STATE))
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }
    return release_semaphore( sem, 1, NULL );
}

static NTSTATUS semaphore_trywait_begin_trans( struct object *obj, struct wait_queue_entry *wait )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &semaphore_ops );
    return hybrid_semaphore_trywait_begin_trans( &sem->any.sem, &sem->trans_state );
}

static NTSTATUS semaphore_trywait_commit( struct object *obj, int clear_notify )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &semaphore_ops );
    return hybrid_semaphore_trywait_commit( &sem->any.sem, &sem->trans_state, clear_notify );

}

static NTSTATUS semaphore_trywait_rollback( struct object *obj )
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &semaphore_ops );
    return hybrid_semaphore_trywait_rollback( &sem->any.sem, &sem->trans_state );
}

static void semaphore_destroy(struct object *obj)
{
    struct hybrid_server_object *sem = (struct hybrid_server_object *)obj;
    assert( obj->ops == &semaphore_ops );

    hybrid_server_object_destroy( sem );
}

/* create a semaphore */
DECL_HANDLER(create_semaphore)
{
    struct hybrid_server_object *sem;
    struct unicode_str name;
    struct directory *root = NULL;
    const struct object_attributes *objattr = get_req_data();
    const struct security_descriptor *sd;
    struct shm_object_info info = shm_object_info_init( &info );
    const int server_only = req->access & SYNC_OBJECT_ACCESS_SERVER_ONLY;
    unsigned int access   = req->access & SYNC_OBJECT_ACCESS_MASK;

    reply->handle = 0;

    if (!objattr_is_valid( objattr, get_req_data_size() ))
        return;

    sd = objattr->sd_len ? (const struct security_descriptor *)(objattr + 1) : NULL;
    objattr_get_name( objattr, &name );

    if (objattr->rootdir && !(root = get_directory_obj( current->process, objattr->rootdir, 0 )))
        return;

    if ((sem = create_semaphore( root, &name, req->attributes, req->initial, req->max, sd, &info, server_only )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current->process, sem, access, req->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current->process, sem, access, req->attributes );

        reply->flags  = info.flags;
        reply->shm_id = info.shm_id;
        reply->offset = info.offset;
if (0)
{
    char buf[0x400];
    char *start = buf;
    shm_object_info_dump( &info, &start, &buf[0x400] );
    fprintf( stderr, "%s: %s\n", __func__, buf );
    process_groups_dump( current->process, PROCESS_GROUP_DUMP_ALL, 0x2000 );
}


        hybrid_server_object_check( sem );
        release_object( sem );
    }

    if (root) release_object( root );
}

/* open a handle to a semaphore */
DECL_HANDLER(open_semaphore)
{
    struct unicode_str name;
    struct directory *root = NULL;
    struct hybrid_server_object *sem;
    struct shm_object_info info = shm_object_info_init( &info );
    const int server_only = req->access & SYNC_OBJECT_ACCESS_SERVER_ONLY;
    unsigned int access   = req->access & SYNC_OBJECT_ACCESS_MASK;

    get_req_unicode_str( &name );
    if (req->rootdir && !(root = get_directory_obj( current->process, req->rootdir, 0 )))
        return;

    if ((sem = open_object_dir( root, &name, req->attributes, &semaphore_ops )))
    {
        reply->handle = alloc_handle( current->process, &sem->obj, access, req->attributes );

        if (server_only && !hybrid_object_is_server_private( &sem->any.ho ))
        {
            fprintf(stderr, "wineserver: ERROR: object not server-private\n");
            release_object( sem );
            set_error( STATUS_INVALID_PARAMETER );
        }
        else
        {
            /* migration potentially triggered with this call */
            if (!hybrid_server_object_get_info( sem, &info ))
                hybrid_server_object_check( sem );

            reply->flags  = info.flags;
            reply->shm_id = info.shm_id;
            reply->offset = info.offset;
            reply->max    = sem->any.sem.max;
        }

        release_object( sem );
    }

    if (root) release_object( root );
}

/* release a semaphore */
DECL_HANDLER(release_semaphore)
{
    struct hybrid_server_object *sem;

    if ((sem = (struct hybrid_server_object *)get_handle_obj( current->process, req->handle,
                                                              SEMAPHORE_MODIFY_STATE, &semaphore_ops )))
    {
        release_semaphore( sem, req->count, &reply->prev_count );
        hybrid_server_object_check( sem );
        release_object( sem );
    }
}

/* query details about the semaphore */
DECL_HANDLER(query_semaphore)
{
    struct hybrid_server_object *sem;

    if ((sem = (struct hybrid_server_object *)get_handle_obj( current->process, req->handle,
                                                              SEMAPHORE_QUERY_STATE, &semaphore_ops )))
    {
        reply->current = sem->any.ho.value->data;
        reply->max = sem->any.sem.max;
        hybrid_server_object_check( sem );
        release_object( sem );
    }
}
