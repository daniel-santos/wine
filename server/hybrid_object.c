/*
 * Server-side hybrid object implementation
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

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"

#include "file.h"
#include "process.h"
#include "process_group.h"
#include "thread.h"
#include "handle.h"
#include "shm_slab.h"
#include "request.h"

#include "wine/sync.h"
#include "wine/sync_impl_server.h"

/* rather or not the env variable STAGING_SHM_SYNC is set to non-zero */
int staging_sync = 0;

#if DEBUG_SHM_SYNC
FILE *shm_sync_log;
struct tracer *shm_sync_tracer;

void shm_sync_debug_atexit(void)
{
    if (shm_sync_tracer)
    {
        tracer_dump(shm_sync_tracer);
        free(shm_sync_tracer);
    }

    if (shm_sync_log)
        fclose(shm_sync_log);
}

void init_shm_sync_debug(void)
{
    shm_sync_log = fopen("/tmp/process_group.log", "w+");
    if (!shm_sync_log)
    {
        perror("shm_sync_log = fopen()");
        exit(1);
    }

    shm_sync_tracer = tracer_alloc(128, 8, 0x20000, shm_sync_log);
    atexit(shm_sync_debug_atexit);
}
#endif /* DEBUG_SHM_SYNC */


/******************************************************************************
 *              hybrid_server_object_init
 *
 * hso          [I] the object
 * info         [O] the shared memory info
 *
 * Initialize the hybrid_object members after base class already inited.
 *
 */
int hybrid_server_object_init( struct hybrid_server_object *hso, struct shm_object_info *info,
                               struct process *process )
{
    /* HACK: This only needs to be called once from hybrid_object.c per process, but I don't know
     * where to put it right now */
    sync_impl_init( NULL, NULL, NULL, shmglobal ? &shmglobal->last_server_cpu : NULL);

    hso->process_group = NULL;
    info->flags        = 0;
    hso->any.ho.atomic.flags_refcounts = 0;

    if (process_group_obj_add( NULL, hso, 0, info, TRUE ))
    {
        /* TODO: Audit this code path and make sure that all possible failures set last error.  */
        assert( get_error() != STATUS_SUCCESS );
        return -1;
    }

    if (!info->ptr)
        return -1;

    hybrid_object_init( &hso->any.ho, info );

    return 0;
}

/* possibly triggers migration */
int hybrid_server_object_get_info( struct hybrid_server_object *hso, struct shm_object_info *info,
                                   struct process *process )
{
    if (process_group_manage_object( hso, process, 0, FALSE, -1 ))
        return -1;

    process_group_get_info( hso, info );

    /* HACK fixme */
    info->sem.max = hso->any.sem.max;
    return 0;
}

/* called by obj->ops->destroy when refcount is zero */
void hybrid_server_object_destroy( struct hybrid_server_object *hso )
{
//    assert ( !hso->process_group );
//    assert ( !hso->any.ho.atomic.value );
//    assert ( !(hso->entry.prev && hso->entry.next) );
    assert( global_error == STATUS_PROCESS_IS_TERMINATING || !hso->process_group);
    if ( global_error == STATUS_PROCESS_IS_TERMINATING && hso->process_group )
        process_group_obj_remove( hso, NULL, 0, PG_EVENT_OBJ_DESTROY, NULL );
}

void __hybrid_server_object_check_bad( void )
{
    set_error( STATUS_FILE_CORRUPT_ERROR );
}

int hybrid_server_object_migrate( struct hybrid_server_object *hso, struct shm_object_info *info )
{
    NTSTATUS result;

    assert( info->ptr );
    if ((result = hybrid_object_migrate( &hso->any.ho, info )))
    {
        fprintf(stderr, "wineserver: %s: ERROR: hybrid_object_migrate failed with %08x\n", __func__, result);
        set_error( result );
        return -1;
    }
assert( hso->any.ho.atomic.value );
    return 0;
}

NTSTATUS hybrid_server_object_clear_notify( struct hybrid_server_object *hso )
{
    return hybrid_object_clear_notify( &hso->any.ho );
}

obj_handle_t shared_object_open( struct process *process, obj_handle_t parent,
                                        unsigned int access,
                                        const struct object_ops *private_type,
                                        const struct object_ops *shared_type,
                                        const struct unicode_str *name, unsigned int attr,
                                        struct shm_object_info *info)
{
    struct object *obj;
    int private = access & SYNC_OBJECT_ACCESS_SERVER_ONLY;
    const struct object_ops *ops_array[2];
    obj_handle_t h;

    if (!have_shm() || !staging_sync_enabled())
        private = TRUE;

    ops_array[0] = private ? private_type : shared_type;
    ops_array[1] = private ? shared_type  : private_type;
    //obj = open_named_polytype_object( parent, ops_array, 2, name, attr );
    h = open_polytype_object( process, parent, access & SYNC_OBJECT_ACCESS_MASK, ops_array, 2,
                              name, attr, &obj);
    if (h)
    {
        info->private = obj->ops == private_type;
        if (!info->private)
        {
            struct hybrid_server_object *hso = (struct hybrid_server_object *)obj;
            assert( obj->ops == shared_type );

            if (private)
                fprintf( stderr, "WARNING: %s: requested server-private, but object is not\n",
                         __func__);

            /* migration potentially triggered with this call */
            if (!hybrid_server_object_get_info( hso, info, process ))
                hybrid_server_object_check( hso );
        }
        release_object( obj );
    }

    return h;
}
