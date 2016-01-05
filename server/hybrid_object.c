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

/******************************************************************************
 *              hybrid_server_object_init
 *
 * hso          [I] the object
 * info         [O] the shared memory info
 * flags        [I] valid flags are HYBRID_SYNC_SERVER_PRIVATE.
 *
 * Initialize the hybrid_object members after base class already inited.
 *
 */
int hybrid_server_object_init( struct hybrid_server_object *hso, struct shm_object_info *info, int flags )
{
    assert( current );
    assert( current->process );

    /* FIXME: This only needs to be called once from hybrid_object.c per process, but I don't have an
     * init func in here for that right now */
    sync_impl_init( NULL, NULL, shmglobal ? &shmglobal->last_server_cpu : NULL);

    /* should only have these flags set */
    assert( !(flags & ~HYBRID_SYNC_INIT_MASK) );

    /* If we don't have shared memory or staging_sync isn't enabled then we'll use server private
     * objects (even when not requested) */
    if (!have_shm() || !staging_sync_enabled())
        flags |= HYBRID_SYNC_SERVER_PRIVATE;

    hso->process_group = NULL;
    info->flags        = hso->any.ho.flags_refcount = flags;

    if (flags & HYBRID_SYNC_SERVER_PRIVATE)
    {
        info->ptr = NULL;
        //info->hash_base = 0;
    }
    else
    {
        if (process_group_obj_add( NULL, hso, 0, info ))
            return -1;

        if (!info->ptr)
            return -1;

        info->hash_base = fnv1a_hash32( FNV1A_32_INIT, info->hash_base_in,
                                        sizeof(info->hash_base_in) );
    }

    hybrid_object_init( &hso->any.ho, info->ptr, info->flags, info->hash_base);

    return 0;
}

/* possibly triggers migration */
int hybrid_server_object_get_info( struct hybrid_server_object *hso, struct shm_object_info *info )
{
    assert (current);

    if ( hybrid_object_is_server_private( &hso->any.ho ) )
    {
        memset( info, 0, sizeof(*info) );
        info->flags = HYBRID_SYNC_SERVER_PRIVATE;
        return 0;
    }

    if (process_group_manage_object( hso, current->process, 0, FALSE, -1 ))
        return -1;

    process_group_get_info( hso, info );
    info->flags = hso->any.ho.flags_refcount & HYBRID_SYNC_SERVER_PRIVATE;
    return 0;
}

/* called by obj->ops->destroy when refcount is zero */
void hybrid_server_object_destroy( struct hybrid_server_object *hso )
{
    //process_group_release( current ? current->process : NULL, hso, PG_EVENT_OBJ_DESTROY);
    /* TODO: verify if no handles then process resources should be released */
}

void __hybrid_server_object_check_bad( void )
{
    set_error( STATUS_FILE_CORRUPT_ERROR );
}

int hybrid_server_object_migrate( struct hybrid_server_object *hso, struct shm_object_info *info )
{
    NTSTATUS result;

    assert( info->ptr );
    if ((result = hybrid_object_migrate( &hso->any.ho, info)))
    {
        fprintf(stderr, "wineserver: %s: ERROR: hybrid_object_migrate failed with %08x\n", __func__, result);
        set_error( result );
        return -1;
    }

    return 0;
}

NTSTATUS hybrid_server_object_clear_notify( struct hybrid_server_object *hso )
{
    return hybrid_object_clear_notify( &hso->any.ho );
}
