/*
 * Management of shared memory objects shared amongst groups of processes
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

#ifndef _WINE_SERVER_PROCESS_GROUP_H
#define _WINE_SERVER_PROCESS_GROUP_H

#include "shm_slab.h"
#include "object.h"

struct process;
struct hybrid_server_object;

/* process-group structs & functions */

struct process_group
{
    struct shm_cache    *cache;         /* the shared object cache in use for this process group */
    struct list          entry;         /* entry in list of all process_groups */
    struct list          objects;       /* list of all objects in group */
    unsigned             global:1;      /* process group for global handles? */
    unsigned             size:31;       /* size of processes array */
    struct process      *processes[1];  /* pointer to processes */
};

/* proces group for global handles */
extern struct process_group global_process_group;

enum pg_event {
    PG_EVENT_OBJ_CLOSE,         /* a handle to an object is closed by a single process */
    PG_EVENT_OBJ_RELEASE,       /* call to get_shared_memory implicitly releases previously aquired resources */
    PG_EVENT_OBJ_DESTROY,       /* the object is being destroyed (refcount reached zero) */
    PG_EVENT_TERM,              /* a process terminates */
    PG_EVENT_DESTROY,           /* the process group is being destroyed */
    PG_EVENT_ACCESS,            /* a process accesses an object (possibly for the 1st time) */

    PG_EVENT_COUNT
};
static const char *const rel_reasons[PG_EVENT_COUNT] = {
    "PG_EVENT_OBJ_CLOSE",
    "PG_EVENT_OBJ_RELEASE",
    "PG_EVENT_DESTROY",
    "PG_EVENT_TERM",
    "PG_EVENT_DESTROY",
    "PG_EVENT_ACCESS"
};

extern int process_group_manage_object( struct hybrid_server_object *hso, struct process *process,
                                        obj_handle_t handle, int remove, enum pg_event event );
extern int process_group_close_handle( struct object *obj, struct process *process, obj_handle_t handle );
extern int process_group_obj_remove( struct hybrid_server_object *hso, struct process *process,
                                     obj_handle_t handle, enum pg_event event );
extern int process_group_obj_add( struct process_group *pg, struct hybrid_server_object *hso,
                                  obj_handle_t handle, struct shm_object_info *info );
extern void process_group_get_info( struct hybrid_server_object *hso, struct shm_object_info *info );
//extern int process_group_close( struct hybrid_server_object *hso, struct process *process );
extern void process_group_term( struct process *process );
extern int process_group_get_new_release_old( struct hybrid_server_object *hso, struct process *process,
                                              obj_handle_t handle, struct shm_object_info *info );

#ifdef DEBUG_OBJECTS
enum process_group_dump_flags {
    PROCESS_GROUP_DUMP_GROUPS      = 0x01,
    PROCESS_GROUP_DUMP_OBJECTS     = 0x02,
    PROCESS_GROUP_DUMP_ORPHANS     = 0x04,
    PROCESS_GROUP_DUMP_SLABS       = 0x08,
    PROCESS_GROUP_DUMP_SLAB_MAPS   = 0x10,
    PROCESS_GROUP_DUMP_SLAB_MEMORY = 0x20,
    PROCESS_GROUP_DUMP_GROUPS_ALL  = PROCESS_GROUP_DUMP_GROUPS
                                   | PROCESS_GROUP_DUMP_OBJECTS
                                   | PROCESS_GROUP_DUMP_ORPHANS,
    PROCESS_GROUP_DUMP_SLABS_ALL   = PROCESS_GROUP_DUMP_SLABS
                                   | PROCESS_GROUP_DUMP_SLAB_MAPS
                                   | PROCESS_GROUP_DUMP_SLAB_MEMORY,
    PROCESS_GROUP_DUMP_ALL         = PROCESS_GROUP_DUMP_GROUPS_ALL
                                   | PROCESS_GROUP_DUMP_SLABS_ALL
};
extern void process_groups_dump( struct process *process, enum process_group_dump_flags flags, size_t buf_size );
#endif

#endif /* _WINE_SERVER_PROCESS_GROUP_H */
