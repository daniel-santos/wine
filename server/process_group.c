/*
 * Management of shared memory objects amongst groups of processes
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
#include <stdio.h>
#include <stdlib.h>

#include "shm_slab.h"
#include "process_group.h"

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "process.h"
#include "process_group.h"
#include "thread.h"
#include "handle.h"
#include "file.h"
#ifdef DEBUG_OBJECTS
# include "wine/pretty_dump.h"
#endif


/* All living process groups.  */
static struct list all_process_groups = LIST_INIT(all_process_groups);

/* Where process groups go when they die but still have orphans.  */
static struct list limbo = LIST_INIT(limbo);

/* Where objects go until all clients free their shared memory.  */
static struct list orphanage = LIST_INIT(orphanage);

static void process_group_dec_refcount( struct process_group *pg );
static int create_orphan_or_free( struct hybrid_server_object *hso, void *ptr,
                                  struct process_group *pg, struct process *process,
                                  obj_handle_t handle, enum pg_event event );
static int release_orphans( struct hybrid_server_object *hso, struct process* process,
                            struct process_group *pg, obj_handle_t handle, enum pg_event event );

/* process group for objects made global */
/* TODO: not yet managed */
struct process_group global_process_group =
{
    NULL,                                       /* cache */
    {NULL, NULL},                               /* entry */
    LIST_INIT( global_process_group.objects ),  /* objects */
    TRUE,                                       /* global */
    TRUE,                                       /* alive */
    0,                                          /* size */
    0,                                          /* refcount */
    {NULL}                                      /* processes */
};

/* Returns the index of the process within the process group or -1 if it is not in the group */
static int get_process_index(const struct process_group *pg, const struct process *process)
{
    size_t i;

    for (i = 0; i < pg->size; ++i)
    {
        if (pg->processes[i] == process)
            return i;
    }

    return -1;
}

static inline int process_in_group(const struct process_group *pg, const struct process *process)
{
    return get_process_index(pg, process) != -1;
}

static struct shm_cache *alloc_cache( size_t initial_size )
{
    return shm_cache_alloc(sizeof(union shm_sync_value), initial_size,
                           SHM_CACHE_POISON | SHM_CACHE_PAD | SHM_CACHE_VERIFY_MEM);
}


/*****************************************************************************
 *              process_group member functions
 */

/* create a composite process group for multiple processes sharing objects */
static struct process_group *process_group_create( struct process *processes[], size_t size,
                                                   size_t initial_size )
{
    struct process_group *pg;
    const size_t obj_size = sizeof(struct process_group) + sizeof(processes[0]) * (size - 1);

    pg = mem_alloc(obj_size);
    if (!pg)
        return NULL;

    pg->cache = alloc_cache( initial_size );
    if (!pg->cache)
    {
        free (pg);
        return NULL;
    }

    pg->global   = 0;
    pg->alive    = 1;
    pg->size     = size;
    pg->refcount = 0;

    list_add_tail(&all_process_groups, &pg->entry);
    list_init( &pg->objects );
    memcpy( pg->processes, processes, sizeof(pg->processes[0]) * size );
//fprintf(stderr, "%s: %p\n", __func__, pg);
//process_groups_dump( pg->processes[0], PROCESS_GROUP_DUMP_GROUPS | PROCESS_GROUP_DUMP_OBJECTS | PROCESS_GROUP_DUMP_ORPHANS | PROCESS_GROUP_DUMP_SLABS | PROCESS_GROUP_DUMP_SLAB_MAPS | PROCESS_GROUP_DUMP_SLAB_MEMORY );

    return pg;
}

/* This could be optimized using a hashtable & hashing the process IDs, but it probably doesn't matter. */
static struct process_group *process_group_find(struct process *processes[], size_t count)
{
    struct process_group *pg;

    LIST_FOR_EACH_ENTRY(pg, &all_process_groups, struct process_group, entry)
    {
        size_t i;

        if (pg->size != count)
            continue;

        for (i = 0; i < count; ++i)
            if (!process_in_group(pg, processes[i]))
                goto continue_outer;

        return pg;

continue_outer:
        continue;
    }
    return NULL;
}

/* Find or create an appropriate process group.  */
static struct process_group *process_group_find_or_create( struct process_group *prototype,
                                                           struct process *process, int remove )
{
    struct process_group *pg;
    struct process **processes;
    struct process *exclude = remove ? process : NULL;
    ssize_t size;
    size_t j = 0;

    size = (prototype ? prototype->size : 0) + (remove ? -1 : 1);
    assert( prototype || remove == 0 );

    if ( size < 1 )
        return NULL;

    processes = mem_alloc( sizeof(processes[0]) * size );
    if (!processes)
        return NULL;

    /* Copy process pointer array.  */
    if (prototype)
    {
        size_t i;
        for (i = 0; i < prototype->size; ++i)
            if (prototype->processes[i] != exclude)
                processes[j++] = prototype->processes[i];
    }

    if (!remove)
        processes[j++] = process;

    assert( j == size );

    pg = process_group_find( processes, size );

    /* if none found, then create a new one */
    if (!pg)
    {
        /* create new group with at least as much space as what the prototype is using */
        size_t init_size = prototype ? shm_cache_get_space_used( prototype->cache ) : 1;

        /* round up to page boundary */
        init_size = (init_size + get_page_size() - 1) & ~(get_page_size() - 1);
        pg = process_group_create( processes, size, init_size );
    }
    if (!pg)
        fprintf( stderr, "wineserver: ERROR %s: process_group_create failed with %08x\n", __func__, get_error() );

    return pg;
}


/******************************************************************************
 *              process_group_manage_object
 *
 * Manage an object's process group, potentially triggering a migration.
 *
 * PARAMS
 *   hso        [I]     The object to manage
 *   process    [I]     The process in question
 *   handle     [I]     Only needed when remove is TRUE (closing a handle)
 *   remove     [I]     non-zero if the process is loosing reference to the object
 *   event      [I]     The event for this call
 *
 * If hso has no process group, then remove is invalid and the object will be added to a group with
 * only that process. If remove is false and the object is in a group that already includes process,
 * then nothing is done. Otherwise, a migration will occur.
 *
 * If remove is true and the process group contains only the specified process, then the object
 * is removed from that group and left without a group (this presumes that deletion is in progress).
 * Otherwise, an appropriate process group is located (if it exists) or created and the object is
 * migrated to that group.
 */
int process_group_manage_object( struct hybrid_server_object *hso, struct process *process,
                                 obj_handle_t handle, int remove, enum pg_event event )
{
    struct process_group *from = hso->process_group;
    struct process_group *to;
    struct shm_object_info info;
    union shm_sync_value *old_shm;
    int in_new_group;
    int ret;

    assert( hso );
    assert( process );

    shm_sync_trace("%s: process = %p, hso = %p, value = %p\n", __func__, process, hso, hso->any.ho.atomic.value);

    if (from)
    {
        int in_current_group = process_in_group( from, process );

        if (likely( !remove && in_current_group))
            return 0; /* from already includes this process (fast path) */

        assert( !remove || in_current_group );
    }
    else /* from == NULL */
        assert( !remove );

    if (!(to = process_group_find_or_create( from, process, remove )))
    {
        if (get_error()) /* failure */
            return -1;
        else /* object about to be destroyed (as no other place to go ) */
        {
            assert( hso->obj.handle_count == 1 );
            assert( remove );
            return process_group_obj_remove( hso, process, handle, event, NULL );
        }
    }

    in_new_group = process_in_group( to, process );
    /* verify that we did this correctly */
    assert( remove ? !in_new_group : in_new_group );

    /* get new shared memory for object to migrate to */
    info = shm_object_info_init( );
    if ( !shm_cache_obj_alloc( to->cache, &info ) )
        return -1;

    old_shm = hso->any.ho.atomic.value;
    if (hybrid_server_object_migrate( hso, &info ))
    {
        shm_cache_obj_free( to->cache, &info.ptr );
        return -1;
    }

    ret = process_group_obj_remove( hso, process, handle, event, old_shm );
    process_group_obj_add( to, hso, handle, &info, FALSE );
    assert (hso->any.ho.atomic.value);
    process_group_check_sanity( hso );
    return ret;
}

/******************************************************************************
 *              process_group_close_handle
 *
 * obj->ops->close() handler for all hybrid objects
 *
 * Returns 1 if OK to close, zero otherwise.
 */
int process_group_close_handle( struct object *obj, struct process *process, obj_handle_t handle )
{
    struct hybrid_server_object *hso = (void*)obj;

    assert( type_is_shared_object( obj ) );
    assert( hso->process_group );
    if ( hso->process_group->global )
    {
        fprintf(stderr, "wineserver: ERROR %s: hybrid object made global not yet supported (and/or tested)\n",
                __func__);
        assert(0);
        return 1;
    }

    /* dec refcount for (and possibly release) any orphans */
    release_orphans( hso, process, NULL, handle, PG_EVENT_OBJ_CLOSE );

    if (!count_handles( obj, process, handle ))
        return !process_group_manage_object( hso, process, handle, TRUE, PG_EVENT_OBJ_CLOSE );

    return 1;  /* ok to close */
}

//static int release_orphans( struct hybrid_server_object *hso, struct process* process, enum pg_event event );

static void process_group_destroy( struct process_group *pg )
{
    size_t size = sizeof(*pg) + sizeof(pg->processes[0]) * (pg->size - 1);
//fprintf(stderr, "%s: %p\n", __func__, pg);
//process_groups_dump( pg->processes[0], PROCESS_GROUP_DUMP_ALL );
    assert( list_empty( &pg->objects ) );
    release_orphans( NULL, NULL, pg, 0, PG_EVENT_DESTROY );
    shm_cache_free( pg->cache );
    list_remove( &pg->entry );
    memset( pg, 0xaa, size );
    free( pg );
}

static int object_in_group( struct hybrid_server_object *hso )
{
    struct list *i;
    LIST_FOR_EACH(i, &hso->process_group->objects)
        if (i == &hso->entry)
            return 1;
    return 0;
}

/*
 *
 * If this object was already moved then old_shm should point to the shared memory previously used.
 */
int process_group_obj_remove( struct hybrid_server_object *hso, struct process *process,
                              obj_handle_t handle, enum pg_event event, void *old_shm )
{
    void *ptr                   = old_shm ? old_shm : hso->any.ho.atomic.value;
    struct process_group *pg    = hso->process_group;
    int ret = 0;

    shm_sync_trace("%s: process = %p, hso = %p, value = %p\n", __func__, process, hso, hso->any.ho.atomic.value);
//fprintf(stderr, "%s\n", __func__);
    assert( pg );
    assert( shm_cache_have_ptr( pg->cache, ptr ) );
    assert( object_in_group( hso ) );

    list_remove( &hso->entry );
    hso->entry.prev    = NULL;
    hso->entry.next    = NULL;
    hso->any.ho.atomic.value  = NULL;
    assert( pg->refcount );

#if 0
    /* destroy process group when last object is removed */
    if (list_empty( &pg->objects ))
    {
        /* no orphan needed */
        shm_cache_obj_free( pg->cache, &ptr );
        process_group_destroy( pg );
    }
    else
#endif
    if (event == PG_EVENT_OBJ_DESTROY)
    {
        shm_cache_obj_free( pg->cache, &ptr );
        process_group_dec_refcount( pg );
    }
    else
        ret = create_orphan_or_free( hso, ptr, pg, process, handle, event );

    hso->process_group = NULL;

    return ret;
}

void process_group_get_info( struct hybrid_server_object *hso, struct shm_object_info *info )
{
    int result;

//fprintf(stderr, "%s\n", __func__);
    assert( hso );
    assert( hso->process_group );
    assert( info );
    result = shm_cache_get_info( hso->process_group->cache, hso->any.ho.atomic.value, info );
    assert( result != -1 ); /* the only failure here can be due to a bug in wineserver */
}

static void process_group_dec_refcount( struct process_group *pg )
{
    /* WORKAROUND: This is a work-around for the current 1.9.0 staging not destroying process
     * objects.  In future, we prefer to not destroy the object if it is still "alive", but rather
     * stick a timer on it and collect it if it isn't used after a while.  */
    if (--pg->refcount/* || pg->alive*/)
        return;

    assert( list_has( &limbo, &pg->entry ) || list_has( &all_process_groups, &pg->entry ) );
    process_group_destroy( pg );
}

/******************************************************************************
 *              process_group_term
 *
 * Mange termination of a process within a group.
 *
 * Iterate through all process groups to find the ones we belong to and notify them that we've
 * terminated.
 */
void process_group_term( struct process *process )
{
    struct process_group *pg;
    struct process_group *pg_next;
    struct hybrid_server_object *hso;

    shm_sync_trace("%s: process = %p\n", __func__, process);

    /* find all groups that process is a member of */
    LIST_FOR_EACH_ENTRY_SAFE(pg, pg_next, &all_process_groups, struct process_group, entry)
    {
        int process_index = get_process_index( pg, process );
        if (process_index == -1)
            continue;

        /* otherwise, we will migrate them to a process group minus the current process */
        while (!list_empty( &pg->objects ))
        {
            hso = LIST_ENTRY( list_head( &pg->objects ), struct hybrid_server_object, entry );
            process_group_manage_object( hso, process, 0, TRUE, PG_EVENT_TERM );
        }

        assert( list_empty( &pg->objects ) );
        if (pg->size == 1)
        {
            assert( pg->processes[0] == process );
            assert( pg->refcount == 0 );
            process_group_destroy( pg );
        } else {
            /* Kill the process group and move it to limbo.  */
            pg->alive = 0;
            pg->processes[process_index] = NULL;
            list_remove( &pg->entry );
            list_add_tail( &limbo, &pg->entry );
        }
    }

    LIST_FOR_EACH_ENTRY_SAFE(pg, pg_next, &limbo, struct process_group, entry)
    {
        int process_index = get_process_index( pg, process );
        if (process_index >= 0)
            pg->processes[process_index] = NULL;
    }
}


/******************************************************************************
 *              process_group_get_new_release_old
 *
 * Retrieve current shm info for an object and release old resources
 *
 * PARAMS
 *  hso         [I]     The object
 *  info        [O]     Pointer an object to receive the data or NULL if closing object
 *
 * Retrieves the shared memory storage information for a hybrid_server_object
 * and release any orphaned shared memory resources that were previously
 * allocated for this object on behalf of the calling process.
 *
 * RETURNS
 *  Success: zero
 *  Failure: non-zero
 */

int process_group_get_new_release_old( struct hybrid_server_object *hso, struct process *process,
                                       obj_handle_t handle, struct shm_object_info *info, int release_old )
{
    //struct shm_object_info existing = shm_object_info_init( );
    struct process_group *pg;

    assert( hso );
    assert( hso->process_group );
    assert( process );

    pg = hso->process_group;

    if (info)
    {
        int obj_index = shm_cache_get_info( pg->cache, hso->any.ho.atomic.value, info );
        assert( obj_index >= 0 );   /* can only fail due to bug in wineserver */
    }

if (pg->global)
{
    fprintf(stderr, "WARNING: global handles not yet properly supported\n");
    assert(0);
}

    /* now we release the process_group along with any orphaned shared memory
     * objects that this process previously had allocated for it. */
    release_orphans( hso, process, NULL, handle, PG_EVENT_OBJ_RELEASE );
if (0)
{
char buf[0x400];
char *start = buf;
const char *end = &buf[0x400];
shm_object_info_dump( info, &start, end);
fprintf(stderr, "%s: %s\n", __func__, buf);
}

    return 0;
}

/* add an object to a process group, allocate some shared memory and return that info */
int process_group_obj_add( struct process_group *pg, struct hybrid_server_object *hso,
                           obj_handle_t handle, struct shm_object_info *info, int allocate_shm )
{
    assert( !allocate_shm || !hso->process_group );
    shm_sync_trace("%s\n", __func__);

    if (!pg)
    {
        assert( current );
        pg = process_group_find_or_create( NULL, current->process, FALSE );
    }

    if (allocate_shm && !shm_cache_obj_alloc( pg->cache, info ))
        return -1;

    hso->any.ho.atomic.value = info->ptr;
    hso->any.ho.hash_base    = info->hash_base;
    assert (hso->any.ho.atomic.value);
    list_add_tail( &pg->objects, &hso->entry );
    hso->process_group = pg;
    ++pg->refcount;
    return 0;
}


/*
 *                              Orphan Management
 */

struct orphan
{
    struct list entry;                  /* entry in orphanage */
    struct hybrid_server_object *hso;   /* the object */
    struct process_group *pg;           /* the process group */
    void *ptr;
    unsigned refcount[1];               /* the refcount for each process (starts at one for each handle) */
};

/* create an orphan (if there are still references) or free the shared memory */
static int create_orphan_or_free( struct hybrid_server_object *hso, void *ptr,
                                  struct process_group *pg, struct process *process,
                                  obj_handle_t handle, enum pg_event event )
{
    unsigned int refcount = 0;
    struct orphan *orphan;
    size_t i;

    if (!hso->obj.handle_count)
        goto free_obj;

    orphan = mem_alloc(sizeof(*orphan) + sizeof(orphan->refcount[0]) * (pg->size - 1));
    if (!orphan)
    {
        fprintf(stderr, "wineserver: ERROR %s: failed to create orphan for object %p\n", __func__, hso);
        return -1;
    }

    orphan->hso = hso;
    orphan->pg  = pg;
    orphan->ptr = ptr;

    if ( event != PG_EVENT_OBJ_CLOSE && event != PG_EVENT_OBJ_RELEASE )
        handle = 0;

    for (i = 0; i < pg->size; ++i)
    {
        obj_handle_t process_handle = (process == pg->processes[i]) ? handle : 0;
        unsigned int count  = count_handles( &hso->obj, pg->processes[i], process_handle );
        orphan->refcount[i] = count;
        refcount           += count;
    }

    if (refcount)
        list_add_tail( &orphanage, &orphan->entry );
    else
    {
        free( orphan );
free_obj:
        shm_cache_obj_free( pg->cache, &ptr );
        process_group_dec_refcount( pg );
    }

    return 0;
}

static void orphan_destroy( struct orphan *orphan )
{
    size_t size = sizeof(*orphan) + sizeof(orphan->refcount[0]) * (orphan->pg->size - 1);
    struct process_group *pg = orphan->pg;
    int result;

    list_remove( &orphan->entry );
    /* shm object can be safely reused now */
    result = shm_cache_obj_free( pg->cache, &orphan->ptr );
    assert( !result );
    memset( orphan, 0xaa, size );
    free( orphan );
    process_group_dec_refcount( pg );
}

#if 0
static void orphan_remove_all( struct process_group *pg )
{
    struct orphan *orphan;
    struct orphan *next;

    LIST_FOR_EACH_ENTRY_SAFE(orphan, next, &orphanage, struct orphan, entry)
    {
        if (orphan->pg == pg)
        {
            list_remove( &orphan->entry );
            free( orphan );
        }
    }
}
#endif

static void release_orphan(struct orphan *orphan, int process_index, obj_handle_t handle, enum pg_event event )
{
    if (event != PG_EVENT_DESTROY)
    {
        unsigned i;
        unsigned *refcount = &orphan->refcount[process_index];
        assert( process_index >= 0 );

        switch (event)
        {
        case PG_EVENT_OBJ_CLOSE:
        case PG_EVENT_OBJ_RELEASE:
            /* it's possible to get here when refcount is already zero because the process did
             * release, but later called NtClose() on the object, but other processes haven't
             * released it yet. */
            if (*refcount)
                --*refcount;
            break;

        case PG_EVENT_OBJ_DESTROY:
            assert(0); /* unless we messed up, the orhpan should already be gone */
            break;

        case PG_EVENT_TERM:
            *refcount = 0;
            break;

        default:
            assert(0);
            return;
        }
        /* any references left? */
        for (i = 0; i < orphan->pg->size; ++i)
            if (orphan->refcount[i])
                return;
    }

    orphan_destroy( orphan );
}

static int release_orphans( struct hybrid_server_object *hso, struct process *process,
                            struct process_group *pg, obj_handle_t handle, enum pg_event event )
{
    struct orphan *orphan;
    struct orphan *next;
    unsigned int ret = 0;

    shm_sync_trace("%s: hso = %p, process = %p, event = %d\n", __func__, hso, process, event);

    LIST_FOR_EACH_ENTRY_SAFE(orphan, next, &orphanage, struct orphan, entry)
    {
        unsigned int process_index = get_process_index( orphan->pg, process );

        switch (event)
        {
            case PG_EVENT_OBJ_CLOSE:   /* a handle to an object for the process was closed */
            case PG_EVENT_OBJ_RELEASE: /* a call to get_shared_memory */
            case PG_EVENT_OBJ_DESTROY:
                if (hso != orphan->hso)
                    continue;
                /* intentional fall-through */

            /* process is terminating, fully release all orphans */
            case PG_EVENT_TERM:
                if (process_index == -1)
                    continue;
                break;

            case PG_EVENT_DESTROY:
                if (orphan->pg != pg)
                    continue;
                break;

            default:
                assert(0);
                continue;
        }
        release_orphan(orphan, process_index, handle, event);
    }

    return ret;
}

#ifdef DEBUG_OBJECTS

static void dump_orphan( struct dump *dump, struct orphan *orphan )
{
    unsigned i;

    dump_printf(dump, "%p {hso = %p, pg = %p, ptr = %p, refcount[%u] = {",
            orphan,
            orphan->hso,
            orphan->pg,
            orphan->ptr,
            orphan->pg->size);

    for (i = 0; i < orphan->pg->size; ++i)
        dump_printf(dump, "%s%u", i ? ", " : "", orphan->refcount[i]);

    dump_printf(dump, "}");
}

void process_group_dump( struct dump *dump, struct process_group *pg, enum process_group_dump_flags flags)
{
    unsigned i;

    dump_indent_inc(dump);
    dump_printf(dump,
            "struct process_group %p {\n"
            "%scache = ",
            pg, dump->indent);

    if (flags & PROCESS_GROUP_DUMP_SLABS)
        shm_cache_dump( dump, pg->cache,
                        flags & PROCESS_GROUP_DUMP_SLAB_MAPS,
                        flags & PROCESS_GROUP_DUMP_SLAB_MEMORY);
    else
        dump_printf(dump, "%p", pg->cache);

    dump_printf(dump,
            "\n"
            "%sentry        = {.prev = %p, .next = %p}\n"
            "%sglobal       = %u\n"
            "%ssize         = %u\n"
            "%sprocesses[%u] = {",
            dump->indent, pg->entry.prev, pg->entry.next,
            dump->indent, pg->global,
            dump->indent, pg->size,
            dump->indent, pg->size);

    for (i = 0; i < pg->size; ++i)
    {
        struct process *p = pg->processes[i];
        dump_printf(dump, "%s%p (%04x/%u)", i ? ", " : "", p, p->id, p->unix_pid);
    }

    if (flags & PROCESS_GROUP_DUMP_OBJECTS)
    {
        const struct hybrid_server_object *hso;
        int i = 0;

        dump_printf(dump, "}\n%sobjects      = {", dump->indent);
        LIST_FOR_EACH_ENTRY(hso, &pg->objects, const struct hybrid_server_object, entry)
        {
            dump_printf(dump, "%s%p (shm = %p)", i++ ? ", " : "", hso, hso->any.ho.atomic.value);
        }
    }
    else
        dump_printf(dump, "}\n%sobjects      = (count = %u)\n", dump->indent, list_count( &pg->objects ));

    dump_printf(dump, "%s}", dump_indent_dec(dump));
}

void process_groups_dump( struct process *process, enum process_group_dump_flags flags, size_t buf_size )
{
    const char *const indent = "                                        ";
    char *buf;
    struct dump dump;

    buf = malloc(buf_size);
    if (!buf)
    {
        fprintf(stderr, "failed to malloc %zu bytes\n", buf_size);
        return;
    }

    dump_init( &dump, buf, buf_size, indent, 2);
    if (flags & PROCESS_GROUP_DUMP_GROUPS)
    {
        struct process_group *pg;
        LIST_FOR_EACH_ENTRY(pg, &all_process_groups, struct process_group, entry)
            if (!process  || process_in_group( pg, process ))
            {
                process_group_dump( &dump, pg, flags );
                fprintf( stderr, "%s\n", buf );
                dump_reset( &dump );
            }
    }
    else if (flags & PROCESS_GROUP_DUMP_ORPHANS)
    {
        struct orphan *orphan;
        LIST_FOR_EACH_ENTRY(orphan, &orphanage, struct orphan, entry)
        {
            dump_orphan( &dump, orphan );
            fprintf( stderr, "%s\n", buf );
            dump_reset( &dump );
        }
    }
}

__attribute__((optimize(2)))
void process_group_check_sanity( struct hybrid_server_object *hso )
{
    struct process_group *pg = hso->process_group;
    struct list *i;

    assert( hso->obj.ops->trywait_begin_trans );
    assert( pg );

    /* Make sure process group is in "all groups" list.  */
    LIST_FOR_EACH(i, &all_process_groups)
        if (i == &pg->entry)
            break;
    assert( i != &all_process_groups );

    /* Verify that this object is in the process group's object list.  */
    LIST_FOR_EACH(i, &pg->objects)
        if (i == &hso->entry)
            break;
    assert( i != &pg->objects );

    /* Verify that the object's shared memory is from the correct cache.  */
    shm_cache_have_ptr( pg->cache, hso->any.ho.atomic.value );

}

size_t process_group_count_living( void )
{
    return list_count( &all_process_groups );
}

size_t process_group_count_limbo( void )
{
    return list_count( &limbo );
}

#endif /* DEBUG_OBJECTS */

