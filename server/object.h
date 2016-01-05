/*
 * Wine server objects
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

#ifndef __WINE_SERVER_OBJECT_H
#define __WINE_SERVER_OBJECT_H

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#include <sys/time.h>
#include "wine/server_protocol.h"
#include "wine/list.h"
#include "wine/sync.h"

#define DEBUG_OBJECTS

/* kernel objects */

struct namespace;
struct object;
struct object_name;
struct thread;
struct process;
struct token;
struct file;
struct wait_queue_entry;
struct async;
struct async_queue;
struct winstation;
struct directory;
struct object_type;
struct process_group;


struct unicode_str
{
    const WCHAR *str;
    data_size_t  len;
};

/* operations valid on all objects */
struct object_ops
{
    /* size of this object type */
    size_t size;
    /* dump the object (for debugging) */
    void (*dump)(struct object *,int);
    /* return the object type */
    struct object_type *(*get_type)(struct object *);
    /* add a thread to the object wait queue */
    int  (*add_queue)(struct object *,struct wait_queue_entry *);
    /* remove a thread from the object wait queue */
    void (*remove_queue)(struct object *,struct wait_queue_entry *);
    /* is object signaled? */
    int  (*signaled)(struct object *,struct wait_queue_entry *);
    /* wait satisfied */
    void (*satisfied)(struct object *,struct wait_queue_entry *);
    /* signal an object */
    int  (*signal)(struct object *, unsigned int);
    /* return an fd object that can be used to read/write from the object */
    struct fd *(*get_fd)(struct object *);
    /* map access rights to the specific rights for this object */
    unsigned int (*map_access)(struct object *, unsigned int);
    /* returns the security descriptor of the object */
    struct security_descriptor *(*get_sd)( struct object * );
    /* sets the security descriptor of the object */
    int (*set_sd)( struct object *, const struct security_descriptor *, unsigned int );
    /* lookup a name if an object has a namespace */
    struct object *(*lookup_name)(struct object *, struct unicode_str *,unsigned int);
    /* open a file object to access this object */
    struct object *(*open_file)(struct object *, unsigned int access, unsigned int sharing,
                                unsigned int options);
    /* close a handle to this object */
    int (*close_handle)(struct object *,struct process *,obj_handle_t);
    /* destroy on refcount == 0 */
    void (*destroy)(struct object *);
/*    NTSTATUS (*trywait)(struct object *,struct wait_queue_entry *); */
    /* If object is signaled, starts a wait-multi transaction. This sets the "locked" bit
     * prohibiting other operations on the object until either commited or rolled back.
     * if the object is not signaled, then its SHM_SYNC_VALUE_NOTIFY_SVR flag is set
     * (atomically) assuring that the next client that signals the object will notify
     * the server so that the wait can complete */
    NTSTATUS (*trywait_begin_trans)(struct object *,struct wait_queue_entry *);
    /* commits a prior call to trywait_begin_trans() (clears "locked" bit). Also clears
     * SHM_SYNC_VALUE_NOTIFY_SVR if there are no other waiters */
    NTSTATUS (*trywait_commit)(struct object *, int clear_notify);
    /* rolls back a prior call to trywait_begin_trans() (clears "locked" bit and resets value) */
    NTSTATUS (*trywait_rollback)(struct object *);
};

struct object
{
    unsigned int              refcount;    /* reference count */
    unsigned int              handle_count;/* handle count */
    const struct object_ops  *ops;
    struct list               wait_queue;
    struct object_name       *name;
    struct security_descriptor *sd;
#ifdef DEBUG_OBJECTS
    struct list               obj_list;
#endif
};

struct wait_queue_entry
{
    struct list         entry;
    struct object      *obj;
    struct thread_wait *wait;
};

extern void *mem_alloc( size_t size );  /* malloc wrapper */
extern void *memdup( const void *data, size_t len );
extern void *alloc_object( const struct object_ops *ops );
extern const WCHAR *get_object_name( struct object *obj, data_size_t *len );
extern WCHAR *get_object_full_name( struct object *obj, data_size_t *ret_len );
extern void dump_object_name( struct object *obj );
extern void *create_object( struct namespace *namespace, const struct object_ops *ops,
                            const struct unicode_str *name, struct object *parent );
extern void *create_named_object( struct namespace *namespace, const struct object_ops *ops,
                                  const struct unicode_str *name, unsigned int attributes );
extern void unlink_named_object( struct object *obj );
extern void make_object_static( struct object *obj );
extern struct namespace *create_namespace( unsigned int hash_size );
/* grab/release_object can take any pointer, but you better make sure */
/* that the thing pointed to starts with a struct object... */
extern struct object *grab_object( void *obj );
extern void release_object( void *obj );
extern struct object *find_object( const struct namespace *namespace, const struct unicode_str *name,
                                   unsigned int attributes );
extern struct object *find_object_index( const struct namespace *namespace, unsigned int index );
extern struct object_type *no_get_type( struct object *obj );
extern int no_add_queue( struct object *obj, struct wait_queue_entry *entry );
extern void no_satisfied( struct object *obj, struct wait_queue_entry *entry );
extern int no_signal( struct object *obj, unsigned int access );
extern struct fd *no_get_fd( struct object *obj );
extern unsigned int no_map_access( struct object *obj, unsigned int access );
extern struct security_descriptor *default_get_sd( struct object *obj );
extern int default_set_sd( struct object *obj, const struct security_descriptor *sd, unsigned int set_info );
extern int set_sd_defaults_from_token( struct object *obj, const struct security_descriptor *sd,
                                       unsigned int set_info, struct token *token );
extern struct object *no_lookup_name( struct object *obj, struct unicode_str *name, unsigned int attributes );
extern struct object *no_open_file( struct object *obj, unsigned int access, unsigned int sharing,
                                    unsigned int options );
extern int no_close_handle( struct object *obj, struct process *process, obj_handle_t handle );
extern void no_destroy( struct object *obj );
#ifdef DEBUG_OBJECTS
extern void dump_objects(void);
extern void close_objects(void);
#endif

/* event functions */

struct event;
struct keyed_event;

extern struct event *create_event( struct directory *root, const struct unicode_str *name,
                                   unsigned int attr, int manual_reset, int initial_state,
                                   const struct security_descriptor *sd );
extern struct keyed_event *create_keyed_event( struct directory *root, const struct unicode_str *name,
                                               unsigned int attr, const struct security_descriptor *sd );
extern struct event *get_event_obj( struct process *process, obj_handle_t handle, unsigned int access );
extern struct keyed_event *get_keyed_event_obj( struct process *process, obj_handle_t handle, unsigned int access );
extern void pulse_event( struct event *event );
extern void set_event( struct event *event );
extern void reset_event( struct event *event );

/* mutex functions */

extern void abandon_mutexes( struct thread *thread );

/* serial functions */

int get_serial_async_timeout(struct object *obj, int type, int count);

/* socket functions */

extern void sock_init(void);

/* debugger functions */

extern int set_process_debugger( struct process *process, struct thread *debugger );
extern void generate_debug_event( struct thread *thread, int code, const void *arg );
extern void generate_startup_debug_events( struct process *process, client_ptr_t entry );
extern void debug_exit_thread( struct thread *thread );

/* registry functions */

extern unsigned int get_prefix_cpu_mask(void);
extern void init_registry(void);
extern void flush_registry(void);

/* signal functions */

extern void start_watchdog(void);
extern void stop_watchdog(void);
extern int watchdog_triggered(void);
extern void init_signals(void);

/* atom functions */

extern atom_t add_global_atom( struct winstation *winstation, const struct unicode_str *str );
extern atom_t find_global_atom( struct winstation *winstation, const struct unicode_str *str );
extern int grab_global_atom( struct winstation *winstation, atom_t atom );
extern void release_global_atom( struct winstation *winstation, atom_t atom );

/* directory functions */

extern struct directory *get_directory_obj( struct process *process, obj_handle_t handle, unsigned int access );
extern struct object *find_object_dir( struct directory *root, const struct unicode_str *name,
                                       unsigned int attr, struct unicode_str *name_left );
extern void *create_named_object_dir( struct directory *root, const struct unicode_str *name,
                                      unsigned int attr, const struct object_ops *ops );
extern void *open_object_dir( struct directory *root, const struct unicode_str *name,
                              unsigned int attr, const struct object_ops *ops );
extern struct object_type *get_object_type( const struct unicode_str *name );
extern void init_directories(void);

/* symbolic link functions */

extern struct symlink *create_symlink( struct directory *root, const struct unicode_str *name,
                                       unsigned int attr, const struct unicode_str *target );

extern int staging_sync;
static inline int staging_sync_enabled( void )
{
    return staging_sync;
}

/* hybrid objects structs & functions */

/******************************************************************************
 *              struct hybrid_server_object
 *
 * A specialization of struct object containing a server-side private portion
 * and a portion that may exist in either private or shared memory.
 *
 * Hybrid objects are only useable in the context of a thread.
 *
 */
struct hybrid_server_object
{
    struct object           obj;            /* base class object */
    union hybrid_object_any any;
    union shm_sync_value    trans_state;    /* stores value when transaction starts to verify that it is unchanged */
    struct process_group   *process_group;  /* process group this object belongs to */
    struct list             entry;          /* entry in process group */
};

extern int hybrid_server_object_init( struct hybrid_server_object *hso, struct shm_object_info *info, int flags );
extern void hybrid_server_object_destroy( struct hybrid_server_object *hso );
extern int hybrid_server_object_get_info( struct hybrid_server_object *hso, struct shm_object_info *info );
extern int hybrid_server_object_migrate( struct hybrid_server_object *hso, struct shm_object_info *info );
extern NTSTATUS hybrid_server_object_clear_notify( struct hybrid_server_object *hso );
extern void __hybrid_server_object_check_bad( void );

static inline int type_is_hybrid_object( struct object *obj )
{
    /* This is the current test, but this probably needs something cleaner */
    return !!obj->ops->trywait_begin_trans;
}

/* Returns true if the object is a hybrid_object and uses shared memory. */
static inline int object_is_shared( struct object *obj )
{
    struct hybrid_server_object *hso = (void*)obj;
    return type_is_hybrid_object( obj ) && !hybrid_object_is_server_private( &hso->any.ho );
}

static inline int hybrid_server_object_is_bad( struct hybrid_server_object *hso )
{
    return hybrid_object_bad( &hso->any.ho );
}

static inline void hybrid_server_object_check( struct hybrid_server_object *hso )
{
    if (hybrid_server_object_is_bad( hso ))
        __hybrid_server_object_check_bad();
}

/* global variables */

  /* command-line options */
extern int debug_level;
extern int foreground;
extern timeout_t master_socket_timeout;
extern const char *server_argv0;

  /* server start time used for GetTickCount() */
extern timeout_t server_start_time;

#define KEYEDEVENT_WAIT       0x0001
#define KEYEDEVENT_WAKE       0x0002
#define KEYEDEVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x0003)

#endif  /* __WINE_SERVER_OBJECT_H */
