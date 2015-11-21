/*
 * Shared memory slab allocator
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

#ifndef __WINE_SERVER_SHM_SLAB_H
#define __WINE_SERVER_SHM_SLAB_H

#include <sys/types.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>

#include "wine/list.h"
#include "wine/sync.h"

#define SHM_SLAB_DEBUG
#ifdef SHM_SLAB_DEBUG
# include "pretty_dump.h"
#endif


/**********************************************************************
 *              Shared Memory Slab Allocator
 *
 * A struct shm_cache represents basic slab cache allocator built on top of memfd-based shared
 * memory and composed of one of more struct shm_slab objects where the objects are stored. It
 * differs from a typical slab allocator in these ways:
 *
 * o The slabs reside in shared memory.
 * o The struct shm_slab's data is not stored in the slab its self, so remains in private memory.
 * o Each struct shm_slab an associated file descriptor for the memory.
 * o Memory is managed in chunks of sizeof(slab_niblet_t) (4 or 8) instead of single bytes
 *
 * It curently supports some memory misuse protections enabled when built with the macro
 * SHM_SLAB_DEBUG defined:
 *
 * SHM_CACHE_POISON     Unallocated objects are initially memset 0xaa and when allocated are memset
 *                      again to 0x55. When freed, they are memset again to 0xaa.
 *
 * SHM_CACHE_PAD        Objects in the slab are padded with sizeof(long) bytes of memory that's
 *                      memset  to 0xfd.
 *
 * SHM_CACHE_VERIFY_MEM Verify that the unallocated and padding memory is not
 *                      modified at every access operation. This has fairly
 *                      significant overhead and is currently only impelemnted
 *                      as a failed assertion.
 */


#ifdef SHM_SLAB_DEBUG
# define SHM_CACHE_POISON     1      /* poison unallocated & uninitialized memory */
# define SHM_CACHE_PAD        2      /* pad all objects memory marked 0xfd */
# define SHM_CACHE_VERIFY_MEM 4      /* perform check during alloc/free operations and fail the
                                      * operation if padding is changed (significant overhead) */
#else /* use optimizer to compile out dead code */
# define SHM_CACHE_POISON     0
# define SHM_CACHE_PAD        0
# define SHM_CACHE_VERIFY_MEM 0
#endif

typedef unsigned long slab_map_t;
#define SHM_SLAB_MAP_BYTES    __SIZEOF_LONG__
#define SHM_SLAB_MAP_BITS     (SHM_SLAB_MAP_BYTES * 8)

typedef unsigned long slab_niblet_t;
#define SHM_SLAB_NIBLET_SIZE    __SIZEOF_LONG__
#define SHM_SLAB_ALIGN          SHM_SLAB_NIBLET_SIZE

/* TODO: move this struct to shm_slab.c? */
struct shm_slab
{
    struct list    entry;       /* list entry for struct shm_cache::slabs */
    int            next_free;   /* index to next free object or (if negative) a hint as to where the next free object may be */
    slab_niblet_t *ptr;         /* pointer to slab */
    int            fd;          /* fd to shared memory */
    unsigned       capacity;    /* total capcity of this slab */
    unsigned       count;       /* current slab population */
    __int64        id;          /* unique id number of slab */
    unsigned       slab_size;   /* size of the slab in bytes */
    unsigned       struct_size; /* the size of this shm_slab object */
    slab_map_t     map[1];      /* bitmap of free/used objects */
};

struct shm_cache
{
    unsigned            obj_size;       /* size of objects allocated */
    struct shm_slab    *next_free_slab; /* pointer to the next slab that objects will be allocated from or NULL */
    unsigned            capacity;       /* total number of objects this cache can store (before needing to grow) */
    unsigned            count;          /* current cache population */
    unsigned            flags;          /* flags (SHM_CACHE_POISON, SHM_CACHE_PAD) */
    struct list         slabs;          /* shared memory slabs */
};

extern struct shm_cache *shm_cache_alloc(size_t obj_size, size_t initial_size, int flags);
extern void shm_cache_free( struct shm_cache *cache );
extern void *shm_cache_obj_alloc( struct shm_cache *cache, struct shm_object_info *info );
extern int shm_cache_obj_free( struct shm_cache *cache, void **ptr );
extern int shm_cache_get_info( struct shm_cache *cache, void *ptr, struct shm_object_info *info );
extern size_t shm_cache_get_space_used( struct shm_cache *cache );

static inline int shm_cache_have_ptr( struct shm_cache *cache, void *ptr )
{
    return shm_cache_get_info( cache, ptr, NULL ) != -1;
}

#ifdef SHM_SLAB_DEBUG
extern const char *shm_cache_dump( struct dump *dump, struct shm_cache *cache, int dump_map, int dump_memory );
#else
static inline char *shm_cache_dump( void *dump, struct shm_cache *cache, int dump_map, int dump_memory )
{
    return NULL;
}
#endif

#endif /* __WINE_SERVER_SHM_SLAB_H */
