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

#include "config.h"
#include "wine/port.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "ntstatus.h"
#include "shm_slab.h"
#include "thread.h"
#include "file.h"

/******************************************************************************
 *
 *                      Shared memory slab allocator
 *
 * struct shm_cache represents a cache of objects of a fixed size that are allocated from shared
 * memory slabs of type struct shm_slab. Normal principles of a slab allocation are followed except
 * that the struct shm_slab data is not stored within the slab its self, since the slab resides in
 * shared memory.
 *
 * Niblets
 * Internally, the library operates on data in "niblets", whos size is chosen at built time to be
 * the an optimal data size for the target machine to perform successive memory reads & writes to.
 * The purpose of this is only to optimize debugging features (object poisoning, padding & memory
 * verification) as a CPU typicaly reads & writes faster to aligned "words" of a particular size --
 * "niblets" in this library. All size & offset values are calculated in niblets internally (except
 * for shm_slab::struct_size, which is just the size of the object its self).
 *
 * In short, this allocator is hard-coded to manage objects of a fixed alignment and whos size will
 * always be rounded up to boundary of a niblet.
 *
 */

/* TODO: move to port.h, winnt.h or some such? */
/* Make a promise to the compiler that pointer is aligned without generating code to check it (can
 * produce bad code if used incorrectly). see https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
 */
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)
# define assume_aligned( ptr, align ) \
    ((typeof(ptr)) __builtin_assume_aligned( ptr, align ))
#else
# define assume_aligned( ptr, align ) (ptr)
#endif

#define ptr_is_aligned( ptr, align ) (!((long)(ptr) & (align - 1)))
#define assert_aligned( ptr, align ) assert( ptr_is_aligned( ptr, align ) )
#define assert_is_pow2( x ) assert( !((x) & ((x) - 1)) )

#if SHM_SLAB_NIBLET_SIZE == 8
# define SHM_SLAB_NIBLET_FORMAT  "%016lx"
# define SHM_CACHE_FREE          0xaaaaaaaaaaaaaaaaul
# define SHM_CACHE_UNINIT        0x5555555555555555ul
# define SHM_CACHE_NO_MANS_LAND  0xfdfdfdfdfdfdfdfdul
#elif SHM_SLAB_NIBLET_SIZE == 4
# define SHM_SLAB_NIBLET_FORMAT  "%08lx"
# define SHM_CACHE_FREE          0xaaaaaaaaul
# define SHM_CACHE_UNINIT        0x55555555ul
# define SHM_CACHE_NO_MANS_LAND  0xfdfdfdfdul
#else
# error long not 4 or 8 bytes
#endif

static __int64 next_slab_id = 1;

/* hard-code alignment (in niblets) */
static inline size_t get_align( void )
{
    return 1;
}

/* padding (if enabled) is always size of alignment */
static inline size_t get_padding( struct shm_cache *cache )
{
    return cache->flags & SHM_CACHE_PAD ? get_align() : 0;
}

static inline size_t get_store_size( struct shm_cache *cache )
{
    return cache->obj_size + get_padding( cache ) * 2;
}

static inline int shm_slab_is_full( struct shm_slab *slab )
{
    return slab->count == slab->capacity;
}

/* fast memset for blocks of slab_niblet_t memory */
static inline void nibset( slab_niblet_t *ptr, slab_niblet_t value, size_t n )
{
    ptr = assume_aligned( ptr, sizeof(*ptr) );
    while (n)
        ptr[--n] = value;
}

/*
 *              struct shm_cache Functions
 */

/* allocate a shm_slab object and summon shared memory */
static struct shm_slab *shm_slab_alloc( struct shm_cache *cache, size_t slab_size )
{
    /* All calculations (excluding struct_size) are in niblets */
    const size_t page_size      = get_page_size() / sizeof(slab_niblet_t);
    const size_t obj_store_size = get_store_size( cache );
    const size_t capacity       = slab_size / obj_store_size;
    const size_t map_size       = (capacity + SHM_SLAB_MAP_BITS - 1) / SHM_SLAB_MAP_BITS;
    const size_t struct_size    = sizeof(struct shm_slab) + (map_size - 1) * SHM_SLAB_MAP_BYTES;
    struct shm_slab *slab;
    int fd;
    slab_niblet_t *ptr;

    assert( !(slab_size % page_size) );

    /* 64 bit unique id will wrap at ~18.4 quintillion (1.84+e31), at which point UB would
     * become possible (although unlikely) */
    assert( next_slab_id != 0ll);

    if (!(slab = mem_alloc( struct_size )))
        return NULL;

    if (!allocate_shared_memory( &fd, (void**)&ptr, slab_size * sizeof(slab_niblet_t)))
    {
        assert( current ? current->error : global_error );
        free( slab );
        return NULL;
    }
    assert( ptr_is_aligned( ptr, sizeof(slab_niblet_t) ) );

    /* slab->entry left uninitialized */
    slab->next_free   = 0;
    slab->ptr         = ptr;
    slab->fd          = fd;
    slab->capacity    = capacity;
    slab->count       = 0;
    slab->id          = next_slab_id++;
    slab->slab_size   = slab_size;
    slab->struct_size = struct_size;
    memset(slab->map, 0, map_size * SHM_SLAB_MAP_BYTES);

    /* take care of memory marking (in niblets) */
    if (cache->flags & (SHM_CACHE_POISON | SHM_CACHE_PAD))
    {
        const size_t padding        = get_padding( cache );
        const size_t end_pad_offset = padding + cache->obj_size;
        const size_t used           = capacity * obj_store_size;
        slab_niblet_t *p;
        const slab_niblet_t *end;

        for (p = ptr, end = ptr + used; p != end; p += obj_store_size)
        {
            size_t i;

            /* mark object slots as unallocated */
            if (cache->flags & SHM_CACHE_POISON)
                nibset(p + padding, SHM_CACHE_FREE, cache->obj_size);

            /* mark padding as "no man's land". */
            for (i = 0; i < padding; ++i)
                p[i] = p[i + end_pad_offset] = SHM_CACHE_NO_MANS_LAND;
        }

        /* mark any unused portion as uninitiaized */
        if (cache->flags & SHM_CACHE_POISON)
            nibset((void*)end, SHM_CACHE_UNINIT, slab_size - used);
    }

    return slab;
}

/* free a shm_slab object and it's associated shared memory */
static void shm_slab_free( struct shm_slab *slab )
{
    assert( !slab->count );
    nibset( slab->ptr, SHM_CACHE_FREE, slab->slab_size );
    release_shared_memory( slab->fd, slab->ptr, slab->slab_size * sizeof(slab_niblet_t) );
    memset( slab, SHM_CACHE_FREE & 0xff, slab->struct_size );
    free( slab );
}

/* Returns the index of the next free object in the slab or -1 if none found. */
static int shm_slab_find_free(struct shm_cache *cache, struct shm_slab *slab, unsigned start)
{
    const slab_map_t ENTRY_FULL = ~((slab_map_t)0);
    const slab_map_t *const end =  &slab->map[(slab->capacity - 1) / SHM_SLAB_MAP_BITS] + 1;
    const slab_map_t *p;
    const slab_map_t *search_start;

    if (slab->count == slab->capacity)
        return -1;

    for (p = search_start = &slab->map[start / SHM_SLAB_MAP_BITS];;)
    {
        if (*p != ENTRY_FULL)
        {
            int index = (p - slab->map) * SHM_SLAB_MAP_BITS + ctol(*p);

            /* there will usually be some unused bits at the end of the map */
            if (index < (int)cache->capacity)
                return index;
        }

        if (++p == end)
            p = slab->map;

        assert( p != search_start ); /* if not at capacity, we should never reach this line */
    }
}

static inline void shm_slab_calc_map( struct shm_slab *slab, int index, slab_map_t **entry,
                                      slab_map_t *mask)
{
    assert( index >= 0 && index < (int)slab->capacity );
    *entry = &slab->map[index / SHM_SLAB_MAP_BITS];
    *mask  = ((slab_map_t)1ul) << (index % SHM_SLAB_MAP_BITS);
}

static inline int verify_niblet( const slab_niblet_t *addr, const slab_niblet_t val )
{
    if (unlikely( *addr != val ))
    {
        fprintf( stderr, "wineserver: ERROR: shared memory corruption detected: %p should be "
                 SHM_SLAB_NIBLET_FORMAT ", found " SHM_SLAB_NIBLET_FORMAT "\n", addr, val, *addr );
        set_error( STATUS_FILE_CORRUPT_ERROR );
        return 1;
    }
    return 0;
}

/* verifies the object and pointer */
static int verify_object_memory( struct shm_cache *cache, struct shm_slab *slab,
                                 const slab_niblet_t *ptr, int is_free )
{
    if (cache->flags & SHM_CACHE_VERIFY_MEM)
    {
        const size_t padding  = get_padding( cache );
        const size_t obj_size = cache->obj_size;
        size_t i;

        /* verify object was is memset correctly */
        if (is_free)
            for (i = 0; i < obj_size; ++i)
                if (verify_niblet( &ptr[i], SHM_CACHE_FREE ))
                    return 1;

        /* verify no-man's land is untouched */
        for (i = 0; i < padding; ++i)
        {
            if (verify_niblet( &ptr[i - padding ], SHM_CACHE_NO_MANS_LAND ))
                return 1;

            if (verify_niblet( &ptr[i + obj_size], SHM_CACHE_NO_MANS_LAND ))
                return 1;
        }
    }

    return 0;
}

static inline int is_pointer_valid( struct shm_cache *cache, struct shm_slab *slab,
                                    const slab_niblet_t *ptr )
{
    const size_t padding        = get_padding( cache );
    const size_t obj_store_size = get_store_size( cache );
    size_t offset;

    if (!ptr_is_aligned( ptr, sizeof(slab_niblet_t) ))
        return FALSE;

    offset = (ptr - slab->ptr) - padding;
    if (offset % obj_store_size)
        return FALSE;

    return TRUE;
}

/* Allocate the specified object from the shm_slab. If index doesn't refer to a valid, free object
 * then an assertion will fail.*/
static slab_niblet_t *shm_slab_obj_do_alloc( struct shm_cache *cache, struct shm_slab *slab,
                                             unsigned index, struct shm_object_info *info )
{
    const size_t padding  = get_padding( cache );
    const size_t offset   = get_store_size( cache ) * index + padding;
    slab_niblet_t *ptr    = slab->ptr + offset;
    slab_map_t *entry, mask;
    shm_slab_calc_map( slab, index, &entry, &mask );

    assert( slab->count < slab->capacity );
    assert( !(*entry & mask) );

    if ((cache->flags & SHM_CACHE_VERIFY_MEM) && verify_object_memory( cache, slab, ptr, TRUE ))
        return NULL;

    if (cache->flags & SHM_CACHE_POISON)
        nibset( ptr, SHM_CACHE_UNINIT, cache->obj_size );

    ++slab->count;
    *entry |= mask;

    /* While we have most of the data sitting around in registers, see if we can find the next free
     * object and if not then at least record a hint. */
    index &= ~(SHM_SLAB_MAP_BITS - 1);
    if (*entry != ~(slab_map_t)0)
    {
        /* index can == capacity here, but check is skipped as this can only happen if slab is
         * full, in which case next_free will not be used */
        slab->next_free = index + ctol(*entry);
/* remove this assert after debugging & testing */
assert( shm_slab_is_full( slab ) || slab->next_free < (int)slab->capacity );
    }
    else
        slab->next_free = -(int)(index + SHM_SLAB_MAP_BITS);

    info->shm_id = slab->id;
    info->offset = offset * sizeof(slab_niblet_t);
    info->size   = slab->slab_size * sizeof(slab_niblet_t);
    info->fd     = slab->fd;
    info->ptr    = slab->ptr + offset;

    return ptr;
}

/* Find the next free object and allocate it. Make sure the slab is not full prior to calling -- should never fail */
static slab_niblet_t *shm_slab_obj_alloc( struct shm_cache *cache, struct shm_slab *slab,
                                          struct shm_object_info *info )
{
    int next_free = slab->next_free;

    /* don't call this function when it's full */
    assert( !shm_slab_is_full( slab ) );

    if (next_free < 0)
        next_free = shm_slab_find_free( cache, slab, -next_free );

    assert( next_free >= 0 ); /* this should never happen here */

    return shm_slab_obj_do_alloc( cache, slab, next_free, info );
}

/* returns the index of the object the pointer referrs to or -1 if the slab doesn't contain this address */
static inline int shm_slab_ptr_to_index( struct shm_cache *cache, struct shm_slab *slab,
                                         const slab_niblet_t *ptr)
{
    if (ptr >= slab->ptr)
    {
        size_t index = (ptr - slab->ptr) / get_store_size( cache );

        if (is_pointer_valid( cache, slab, ptr ) && index < slab->capacity)
            return index;
    }

    return -1;
}

/* free an object */
static int shm_slab_obj_free( struct shm_cache *cache, struct shm_slab *slab, int index )
{
    slab_map_t *entry, mask;
    shm_slab_calc_map( slab, index, &entry, &mask );

    if (!(*entry & mask))
    {
        set_error( STATUS_MEMORY_NOT_ALLOCATED );
        return -1;
    }

    assert( slab->count );

    --slab->count;
    *entry &= ~mask;

    if (slab->next_free < 0 || slab->next_free > index)
        slab->next_free = index;

    if (cache->flags & (SHM_CACHE_POISON | SHM_CACHE_VERIFY_MEM))
    {
        slab_niblet_t *ptr = slab->ptr + get_store_size( cache ) * index + get_padding( cache );

        /* check no man's land */
        if (cache->flags & SHM_CACHE_VERIFY_MEM && verify_object_memory( cache, slab, ptr, FALSE ))
            return -1;

        /* mark memory as free */
        if (cache->flags & SHM_CACHE_POISON)
            nibset( ptr, SHM_CACHE_FREE, cache->obj_size );
//fprintf(stderr, "%s: %p\n", __func__, ptr);
    }
    return 0;
}


/*
 *              struct shm_cache Functions
 */

static struct shm_slab *shm_cache_grow( struct shm_cache *cache, size_t slab_size )
{
    struct shm_slab *slab = shm_slab_alloc( cache, slab_size );

    if (!slab)
        return NULL;

    list_add_tail( &cache->slabs, &slab->entry );
    cache->next_free_slab = slab;
    cache->capacity      += slab->capacity;

    return slab;
}

/* calculate the initial slab size in niblets */
static inline size_t calc_slab_size( size_t initial_size )
{
    const size_t page_size = get_page_size();

    assert_is_pow2( page_size );
    if (!initial_size)
        initial_size = page_size;
    return ((initial_size + page_size - 1) & ~(page_size - 1)) / sizeof(slab_niblet_t);
}

static inline size_t round_up_to_niblets( size_t val )
{
    return (val + sizeof(slab_niblet_t) - 1) / sizeof(slab_niblet_t);
}

/******************************************************************************
 *              shm_cache_alloc
 *
 * Allocate a new shared memory cache
 *
 * PARAMS
 *   obj_size      [I]  Size of objects this cache will allocate
 *   initial_size  [I]  The size of the initial slab in bytes
 *   flags         [I]  Flags (see below)
 *
 * Valid flags are:
 *   SHM_CACHE_POISON     poison unallocated memory 0xaa and uninitialized memory 0x55
 *   SHM_CACHE_PAD        pad all objects with memory marked 0xfd
 *   SHM_CACHE_VERIFY_MEM perform validation of memory during free/alloc operations
 */
struct shm_cache *shm_cache_alloc(size_t obj_size, size_t initial_size, int flags)
{
    const size_t slab_size = calc_slab_size( initial_size );
    size_t obj_store_size;
    struct shm_cache *cache;
    const size_t align = get_align();

    assert( obj_size );
    assert_is_pow2( align );

    /* SHM_CACHE_VERIFY_MEM implies SHM_CACHE_POISON */
    if (flags & SHM_CACHE_VERIFY_MEM)
        flags |= SHM_CACHE_POISON;

    obj_size  = round_up_to_niblets( obj_size );
    if (obj_size < align)
        obj_size = align;

    obj_store_size = obj_size;
    if (flags & SHM_CACHE_PAD)
        obj_store_size += 2;

    /* after adding pading, at least one object must still fit in the slab */
    assert( obj_store_size <= slab_size );

    cache = mem_alloc(sizeof(struct shm_cache));
    if (!cache)
        return NULL;

    cache->obj_size       = obj_size;
    cache->next_free_slab = NULL;
    cache->capacity       = 0;
    cache->count          = 0;
    cache->flags          = flags;
    list_init( &cache->slabs );

    if (!shm_cache_grow( cache, slab_size ))
    {
        free(cache);
        return NULL;
    }

    return cache;
}

static struct shm_slab *get_last_slab( struct shm_cache *cache )
{
    assert( !list_empty( &cache->slabs ) );
    return LIST_ENTRY(list_tail( &cache->slabs ), struct shm_slab, entry);
}

void shm_cache_free( struct shm_cache *cache )
{
    assert(!cache->count);

    while (!list_empty( &cache->slabs ))
    {
        struct shm_slab *slab = get_last_slab( cache );

        list_remove( &slab->entry );
        shm_slab_free( slab );
    }
    memset( cache, 0xaa, sizeof(*cache) );
    free( cache );
}

static size_t calculate_next_slab_size( struct shm_cache *cache )
{
    const size_t page_size_minus_one = get_page_size() / sizeof(slab_niblet_t) - 1;

    /* increase by roughly Phi */
    size_t new_slab_size = cache->capacity * get_store_size( cache ) * 618 / 1000;

    /* round up to the nearest page */
    return (new_slab_size + page_size_minus_one) & ~page_size_minus_one;
}

/* look for a free slab starting with the slab residing at the parameter start and wrap around to
 * the beginning of the list if needed. If start is NULL, then just start at the beginning of the
 * list. */
static struct shm_slab *find_free_slab( struct shm_cache *cache, struct shm_slab *start )
{
    struct list *i;
    struct shm_slab *slab;

    LIST_FOR_EACH( i, start ? &start->entry : &cache->slabs )
    {
        if (i == &cache->slabs)  /* not a slab object */
            continue;

        slab = LIST_ENTRY(i, struct shm_slab, entry);
        if (!shm_slab_is_full( slab ))
            return slab;
    }

    return NULL;
}

/******************************************************************************
 *              shm_cache_obj_alloc
 *
 * Allocate an object from the cache
 *
 * PARAMS
 *   cache  [I]  The cache
 *   info   [O]  (optional) buffer to store object information
 *
 * RETURNS
 *   pointer to the new object
 *   NULL upon failure - get_error() will have reason
 */
void *shm_cache_obj_alloc( struct shm_cache *cache, struct shm_object_info *info )
{
    /* if we're at capacity then grow */
    if (cache->count == cache->capacity)
        if (!shm_cache_grow( cache, calculate_next_slab_size( cache ) ))
            return NULL;

    /* if next_free_slab doesn't actually have room then find another slab */
    if (!cache->next_free_slab || shm_slab_is_full( cache->next_free_slab ))
        cache->next_free_slab = find_free_slab( cache, cache->next_free_slab );
    assert( cache->next_free_slab ); /* should never happen */

    ++cache->count;

    return shm_slab_obj_alloc( cache, cache->next_free_slab, info );
}

static inline int shm_cache_check_shrink( struct shm_cache *cache )
{
    /* when we're ~70% free, try to shirnk (but not when count == 0) */
    return cache->count * 1000 / 309 < cache->capacity;
}

static void shm_cache_try_shrink( struct shm_cache *cache )
{
    struct shm_slab *slab;

    /* don't free the last slab */
    if (list_head( &cache->slabs ) == list_tail( &cache->slabs ))
        return;

    /* try to free the smallest slab */
    LIST_FOR_EACH_ENTRY(slab, &cache->slabs, struct shm_slab, entry)
    {
        if (slab->count)
            continue;

        cache->capacity -= slab->capacity;
        if (cache->next_free_slab == slab)
            cache->next_free_slab = NULL;
        list_remove( &slab->entry );
        shm_slab_free( slab );
        return;
    }
}

static void populate_info( struct shm_cache *cache, struct shm_slab *slab, unsigned index,
                           struct shm_object_info *info )
{
    const size_t page_size = get_page_size() / sizeof(slab_niblet_t);
    const size_t padding   = get_padding( cache );
    const size_t offset    = get_store_size( cache ) * index + padding;

    assert( !(slab->slab_size % page_size) );

    info->shm_id = slab->id;
    info->offset = offset * sizeof(slab_niblet_t);
    info->size   = slab->slab_size * sizeof(slab_niblet_t);
    info->fd     = slab->fd;
    info->ptr    = slab->ptr + offset;
}

/* find the slab that houses the object at ptr address and return the slab & index of that object */
static int shm_cache_obj_find( struct shm_cache *cache, struct shm_slab **slab_ptr,
                               const slab_niblet_t *ptr, struct shm_object_info *info )
{
    struct shm_slab *slab;

    LIST_FOR_EACH_ENTRY(slab, &cache->slabs, struct shm_slab, entry)
    {
        int index = shm_slab_ptr_to_index( cache, slab, ptr );
        if (index == -1)
            continue;

        if (!is_pointer_valid( cache, slab, ptr ))
        {
            set_error( STATUS_DATATYPE_MISALIGNMENT );
            return -1;
        }

        *slab_ptr = slab;
        if (info)
            populate_info( cache, slab, index, info );

        return index;
    }

    set_error( STATUS_NOT_FOUND );
    return -1;
}

/******************************************************************************
 *              shm_cache_get_info
 *
 * Get information about an object
 *
 * PARAMS
 *   cache  [I]  The cache
 *   ptr    [I]  Pointer to the object
 *   info   [O]  (Optional) Buffer to write object information to
 *
 * RETURNS
 *   SUCCESS: the object's index (within the slab that stores it)
 *   FAILURE: -1
 */
int shm_cache_get_info( struct shm_cache *cache, void *ptr, struct shm_object_info *info )
{
    struct shm_slab *slab;
    return shm_cache_obj_find( cache, &slab, ptr, info );
}

/* free an object allocated from this cache */
int shm_cache_obj_free( struct shm_cache *cache, void **ptr )
{
    struct shm_slab *slab;
    int index = shm_cache_obj_find( cache, &slab, *ptr, NULL );

    if (index == -1)
        return -1;

    if (shm_slab_obj_free( cache, slab, index ))
        return -1;

    memset( ptr, 0x5a, sizeof(*ptr) );
    --cache->count;
    if (cache->next_free_slab && cache->next_free_slab->id > slab->id)
        cache->next_free_slab = slab;

    if (shm_cache_check_shrink( cache ))
        shm_cache_try_shrink( cache );

    return 0;
}

size_t shm_cache_get_space_used( struct shm_cache *cache )
{
    return get_store_size( cache ) * cache->count;
}

#ifdef SHM_SLAB_DEBUG
static const char *shm_slab_dump( struct dump *dump, struct shm_slab *slab, int dump_map, int dump_memory )
{
    const size_t BITS_PER_MAP_ENTRY = sizeof(slab->map[0]) * 8;
    size_t map_size = (slab->capacity + BITS_PER_MAP_ENTRY - 1) / BITS_PER_MAP_ENTRY;
    size_t i;

    dump_indent_inc(dump);
    dump_printf(dump,
            "struct shm_cache %p {\n"
            "%sentry     = (.prev = %p, .next = %p),\n"
            "%snext_free = %d,\n"
            "%sptr       = %p,\n"
            "%sfd        = %d,\n"
            "%scapacity  = %u,\n"
            "%scount     = %u,\n"
            "%sid        = %016llx,\n"
            "%sslab_size = %u,\n"
            "%sstruct_size = %u,\n"
            "%smap       = (%zu entries)",
            slab,
            dump->indent, slab->entry.prev, slab->entry.next,
            dump->indent, slab->next_free,
            dump->indent, slab->ptr,
            dump->indent, slab->fd,
            dump->indent, slab->capacity,
            dump->indent, slab->count,
            dump->indent, (long long)slab->id,
            dump->indent, slab->slab_size,
            dump->indent, slab->struct_size,
            dump->indent, map_size
    );

    if (dump_map)
    {
        const char *fmt = sizeof(long) == 8 ? "%s%016lx,\n" : "%s%08lx,\n";
        assert( sizeof(slab->map[0]) == 4 || sizeof(slab->map[0]) == 8 );

        dump_printf(dump, " {\n");
        dump_indent_inc( dump );
        for (i = 0; i < map_size; ++i)
            dump_printf(dump, fmt, dump->indent, slab->map[i]);
        dump_printf(dump, "%s}", dump_indent_dec( dump ));
    }

    if (dump_memory)
    {
        const size_t         bytes_per_row   = 64;
        const size_t         bytes_per_group = 4;
        char                 line_buf[256]   = { 0 };
        char                *out             = line_buf;
        const unsigned char *p               = (const unsigned char*)slab->ptr;
        const unsigned char *end             = p + slab->slab_size;

        dump_printf(dump, ",\n%sslab memory {", dump->indent);
        dump_indent_inc( dump );

        for (; p < end; ++p)
        {
            if (!((size_t)p % bytes_per_row) && *line_buf)
            {
                dump_printf(dump, "\n%s%s", dump->indent, line_buf);
                *line_buf = 0;
            }

            if (!*line_buf)
            {
                sprintf(line_buf, "%04lx:", (size_t)p & 0xffffl);
                out = line_buf + strlen(line_buf);
            }

            if (!((size_t)p % bytes_per_group))
                *(out++) = ' ';

            sprintf(out,"%02x", *p);
            out += 2;
        }

        if (*line_buf)
            dump_printf(dump, "\n%s%s", dump->indent, line_buf);

        dump_printf(dump, "\n%s}", dump_indent_dec(dump));
    }
    dump_printf(dump, "\n%s}", dump_indent_dec(dump));
    return dump->buffer;
}

const char *shm_cache_dump( struct dump *dump, struct shm_cache *cache, int dump_map, int dump_memory )
{
    struct shm_slab *slab;
    unsigned i;

    dump_indent_inc(dump);
    dump_printf(dump,
            "struct shm_cache %p {\n"
            "%sobj_size            = %u,\n"
            "%snext_free_slab      = %p,\n"
            "%scapacity            = %u,\n"
            "%scount               = %u,\n"
            "%sflags               = 0x%08x,\n"
            "%sslabs               (%u entries) {",
            cache,
            dump->indent, cache->obj_size,
            dump->indent, cache->next_free_slab,
            dump->indent, cache->capacity,
            dump->indent, cache->count,
            dump->indent, cache->flags,
            dump->indent, list_count( &cache->slabs ));

    dump_indent_inc(dump);

    i = 0;
    LIST_FOR_EACH_ENTRY(slab, &cache->slabs, struct shm_slab, entry)
    {
        const char *comma = i ? "," : "";
        dump_printf(dump, "%s\n%s[%u] = ", comma, dump->indent,  i);
        ++i;
        shm_slab_dump( dump, slab, dump_map, dump_memory );
    }
    dump_printf(dump, "\n%s}", dump_indent_dec(dump));
    dump_printf(dump, "\n%s}", dump_indent_dec(dump));

    return dump->buffer;
}
#endif
