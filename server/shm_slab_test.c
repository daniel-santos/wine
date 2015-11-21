#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

#include "shm_slab.h"

static char debug_bufer[0x10000];

struct obj
{
    char *ptr;
    int fd;
    unsigned offset;
};

#if 0
static  void randomize(void *p, size_t n, size_t size, unsigned int seed) {
    unsigned long *arr = p;
    const size_t LONG_BITS = sizeof(unsigned long) * 8;
    const size_t RAND_BITS = LONG_BITS - __builtin_clzl((unsigned long)RAND_MAX);
    const size_t bytes = n * size;
    const size_t count = bytes / sizeof(unsigned long);
    size_t i;

    //assert(!(bytes % sizeof(*arr)));
    //assert(size == sizeof(*arr));

    srandom(seed);

    for (i = 0; i < count; ++i) {
        size_t bits;

        arr[i] = (unsigned long)random();

        for (bits = RAND_BITS; bits < LONG_BITS; bits += RAND_BITS) {
            arr[i] <<= RAND_BITS;
            arr[i] ^= (unsigned long)random();
        }
//      arr[i] >>= 56;
    }

    /* if not aligned to size of long get the last few bytes */
    for (i = 0; i < bytes % sizeof(*arr); ++i) {
        ((char *)p) [count * sizeof(*arr) + i] = random();
    }
}
#endif

static void seed_from_time(void)
{
    struct timespec ts;
    //unsigned int seed;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    srandom(ts.tv_sec ^ ts.tv_nsec);
}

static const char *const indent_str = "                                        ";
static struct obj objs[512];
static int randlist[512];
void shm_slab_test(void)
{
    ssize_t i, j;
    struct shm_cache *cache;
    struct dump dump;
    int flags = SHM_CACHE_POISON | SHM_CACHE_PAD | SHM_CACHE_VERIFY_MEM;

    dump_init(&dump, debug_bufer, sizeof(debug_bufer), indent_str, 2);

    cache = shm_cache_alloc(sizeof(struct obj) * 30, 8, 1, flags);
    assert (cache);
    fprintf(stdout, "%s\n\n\n", shm_cache_dump( cache, &dump, 1, 0 ));
    dump_reset(&dump);




    seed_from_time();
    for (i = 0; i < 512; ++i)
        randlist[i] = -1;

    for (i = 0; i < 512; ++i)
    {
        size_t r = random();
        for (j = 0; j < 512; ++j)
        {
            size_t index = (r + j) % 512;
            if (randlist[index] == -1)
            {
                randlist[index] = i;
                break;
            }
        }
    }

    //randomize(randlist, 512, sizeof(randlist[0]), 0);

    for (i = 0; i < 512; ++i) {
        struct obj *obj = &objs[i];

        obj->ptr = shm_cache_obj_alloc( cache, &obj->fd, &obj->offset );
        assert( obj->ptr );

        //*((short*)obj->ptr) = (short)i;
        *((struct obj*)(obj->ptr)) = *obj;
    }

    fprintf(stdout, "%s\n\n\n", shm_cache_dump( cache, &dump, 1, 0 ));
    dump_reset(&dump);

    /* now free in random order */
    for (i = 496; i >= 0; --i) {
        struct obj *obj = &objs[randlist[i]];
        shm_cache_obj_free( cache, &obj->ptr );
    }
    for (i = 0; i < 64; ++i) {
        struct obj *obj = &objs[randlist[i]];
        obj->ptr = shm_cache_obj_alloc( cache, &obj->fd, &obj->offset );
        assert( obj->ptr );

        //*((short*)obj->ptr) = (short)i;
        *((struct obj*)(obj->ptr)) = *obj;
    }

    //assert(shm_cache_obj_free( cache, objs[511].ptr ) == -1);

    //objs[0].ptr = shm_cache_obj_alloc( cache, &objs[0].fd, &objs[0].offset );

    fprintf(stdout, "%s\n", shm_cache_dump( cache, &dump, 1, 0 ));
}

int main(int argc, char *argv[])
{
    shm_slab_test();
    return 0;
}
