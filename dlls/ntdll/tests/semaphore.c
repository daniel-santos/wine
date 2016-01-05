/*
 * Unit test suite for semaphores
 *
 * Copyright 2015 Daniel Santos
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

#include "ntdll_test.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

static char         base[MAX_PATH];
static char         selfname[MAX_PATH];
static const char  *exename;

static struct migration_test_params
{
    unsigned seed;
    ULONGLONG duration;                  /* test duration in miliseconds (or zero if set iterations) */
    unsigned iterations;                /* number of iterations to run */
    unsigned num_thread_process_pairs;  /* number of thread/process pairs */
    unsigned nsems;                     /* size of pool of semaphores each thread/process pair can draw from */
    unsigned pair_max_sems;             /* maxiumum number of semaphores each pair can have */
} params = {
    UINT_MAX,
    0,
    1,
    1,
    4,
    4
};

static void report_error(const char *operation)
{
    DWORD err = GetLastError();
    char buf[0x400];

    if (!err)
        return;

    /* wow, I forgot how stupid 'perror' is on windows */
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                    MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
                    buf, sizeof(buf) / sizeof(*buf) - 1, NULL);

    trace("%s failed with %08x: %s\n", operation, err, buf);
}

static void fill_last_error(char *buf, size_t size)
{
    DWORD err = GetLastError();
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                    MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
                    buf, size - 1, NULL);
}

/* Nomenclature:        return value    check last error        check status
 * do_test_ae           assign          yes                     no
 * do_test_as           assign          no                      yes
 * do_test_te           test            yes                     no
 * do_test_ts           test            no                      yes
 * do_test_se           ignore          yes                     no
 * do_test_ss           ignore          no                      yes
 *
 */

#define do_test_ae(result_var, result_ok_expr, result_type_format_str, last_err_ok_expr, fn, ...) \
    do {\
        DWORD err; \
        SetLastError(0xdeadbeef); \
        result_var = fn(__VA_ARGS__); \
        err = GetLastError(); \
        ok(!!(result_ok_expr), #fn " returned " result_type_format_str ", failed expression (" \
                               #result_ok_expr ")\n", result_var); \
        if (!(last_err_ok_expr)) { \
            char buf[0x400]; \
            fill_last_error(buf, sizeof(buf)); \
            ok(0, #fn ": expected " #last_err_ok_expr ", got %08x: %s\n", err, buf); \
        } \
    } while(0)

static void test_sem_simple_create(void)
{
    HANDLE sem;

    do_test_ae(sem, !!sem, "%p", !err, CreateSemaphoreA, NULL, INT_MAX, INT_MAX, NULL);
    //sem = create_sem(INT_MAX, INT_MAX, NULL, FALSE, 0);
    if (sem)
        CloseHandle(sem);
}

static void test_limits(void)
{
    HANDLE s;
    DWORD ret;

    do_test_ae(s, !!s, "%p", !err, CreateSemaphoreA, NULL, INT_MAX, INT_MAX, NULL);
    if (s)
        CloseHandle(s);

    do_test_ae(s, !!s, "%p", !err, CreateSemaphoreA, NULL, INT_MAX - 1, INT_MAX - 1, NULL);
    if (s)
        CloseHandle(s);

    do_test_ae(s, !s, "%p", err == ERROR_INVALID_PARAMETER, CreateSemaphoreA, NULL, (ULONG)INT_MAX + 1u, (ULONG)INT_MAX + 1u, NULL);
    if (s)
        CloseHandle(s);

    do_test_ae(s, !s, "%p", err == ERROR_INVALID_PARAMETER, CreateSemaphoreA, NULL, INT_MAX, (ULONG)INT_MAX + 1u, NULL);
    if (s)
        CloseHandle(s);

    do_test_ae(s, !s, "%p", err == ERROR_INVALID_PARAMETER, CreateSemaphoreA, NULL, (ULONG)INT_MAX + 1u, INT_MAX + 1u, NULL);
    if (s)
        CloseHandle(s);

    do_test_ae(s, !!s, "%p", !err, CreateSemaphoreA, NULL, 0, 1, NULL);

    do_test_ae(ret, ret, "%d", err == 0xdeadbeef, ReleaseSemaphore, s, 1, NULL );
    do_test_ae(ret, !ret, "%d", err == ERROR_TOO_MANY_POSTS, ReleaseSemaphore, s, 1, NULL );

    if (s)
        CloseHandle(s);
}

static void test_sem_simple_wait(void)
{
    HANDLE sem;
    DWORD ret;
    do_test_ae(sem, !!sem, "%p", !err, CreateSemaphoreA, NULL, 0, 1, NULL);

    do_test_ae(ret, ret == WAIT_TIMEOUT, "%d", err == 0xdeadbeef, WaitForSingleObject, sem, 10 );
    do_test_ae(ret, ret, "%d", err == 0xdeadbeef, ReleaseSemaphore, sem, 1, NULL );

    ret = WaitForSingleObject( sem, 1000 );
    ok(ret == WAIT_OBJECT_0, "WaitForSingleObject returned %08x\n", ret);
    if (ret != WAIT_OBJECT_0)
        report_error("WaitForSingleObject");

    ret = WaitForSingleObject( sem, 123 );
    ok(ret == WAIT_TIMEOUT, "WaitForSingleObject: expected WAIT_TIMEOUT, got %08x\n", ret);

}

#define NUM_SEMS 8


DWORD WINAPI test_sem_thread( LPVOID lpParam )
{
    HANDLE (*sem)[NUM_SEMS] = lpParam;
    DWORD ret;
    int i;

//    trace("sem = %p\n", (*sem)[0]);

    for (i = 0; i < 65536; i += 2)
    {
        ret = WaitForSingleObject( (*sem)[i % NUM_SEMS], 4000 );
        if (!ret && ret != STATUS_TIMEOUT)
            report_error("WaitForSingleObject");
        ok(ret == WAIT_OBJECT_0, "WaitForSingleObject failed, ret = %08x\n", ret);
//trace("    %-4u -%u\n", i, i % NUM_SEMS);

        ret = ReleaseSemaphore((*sem)[(i + 1) % NUM_SEMS], 1, NULL);
        if (!ret)
            report_error("ReleaseSemaphore");
        ok(ret, "ReleaseSemaphore failed, ret = %d\n", ret);
//trace("    %-4u +%u\n", i, (i + 1) % NUM_SEMS);
    }

    ret = WaitForMultipleObjects(NUM_SEMS, *sem, TRUE, 4000);
    if (ret != 0 && ret != STATUS_TIMEOUT)
        report_error("WaitForMultipleObjects");
    ok(ret == WAIT_OBJECT_0, "WaitForMultipleObjects failed, ret = %08x\n", ret);

    trace("wait multiple completed.\n");

    return 0;
}

static void test_sem(void)
{
    HANDLE sem[NUM_SEMS];
    HANDLE t;
    DWORD tid;
    DWORD ret = 0;
    int i;

    for (i = 0; i < NUM_SEMS; ++i)
        do_test_ae(sem[i], !!sem[i], "%p", !err, CreateSemaphoreA, NULL, 0, 1, NULL);

    t = CreateThread(NULL, 0, test_sem_thread, &sem, 0, &tid);
    ok(!!t, "CreateThread failed\n");

    for (i = 0; i < 65536; i += 2)
    {

        ret = ReleaseSemaphore(sem[i % NUM_SEMS], 1, NULL);
        if (!ret)
            report_error("ReleaseSemaphore");
        ok(ret, "ReleaseSemaphore failed, ret = %d\n", ret);
//trace("%-4u     +%u\n", i, i % NUM_SEMS);

        ret = WaitForSingleObject( sem[(i + 1) % NUM_SEMS], 4000 );
        if (ret != 0 && ret != STATUS_TIMEOUT)
            report_error("WaitForSingleObject");
        ok(ret == WAIT_OBJECT_0, "WaitForSingleObject failed, ret = %08x\n", ret);
//trace("%-4u     -%u\n", i, (i + 1) % NUM_SEMS);
    }

    for (i = 0; i < NUM_SEMS; ++i)
    {
        ret = ReleaseSemaphore(sem[i], 1, NULL);
        if (!ret)
            report_error("ReleaseSemaphore");
        ok(ret, "ReleaseSemaphore failed, ret = %d\n", ret);
//trace(".\n");
        Sleep(25);
    }

    ret = WaitForSingleObject( t, 4000 );
    if (!ret && GetLastError() != STATUS_TIMEOUT)
        report_error("WaitForSingleObject");
    ok(ret == WAIT_OBJECT_0, "WaitForSingleObject failed, ret = %08x\n", ret);


    for (i = 0; i < NUM_SEMS; ++i)
        CloseHandle( sem[i % NUM_SEMS] );

    CloseHandle( t );

}


/***************************************************************************************************
 *
 *                                      Migration Stress Tests
 *
 * The theory of these tests is to spawn threads followed by several single-threaded processes. The
 * processes will then successively open and interact with semaphores created by the main process.
 * Each time a process opens a semaphore (that it doesn't already have a handle to) or closes one, a
 * migration is triggered. Each therad will perform various waits on these semaphores and, in turn
 * signal a corresponding process when it's ready for the next iteration.
 *
 * Any other processes that are using these semaphores should manage the migration properly and
 * without delay. If a thread is waiting on one of these objects, the migration should trigger the
 * thread to wake up immediately (become runnable) and make a call to the server (unless another
 * thread of that process beat them to it) so that the underlying wait uses the correct futex
 * address (Linux implementation).
 *
 */
#undef NUM_SEMS
#if 1
#define MAX_NUM_SEMS             128    /* maximum number of semaphores to use */
#define NUM_THREAD_PROCESS_PAIRS 24 
#define PAIR_MAX_SEMS            32     /* how many sems each thread in main process will use */
#else
#define MAX_NUM_SEMS             4    /* maximum number of semaphores to use */
#define NUM_THREAD_PROCESS_PAIRS 1
#define PAIR_MAX_SEMS            4     /* how many sems each thread in main process will use */
#endif

#define STRESS_WAIT_TIME        8000

enum migration_test_state
{
    STATE_INIT,
    STATE_WAITING,
    STATE_RELEASED,
    STATE_DONE,
    STATE_ABORT
};

struct migration_test_data;
struct thread_process_pair
{
    unsigned                    id;
    unsigned                    orig_seed;
    unsigned                    seed;
    unsigned                    nsems;
    unsigned                    sem_indexes[PAIR_MAX_SEMS];
    HANDLE                      sems[PAIR_MAX_SEMS];
    volatile int               *state;
    HANDLE                      thread_handle;
    DWORD                       thread_id;
    PROCESS_INFORMATION         info;
    HANDLE                      sem_thread_ready;       /* for test thread to single main thread that it's ready */
    HANDLE                      sem_thread_repeat;
    struct migration_test_data *data;
};

struct migration_test_data
{
    //HANDLE                      sem_main;
    HANDLE                      thread_repeat_sem;
    HANDLE                      sems[MAX_NUM_SEMS];
    unsigned                    sem_users[MAX_NUM_SEMS];
    struct thread_process_pair  pairs[NUM_THREAD_PROCESS_PAIRS];
    HANDLE                      threads[NUM_THREAD_PROCESS_PAIRS];
    HANDLE                      sems_thread_ready[NUM_THREAD_PROCESS_PAIRS];
    HANDLE                      shm_handle;
    char                       *shm;
    unsigned                    seed;
    unsigned                    num_iterations;
    ULONGLONG                   stop_time;
    volatile int                abort;  /* abnormal end  of tests */
    volatile int                end;    /* normal end of tests */
};

enum sem_test_type
{
        SEM_TEST_SINGLE,
        SEM_TEST_MULTIPLE_ALL,
        SEM_TEST_MULTIPLE_ANY,

        SEM_TEST_COUNT
};

const char *const sem_test_type_str[SEM_TEST_COUNT] = {
    "SEM_TEST_SINGLE",
    "SEM_TEST_MULTIPLE_ALL",
    "SEM_TEST_MULTIPLE_ANY"
};

struct migration_test
{
    enum sem_test_type  type;
    unsigned            nsems;
    unsigned            any_selection;
    HANDLE              sems[MAX_NUM_SEMS];
};

static void dump_thread_process_pair(struct thread_process_pair *pair)
{
    int i;
    char buffer[0x1000];
    char *start = buffer;
    const char *const end = start + sizeof(buffer);

    start += snprintf(start, end - start,
            "pair %p {"
            "id = %u, "
            "orig_seed = %u, "
            "seed = %u, "
            "nsems=%u, "
            "sem_indexes[] = {",
            pair,
            pair->id,
            pair->orig_seed,
            pair->seed,
            pair->nsems);

    for (i = 0; i < pair->nsems; ++i)
        start += snprintf(start, end - start, "%s%u", i ? ", " : "", pair->sem_indexes[i]);
    start += snprintf(start, end - start, "}, sems[] = {");
    for (i = 0; i < pair->nsems; ++i)
        start += snprintf(start, end - start, "%s%p", i ? ", " : "", pair->sems[i]);
    start += snprintf(start, end - start,
            "}, state = %p (%d), "
            "thread_handle = %p, "
            "thread_id = %d, "
            "sem_thread_ready = %p, "
            "data = %p}\n",
            pair->state, *pair->state,
            pair->thread_handle,
            pair->thread_id,
            pair->sem_thread_ready,
            pair->data);
    trace(buffer);
}

static void dump_migration_test(struct migration_test *test)
{
    char buffer[0x1000];
    char *start = buffer;
    const char *const end = start + sizeof(buffer);
    int i;

    start += snprintf(start, end - start,
            "test %p {"
            "type = %u (%s), "
            "nsems = %u, "
            "any_selection = %u, "
            "sems[] = {",
            test,
            test->type, sem_test_type_str[test->type],
            test->nsems,
            test->any_selection);

    for (i = 0; i < test->nsems; ++i)
        start += snprintf(start, end - start, "%s%p", i ? ", " : "", test->sems[i]);
    start += snprintf(start, end - start, "}}\n");
    trace(buffer);
}


/* a stupid wait and cmp/xchng function */
static int wait_for_value_and_set(volatile int *addr, int expected_value, int new_value, DWORD duration)
{
    ULONGLONG end = GetTickCount64() + (ULONGLONG)duration;
    int cur_value;

    while ((cur_value = *addr) != expected_value && (LONGLONG)(end - GetTickCount64()) > 0ll)
    {
        if (cur_value == STATE_DONE || cur_value == STATE_ABORT)
            return cur_value;
        Sleep(4);
    }

    if (cur_value != expected_value)
        return cur_value;
    else
        return InterlockedCompareExchange(addr, new_value, expected_value);
}

static void init_pair_data(struct thread_process_pair *pair, unsigned *seed, unsigned id,
                           void *shm, unsigned *sem_users)
{
    int i, j, k;

    memset(pair, 0, sizeof(*pair));

    pair->id        = id;
    pair->orig_seed = *seed;
    pair->nsems     = (rand_r(seed) % PAIR_MAX_SEMS) + 1;
    pair->state     = (int*)shm + id;

    /* init sem indexes, but assure there's no duplicates */
    for (i = 0; i < pair->nsems; ++i)
        pair->sem_indexes[i] = MAX_NUM_SEMS;

    for (i = 0; i < pair->nsems; ++i)
    {
        for (j = rand_r(seed);; ++j)
        {
            j %= MAX_NUM_SEMS;
            for (k = 0; k < i; ++k)
                if (pair->sem_indexes[k] == j)
                    break;
            if (k == i)
                break;
        }

        pair->sem_indexes[i] = j;
        if (sem_users)
            ++sem_users[j];
    }

    pair->seed = *seed;
}

static void get_next_test(struct thread_process_pair *pair, struct migration_test *test)
{
    int i, j, k;

    test->type = rand_r(&pair->seed) % SEM_TEST_MULTIPLE_ANY; // SEM_TEST_COUNT;

    if (test->type == SEM_TEST_SINGLE)
        test->nsems = 1;
    else
    {
        test->nsems = rand_r(&pair->seed) % pair->nsems + 1;
        if (test->type == SEM_TEST_MULTIPLE_ANY)
            test->any_selection = rand_r(&pair->seed) % test->nsems;
    }

    for (i = 0; i < test->nsems; ++i)
        test->sems[i] = NULL;

    for (i = 0; i < test->nsems; ++i)
    {
        for (j = rand_r(&pair->seed);; ++j)
        {
            HANDLE sem = pair->sems[j % pair->nsems];

            for (k = 0; k < i; ++k)
                if (test->sems[k] == sem)
                    goto continue_outer;

            test->sems[i] = sem;
            break;

continue_outer:
            continue;
        }
    }
}

static void *get_shared_memory(HANDLE *h, BOOL create, BOOL *not_found)
{
    size_t size = 8192 + sizeof(int) * (NUM_THREAD_PROCESS_PAIRS + 1);
    void *mem;

    if (create)
        do_test_ae(*h, !!*h, "%p", err == ERROR_SUCCESS,
                   CreateFileMappingA, INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size,
                                       "test_migrate_shm");
    else
    {
        *h = OpenFileMappingA (FILE_MAP_ALL_ACCESS, FALSE, "test_migrate_shm");
        if (!*h && not_found && GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            *not_found = TRUE;
            return NULL;
        }
        ok(!!*h, "OpenFileMappingA failed, last error = %08x\n", GetLastError());
    }

    if (!*h)
        return NULL;

    do_test_ae(mem, mem != NULL, "%p", err == 0xdeadbeef,
               MapViewOfFile, *h, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (!mem)
    {
        CloseHandle(*h);
        return NULL;
    }

    if (create)
        memset(mem, 0, size);
    return mem;
}

/* spawn a new process (return zero upon success) */
static int test_migrate_spawn_process(struct thread_process_pair *pair, unsigned cur_seed)
{
    BOOL         ret;
    STARTUPINFOA startup;
    char         buffer[MAX_PATH];

    memset(&startup, 0, sizeof(startup));
    startup.cb      = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;

    snprintf(buffer, sizeof(buffer), "\"%s\" tests/semaphore.c migrate %u %u %u",
            selfname, pair->id, pair->orig_seed, cur_seed);

    do_test_ae(ret, ret , "%d", err == ERROR_SUCCESS,
               CreateProcessA, NULL, buffer, NULL, NULL, FALSE, 0L, NULL, NULL, &startup, &pair->info);

    return !ret;        /* windows to rest-of-the-world return value */
}

static void test_migrate_process(int argc, const char *argv[])
{
    struct thread_process_pair pair;
    struct migration_test      test;
    unsigned                   id;
    unsigned                   orig_seed;
    unsigned                   cur_seed;
    HANDLE                     shm_handle;
    void                      *shm;
//    HANDLE                     sem_main;
    char                       buffer[MAX_PATH];
    DWORD                      result;
    int                        i;
    int                        state;
    BOOL                       was_not_found = 0;

    memset(&pair, 0, sizeof(pair));
    memset(&test, 0, sizeof(test));

    assert(argc >= 3);
    id        = atoi(argv[0]);
    orig_seed = atoi(argv[1]);
    cur_seed  = atoi(argv[2]);
    assert(id < NUM_THREAD_PROCESS_PAIRS);

    /* get shared memory */
    if (!(shm = get_shared_memory(&shm_handle, FALSE, &was_not_found)))
    {
        if (was_not_found)
            goto exit;
        goto abort;
    }
//trace("\n\n\n");

//trace("shm = %08x\n", *((volatile int*)shm + NUM_THREAD_PROCESS_PAIRS));
    /* init pair */
    init_pair_data(&pair, &orig_seed, id, shm, NULL);
    pair.seed = cur_seed;

#if 0
    /* get thread ready sem */
    snprintf(buffer, sizeof(buffer), "test_migrate_sem_ready %u", id);
    do_test_ae(pair.sem_thread_ready, !!pair.sem_thread_ready, "%p", err == 0xdeadbeef,
               OpenSemaphoreA, SEMAPHORE_ALL_ACCESS, FALSE, buffer);
    if (!pair.sem_thread_ready)
        goto abort;
#endif

    state = wait_for_value_and_set(pair.state, STATE_WAITING, STATE_RELEASED, STRESS_WAIT_TIME);
    if (state == STATE_DONE || state == STATE_ABORT)
        goto exit;
    ok (state == STATE_WAITING, "state = %d, expected STATE_WAITING\n", state);
    if (state != STATE_WAITING)
        goto abort;
    /*
    state = *pair.state;
    if (state == STATE_DONE || state == STATE_ABORT)
        return;
    */

    /* open the test semaphore(s) this pair is using */
    for (i = 0; i < pair.nsems; ++i)
    {
        snprintf(buffer, sizeof(buffer), "test_migrate_sem %u", pair.sem_indexes[i]);
        //trace("opening sem with name \"%s\"\n", buffer);

        SetLastError(0xdeadbeef);
        pair.sems[i] = OpenSemaphoreA(SEMAPHORE_ALL_ACCESS, FALSE, buffer);
        if (!pair.sems[i])
        {
            state = *pair.state;
            asm volatile ("" : : : "memory");
            if (state == STATE_DONE || state == STATE_ABORT)
                goto exit;
            //trace("state = %d\n", state);
            ok(!!pair.sems[i], "OpenSemaphoreA state = %d\n", state);
        }
#if 0
        do_test_ae(pair.sems[i], !!pair.sems[i], "%p", err == 0xdeadbeef,
                   OpenSemaphoreA, SEMAPHORE_ALL_ACCESS, FALSE, buffer);
#endif
        if (!pair.sems[i])
            goto abort;
    }
    //dump_thread_process_pair(&pair);
    //trace("PROCESS %u ", pair.seed);
    get_next_test(&pair, &test);
    if (0)
        dump_migration_test(&test);


    fprintf(stderr, "r");
    switch (test.type)
    {
    case SEM_TEST_SINGLE:
        do_test_ae(result, result, "%d", err == 0xdeadbeef,
                   ReleaseSemaphore, test.sems[0], 1, NULL );
        break;

    case SEM_TEST_MULTIPLE_ALL:
        for (i = 0; i < test.nsems; ++i)
        {
            do_test_ae(result, result, "%d", err == 0xdeadbeef,
                       ReleaseSemaphore, test.sems[i], 1, NULL );
            if (!result)
                goto abort;
        }
        break;

    case SEM_TEST_MULTIPLE_ANY:
        do_test_ae(result, result, "%d", err == 0xdeadbeef,
                   ReleaseSemaphore, test.sems[test.any_selection], 1, NULL );
        break;
    default:;
    }


    for (i = 0; i < pair.nsems; ++i)
        CloseHandle(pair.sems[i]);

    if (winetest_get_failures())
        goto abort;
//trace("\n\nbailing now...\n");
//return;
    /* otherwise, spawn next process */
    result = test_migrate_spawn_process(&pair, pair.seed);
    ok(!result, "failed to spawn new process\n");
    if (!result)
        goto exit;

abort:
    trace("%s ERROR: aborting test\n", __func__);
    if (pair.state)
    {
        int last_state;
        int new_state = *pair.state;

        /* this is how we communicate back to the main process that the test is bad */
        do {
            last_state = new_state;
            new_state = InterlockedCompareExchange(pair.state, STATE_ABORT, last_state);
        } while (new_state != last_state);
    }
    return;

exit:
    /* since we need to spawn many, many processes, we can't have spam */
    winetest_debug = 0;
}

static inline int thread_keep_going(struct migration_test_data *data)
{
    asm volatile ("" : : : "memory");
    return !(data->abort || data->end);
}

/* thread function for migration tests */
static DWORD WINAPI test_migrate_thread( LPVOID lpParam )
{
    struct thread_process_pair *pair = lpParam;
    struct migration_test_data *data = pair->data;
    struct migration_test test;
    DWORD ret;
    int i = 0;

    memset(&test, 0, sizeof(test));

    /* tell main thread that we're ready to start */
    do_test_ae(ret, ret, "%d", err == 0xdeadbeef,
               ReleaseSemaphore, pair->sem_thread_ready, 1, NULL);
    if (!ret)
        goto abort;

    wait_for_value_and_set(pair->state, STATE_INIT, STATE_WAITING, STRESS_WAIT_TIME);
    /* wait for main thread to signal test start */
    do_test_ae(ret, ret == WAIT_OBJECT_0, "%d", err == 0xdeadbeef,
               WaitForSingleObject, pair->sem_thread_repeat, 10000);

    /* TODO: audit this later for memory barrier to make sure that we can't run forever */
    while(thread_keep_going(data))
    {
        int state;
        //trace("\nget next\n");


        //trace("THREAD  %u ", pair->seed);
        get_next_test(pair, &test);
        if (0)
            dump_migration_test(&test);

        fprintf(stderr, "w");

        switch (test.type)
        {
        case SEM_TEST_SINGLE:
            do_test_ae(ret, ret == WAIT_OBJECT_0, "%08x", err == 0xdeadbeef,
                       WaitForSingleObject, test.sems[0], STRESS_WAIT_TIME);
            break;

        case SEM_TEST_MULTIPLE_ALL:
            do_test_ae(ret, ret == WAIT_OBJECT_0, "%08x", err == 0xdeadbeef,
                       WaitForMultipleObjects, test.nsems, &test.sems[0], TRUE, STRESS_WAIT_TIME);
            break;

        case SEM_TEST_MULTIPLE_ANY:
            do_test_ae(ret, ret == WAIT_OBJECT_0 + test.any_selection, "%08x", err == 0xdeadbeef,
                       WaitForMultipleObjects, test.nsems, test.sems, FALSE, STRESS_WAIT_TIME);
            break;
        default:;
        }

        if (ret != WAIT_OBJECT_0)
            goto abort;

        /* tell main thread that we're ready for the next test */
        do_test_ae(ret, ret, "%d", err == 0xdeadbeef,
                   ReleaseSemaphore, pair->sem_thread_ready, 1, NULL);
        if (!ret) {
            trace("thread iteration %u\n", i);
            dump_thread_process_pair(pair);
            dump_migration_test(&test);
            goto abort;
        }

        /* wait for signal to start next test */
        do_test_ae(ret, ret == WAIT_OBJECT_0, "%d", err == 0xdeadbeef,
                   WaitForSingleObject, pair->sem_thread_repeat, STRESS_WAIT_TIME);
        if (ret != WAIT_OBJECT_0)
            goto abort;

        state = wait_for_value_and_set(pair->state, STATE_RELEASED, STATE_WAITING, STRESS_WAIT_TIME);
        if (state == STATE_ABORT)
            goto abort;
        ok (state == STATE_RELEASED, "state = %d, expected STATE_RELEASED\n", state);
        if (state != STATE_RELEASED)
            goto abort;
        ++i;
    }
    wait_for_value_and_set(pair->state, STATE_RELEASED, STATE_DONE, STRESS_WAIT_TIME);
    return 0;

abort:
    data->abort = 1;
    return -1;
}

static int keep_running(const struct migration_test_data *data, unsigned count)
{
    if (data->abort)
        return 0;

    /* num_iterations is zero if this is a timed test */
    return data->num_iterations
         ? count < data->num_iterations
         : data->stop_time - GetTickCount64() > 0;
}

void test_migrate(void)
{
    char                buffer[MAX_PATH];
    DWORD               ret = 0;
    int                 i, j;
    unsigned            seed_next;
    unsigned            count;
    struct migration_test_data *data;
    unsigned            post_init_rand[NUM_THREAD_PROCESS_PAIRS];

    if (params.seed == UINT_MAX)
        params.seed = GetTickCount();

    data = malloc(sizeof(*data));
    ok (!!data, "malloc of %zu bytes failed\n", sizeof(*data));
    if (!data)
        goto abort;
    memset(data, 0, sizeof(*data));

    data->seed                  = params.seed;
    data->num_iterations        = params.iterations;
    data->stop_time             = 0;
    data->abort                 = 0;
    data->end                   = 0;
    data->shm                   = get_shared_memory(&data->shm_handle, TRUE, NULL);
    if (!data->shm)
        goto abort;

    printf("%s running with seed %u\n", __func__, params.seed);
    seed_next = params.seed;

    /* init test data */
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
    {
        init_pair_data(&data->pairs[i], &seed_next, i, data->shm, data->sem_users);
        post_init_rand[i] = data->pairs[i].seed;
    }

    /* create main sem */
//    do_test_ae(data->sem_main, !!data->sem_main, "%p", !err,
//               CreateSemaphoreA, NULL, 0, NUM_THREAD_PROCESS_PAIRS, "test_migrate_sem_main");

    /* create semaphores used for tests */
    for (i = 0; i < MAX_NUM_SEMS; ++i)
    {
        /* if initialization didn't assign any users then skip it */
        if (!data->sem_users[i])
            continue;

        snprintf(buffer, sizeof(buffer), "test_migrate_sem %u", i);
        trace("creating sem with name \"%s\", max = %u\n", buffer, data->sem_users[i]);
        do_test_ae(data->sems[i], !!data->sems[i], "%p", !err,
                   CreateSemaphoreA, NULL, 0, data->sem_users[i], buffer);
    }


    /* create thread_ready semaphores & init pair->sems[] arrays */
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
    {
        HANDLE h;
        struct thread_process_pair *pair = &data->pairs[i];

        //snprintf(buffer, sizeof(buffer), "test_migrate_sem_ready %u", i);
        do_test_ae(h, !!h, "%p", !err, CreateSemaphoreA, NULL, 0, 1, NULL);
        if (!h)
            goto abort;
        data->sems_thread_ready[i] = h;
        pair->sem_thread_ready     = h;

        do_test_ae(h, !!h, "%p", !err, CreateSemaphoreA, NULL, 0, 1, NULL);
        if (!h)
            goto abort;
        pair->sem_thread_repeat    = h;
        pair->data                 = data;

        for (j = 0; j < pair->nsems; ++j)
            pair->sems[j] = data->sems[pair->sem_indexes[j]];

        if (0)
            dump_thread_process_pair(pair);
    }
#if 0
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
    {
        int k;
        struct thread_process_pair *pair = &data->pairs[i];

        for (j = 0; j < pair->nsems; ++j)
        {
            for (k = 0; k < j; ++k)
            {
                if (pair->sems[j] == pair->sems[k])
                {
                    trace("i = %u, j = %u, k = %u (%p == %p)\n", i, j, k, pair->sems[j], pair->sems[k]);
                    dump_thread_process_pair(pair);
                    goto die;
                }
            }
        }
    }

    if(1)
    {
        int k;
        struct thread_process_pair *pair = &data->pairs[0];
        struct migration_test test;

        for (i = 0; i < 0x1000000; ++i) {
            get_next_test(pair, &test);

            for (j = 0; j < test.nsems; ++j)
            {
                for (k = 0; k < j; ++k)
                    if(test.sems[j] == test.sems[k])
                    {
                        dump_thread_process_pair(pair);
                        dump_migration_test(&test);
                        goto die;
                    }
            }
        }
    }


die:
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
    {
        struct thread_process_pair *pair = &data->pairs[i];

        for (j = 0; j < pair->nsems; ++j)
            CloseHandle(pair->sems[j]);
        CloseHandle(pair->sem_thread_ready);
    }

    for (i = 0; i < MAX_NUM_SEMS; ++i)
        if (data->sems[i])
            CloseHandle(data->sems[i]);

    exit(0);

#endif

for (j = 0; j < 100; ++j) {
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
        do_test_ae(ret, ret, "%d", err == 0xdeadbeef,
                   ReleaseSemaphore, data->sems_thread_ready[i], 1, NULL);

    do_test_ae(ret, ret == WAIT_OBJECT_0, "%08x", err == 0xdeadbeef,
               WaitForMultipleObjects, NUM_THREAD_PROCESS_PAIRS, &data->sems_thread_ready[0],
                                       TRUE, 10000 );
}



    /* create our test threads */
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
    {
        struct thread_process_pair *pair = &data->pairs[i];

        pair->thread_handle = CreateThread(NULL, 0, test_migrate_thread, pair, 0, &pair->thread_id);
        ok(!!pair->thread_handle, "CreateThread failed\n");
        if (!pair->thread_handle)
            goto abort;
        data->threads[i] = pair->thread_handle;
    }

    /* wait for threads to get started and signal that they're ready so we have the greatest chance
     * for contention */
    do_test_ae(ret, ret == WAIT_OBJECT_0, "%08x", err == 0xdeadbeef,
               WaitForMultipleObjects, NUM_THREAD_PROCESS_PAIRS, &data->sems_thread_ready[0],
                                       TRUE, 10000 );
    if (ret != WAIT_OBJECT_0)
        goto abort;

#if 0
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
        do_test_ae(ret, ret == WAIT_OBJECT_0, "%d", err == 0xdeadbeef,
                   WaitForSingleObject, data->pairs[i].sem_thread_ready, 10000 );
#endif
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
        do_test_ae(ret, ret, "%d", err == 0xdeadbeef,
                   ReleaseSemaphore, data->pairs[i].sem_thread_repeat, 1, NULL );

    Sleep(50);
    if (params.duration)
        data->stop_time = GetTickCount64() + params.duration;
    else
        data->num_iterations = params.iterations;

    /* now spawn processes that interact with each thread */
    for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
        if (test_migrate_spawn_process(&data->pairs[i], post_init_rand[i]))
            goto abort;

    for (count = 0; !data->end;)
    {
//        trace("iteration %u\n", count);
        fprintf(stderr, "%u", count);
        do_test_ae(ret, ret == WAIT_OBJECT_0, "%08x", err == 0xdeadbeef,
                   WaitForMultipleObjects, NUM_THREAD_PROCESS_PAIRS, data->sems_thread_ready,
                                           TRUE, 10000 );
        if (ret != WAIT_OBJECT_0)
            goto abort;

        if (!keep_running(data, ++count))
        {
            data->end = 1;
            asm volatile ("" : : : "memory");
        }

        for (i = 0; i < NUM_THREAD_PROCESS_PAIRS; ++i)
            do_test_ae(ret, ret, "%d", err == 0xdeadbeef,
                       ReleaseSemaphore, data->pairs[i].sem_thread_repeat, 1, NULL );
        if (!ret)
        {
            trace("ABORT: iteration = %u\n", count);
            goto abort;
        }
    }

    do_test_ae(ret, ret == WAIT_OBJECT_0, "%08x", err == 0xdeadbeef,
                WaitForMultipleObjects, NUM_THREAD_PROCESS_PAIRS, &data->threads[0],
                                        TRUE, 10000 );
    trace("main process proceeding now...\n");

    for (i = 0; i < MAX_NUM_SEMS; ++i)
        if (data->sems[i])
            CloseHandle(data->sems[i]);

    UnmapViewOfFile(data->shm);
    CloseHandle(data->shm_handle);
//Sleep(60 * 60 * 1000 * 24);
    return;

abort:
    data->abort = 1;
    trace("WARNING: %s aborted due to failure!\n", __func__);
//Sleep(60 * 60 * 1000 * 24);
}

static BOOL init( const char *argv0 )
{
    char *p;

    if (!GetCurrentDirectoryA(sizeof(base), base))
        return FALSE;
    strcpy(selfname, argv0);

    /* Strip the path of selfname */
    if ((p = strrchr(selfname, '\\')) != NULL)
        exename = p + 1;
    else
        exename = selfname;

    if ((p = strrchr(exename, '/')) != NULL)
        exename = p + 1;

    return TRUE;
}

static void show_usage(int argc, const char *argv[])
{
    int i;
    trace("USAGE: %s %s [options] [migrate <proc_num> <seed>]\n"
                    "  --dur  <n>  Duration in miliseconds (instead of iterations)\n"
                    "  --iter <n>  Number of iterations (instead of duration)\n"
                    "  --seed <n>  32 bit unsigned seed\n"
            , argv[0], argv[1]);
    trace("\ngot args[] = {");
    for (i = 1; i < argc; ++i)
        trace("%s\"%s\"", (i == 1 ? "" : ", "), argv[i]);
    trace("}\n");
    exit(-1);
}

START_TEST(semaphore)
{
    const char **argv;
    int argc = winetest_get_mainargs( (char ***)&argv );
    unsigned i;

    if (!init( argv[0] ))
    {
        trace("init failed\n");
        return;
    }

    for (i = 2; i < argc; ++i)
    {
        if (!strcmp(argv[i], "--dur"))
        {
            if (++i >= argc)
                show_usage(argc, argv);

            params.duration   = atoi(argv[i]);
            params.iterations = 0;
        }
        if (!strcmp(argv[i], "--iter"))
        {
            if (++i >= argc)
                show_usage(argc, argv);

            params.iterations = atoi(argv[i]);
            params.duration   = 0;
        }
        else if (!strcmp(argv[i], "--seed"))
        {
            if (++i >= argc)
                show_usage(argc, argv);

            params.seed = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "migrate"))
        {
            if (++i + 2 >= argc)
                show_usage(argc, argv);

            test_migrate_process(argc - i, &argv[i]);
            return;
        }
        else
            show_usage(argc, argv);
    }
    test_sem_simple_wait();
if (0){
    test_sem_simple_create();
    test_limits();
    test_sem_simple_wait();
    test_sem();
} else
    test_migrate();
}
