/*
 * A pretty C object/struct dumper with object hierarchy support (dump)
 * and a wierd stack-backtracing logger (tracer).
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <execinfo.h>
#include <limits.h>

#include "wine/list.h"
#include "wine/pretty_dump.h"

static struct dump default_dump;

/************************************************************************************************
 *              Tracer
 */

static inline ssize_t tracer_room( struct tracer *tracer )
{
    return (char*)tracer->trace_next - (char*)tracer->str_next;
}

struct tracer *tracer_alloc( unsigned short max_backtraces, unsigned char max_frames,
                             unsigned int memory_size, FILE *out )
{
    const unsigned int MEMORY_SIZE_MASK = 0xfff;
    struct tracer *tracer;
    size_t backtrace_size        = sizeof(*tracer->backtrace_buffer) * max_frames;
    size_t backtrace_index_size  = sizeof(*tracer->backtrace_index) * max_backtraces;
    size_t min_obj_size          = sizeof(struct tracer) + backtrace_index_size
                                   + backtrace_size * (max_backtraces + 2);

    assert(sizeof(long) == sizeof(void*));

    if (memory_size < min_obj_size + 0x400)
    {
        fprintf(stderr, "memory_size = %u is too small\n", memory_size);
        return NULL;
    }

    /* Then round it up anyway. */
    memory_size = (memory_size + MEMORY_SIZE_MASK) & ~MEMORY_SIZE_MASK;

    if (!(tracer = malloc(memory_size)))
        return NULL;

    tracer->object_size           = memory_size;
    tracer->out                   = out;
    tracer->max_backtraces        = max_backtraces;
    tracer->max_frames            = max_frames;
    tracer->backtrace_count       = 0;
    tracer->backtraces            = &tracer->backtrace_buffer[max_frames + 2];
    tracer->backtrace_index       = (void*)&tracer->backtraces[max_frames * max_backtraces];
    tracer->str_start             = (void*)&tracer->backtrace_index[max_backtraces];
    tracer->str_next              = tracer->str_start;
    tracer->trace_start           = (void*)((char*)tracer + memory_size - sizeof(struct trace_point));
    tracer->trace_next            = tracer->trace_start;

    /* We need to zero these since we'll lazily populate them (i.e., leave NULL pointers once we
     * reach the first function address) */
    memset( tracer->backtraces, 0, tracer->str_start - (char*)tracer->backtrace_buffer );
    assert( tracer_room(tracer) > 0 );

    return tracer;
}

/* We want these functions optimized, even in a debug build. */
#pragma GCC push_options
#pragma GCC optimize ("-O2")
static inline int backtrace_search_compare( const void *_a, const void *_b )
{
    const struct tracer *tracer = LIST_ENTRY( _a, const struct tracer, backtrace_buffer );
    const long *a = _a;
    const long *b = &tracer->backtraces[tracer->max_frames * (*(const unsigned short *)_b)];
    unsigned char i;

    ++a; /* skip tracer_do frame */
    for (i = 0; i < tracer->max_frames; ++i)
    {
        long diff = a[i] - b[i];

        if (diff > 0)
            return 1;
        else if (diff < 0)
            return -1;
        else if (a == NULL)
            return 0;
    }
    return 0;
}

static inline int backtrace_sort_compare( const void *_a, const void *_b, void *arg )
{
    const struct tracer *tracer = arg;
    const long *a = &tracer->backtraces[tracer->max_frames * (*(const unsigned short *)_a)];
    const long *b = &tracer->backtraces[tracer->max_frames * (*(const unsigned short *)_b)];
    unsigned char i;

    for (i = 0; i < tracer->max_frames; ++i)
    {
        long diff = a[i] - b[i];

        if (diff > 0)
            return 1;
        else if (diff < 0)
            return -1;
        else if (a == NULL)
            return 0;
    }
    return 0;
}

static unsigned short get_backtrace_index(struct tracer *tracer)
{
    unsigned short *index;
    long *next_entry;
    int i;

    index = bsearch( tracer->backtrace_buffer, tracer->backtrace_index, tracer->backtrace_count,
                     sizeof(*tracer->backtrace_index), backtrace_search_compare );

    if (index)
        return *index;

    if (tracer->backtrace_count == tracer->max_backtraces)
        return USHRT_MAX;

    next_entry = &tracer->backtraces[tracer->max_frames * tracer->backtrace_count];

    for (i = 0; i < tracer->max_frames && tracer->backtrace_buffer[i + 1]; ++i)
        next_entry[i] = tracer->backtrace_buffer[i + 1];

    tracer->backtrace_index[tracer->backtrace_count] = tracer->backtrace_count;
    qsort_r( tracer->backtrace_index, ++tracer->backtrace_count, sizeof(*tracer->backtrace_index),
             backtrace_sort_compare, tracer );

    return tracer->backtrace_count - 1;
}
#if 0
static inline __attribute__((always_inline, optimize("-O2"), format (printf, 2, 3)))
void tracer_do( struct tracer *tracer, const char *format, ... )
{
    va_list args;
    ssize_t room = tracer_room( tracer );

    if (room < 0x20)
        if (__tracer_full( tracer, &room ))
            return;

    va_start( args, format );
    __tracer_do( tracer, vsnprintf( tracer->str_next, (size_t)room, format, args ) );
    va_end( args );
}
#endif

void tracer_do( struct tracer *tracer, const char *format, ... )
{
    va_list args;
    ssize_t room = tracer_room( tracer );
    int num_chars;
    int frames;

    if (room < 0x40)
    {
        tracer_dump( tracer );
        tracer_reset( tracer );
        room = tracer_room( tracer );
    }

    va_start( args, format );
    num_chars = vsnprintf( tracer->str_next, (size_t)room, format, args );
    va_end( args );

    //assert(max_backtraces * max_frames);
    if (num_chars < 0)
    {
        perror( "vsnprintf" );
        return;
    }

    tracer->trace_next->str = tracer->str_next - tracer->str_start;
    tracer->str_next += num_chars + 1;

    frames = backtrace( (void**)tracer->backtrace_buffer, tracer->max_frames + 1 );
    if (frames < tracer->max_frames)
        tracer->backtrace_buffer[frames] = 0l;

    tracer->trace_next->backtrace = get_backtrace_index( tracer );
    --tracer->trace_next;
}

void tracer_dump( struct tracer *tracer )
{
    char **symbols;
    struct trace_point *p;
    int i, j;

    fprintf( tracer->out, "tracer_dump begin ------------>\n"
                          "    .backtrace_count = %u\n"
                          "    text chars       = %zu\n"
                          "    entries          = %zu\n",
                          tracer->backtrace_count,
                          tracer->str_next - tracer->str_start,
                          tracer->trace_start - tracer->trace_next );

    symbols = backtrace_symbols( (void**)tracer->backtraces, tracer->backtrace_count
                                                             * tracer->max_frames );
    if (!symbols)
        perror( "backtrace_symbols" );

    for (i = 0; i < tracer->backtrace_count; ++i)
    {
        size_t offset = i * tracer->max_frames;

        fprintf( tracer->out, "backtrace[%u]:\n", i );
        for (j = 0; j < tracer->max_frames && tracer->backtraces[offset + j] ; ++j)
            fprintf( tracer->out, "    %s\n", symbols[offset + j] );
    }


    for (p = tracer->trace_start; p != tracer->trace_next; --p)
    {
//        size_t offset = p->backtrace * tracer->max_frames;

        fprintf( tracer->out, "%3u %s", p->backtrace, tracer->str_start + p->str );
#if 0
        fputs( tracer->str_start + p->str, tracer->out );
        fputs( ": ",tracer->out );
        for (i = 0; i < tracer->max_frames && tracer->backtraces[offset + i] ; ++i)
            fprintf( tracer->out, "%s%s", i ? " -> " : "", symbols[offset + i] );
        fputs( "\n", tracer->out );
#endif
    }

    fprintf( tracer->out, "<------------ tracer_dump end\n" );
}

void tracer_reset( struct tracer *tracer )
{
    tracer->backtrace_count = 0;
    tracer->str_next        = tracer->str_start;
    tracer->trace_next      = tracer->trace_start;
    memset( tracer->backtraces, 0, sizeof(*tracer->backtraces) * tracer->max_frames );
}
#pragma GCC pop_options


/************************************************************************************************
 *              Dumpper
 */

void dump_init( struct dump *dump, char *buf, size_t buf_size, const char *indent,
                unsigned indent_chars_per_level )
{
    const char *indent_end = indent + strlen(indent);

    struct dump prototype =
    {
        buf,
        buf + buf_size,
        indent_end,
        buf,
        indent,
        indent_end,
        indent_chars_per_level,
	!buf
    };

    memcpy( dump, &prototype, sizeof(*dump) );
}

const char *dump_printf( struct dump *dump, const char *format, ... )
{
    int count;
    va_list args;

    if (dump->start >= dump->end)
    {
        fprintf( stderr, "%s: output buffer full\n", __func__ );
        return dump->buffer;
    }

    va_start( args, format );
    count = vsnprintf( dump->start, dump->end - dump->start, format, args );
    va_end( args );

    if (count < 0)
        perror( "vsnprintf" );
    else
        dump->start += count;

    return dump->buffer;
}

const char *dump_indent_inc( struct dump *dump )
{
    dump->indent -= dump->chars_per_level;

    if (dump->indent < dump->indent_str)
        dump->indent = dump->indent_str;

    return dump->indent;
}

const char *dump_indent_dec( struct dump *dump )
{
    dump->indent += dump->chars_per_level;

    if (dump->indent > dump->indent_end)
        dump->indent = dump->indent_end;

    return dump->indent;
}

static struct dump *get_default_dump (void)
{
    if (!default_dump.buffer)
    {
	const size_t buf_size = 0x10000;
	void *buffer = malloc( buf_size );
	const char *indent_str = "                                                ";

	if (!buffer)
	{
	    errno = ENOMEM;
	    perror ( "Failed to allocate default_dump buffer." );
	    exit (-1);
	}
	dump_init( &default_dump, buffer, buf_size, indent_str, 2 );
    }

    return &default_dump;
}

void dump_obj( struct dump *dump, const void *obj, dumpfn fn )
{
    char *start;
    if (!dump)
	dump = get_default_dump();

    dump_reset( dump );
    start = dump->start;
    fn( obj, &start, dump->end );
    fputs( dump->start, stderr );
}
