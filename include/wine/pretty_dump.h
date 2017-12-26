/*
 * A pretty C object/struct dumper with object hierarchy support (struct dump)
 * and a wierd stack-backtracing logger (struct tracer).
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

#ifndef _WINE_PRETTY_DUMP_H
#define _WINE_PRETTY_DUMP_H

struct trace_point {
    int            str;
    unsigned short backtrace;
};

/* A virtually undocumented mechanism that I've mostly forgotten about. :o I think it's a high-
 * performance logging aparatis that saves the backtrace of each call to tracer_do and only
 * resolves the symbols and dumps the backtraces when the program terminates or its buffer
 * fills up, so it might break if libraries are dynamically unloaded. */
struct tracer {
    unsigned int        object_size;
    FILE               *out;
    unsigned short      max_backtraces;
    unsigned char       max_frames;
    unsigned short      backtrace_count;
    long               *backtraces;
    unsigned short     *backtrace_index;
    char               *str_start;
    char               *str_next;
    struct trace_point *trace_start;
    struct trace_point *trace_next;
    long                backtrace_buffer[1];
};

extern struct tracer *tracer_alloc( unsigned short max_backtraces, unsigned char max_frames,
                                    unsigned int memory_size, FILE *out );
extern void tracer_do( struct tracer *tracer, const char *fmt, ... );
extern void tracer_dump( struct tracer *tracer );
extern void tracer_reset( struct tracer *tracer );

struct dump {
    char             *start;            /* next write location */
    const char *const end;              /* one byte past end of buffer */
    const char       *indent;           /* next indention string to use */

    /* private data members */
    char       *const buffer;           /* output buffer */
    const char *const indent_str;       /* the full null-terimated max indention string */
    const char *const indent_end;       /* end of indent string (pointer to the null byte) */
    const unsigned    chars_per_level;  /* number of indent chars per level */
    int		      own_buffer;	/* buffer was allocated in init. */
};

typedef void (*dumpfn)( const void *obj, char **start, const char *const end );

extern void dump_init( struct dump *dump, char *buf, size_t buf_size, const char *indent,
                       unsigned chars_per_level );
extern const char *dump_printf( struct dump *dest, const char *format, ... )
                                                            __attribute__((format (printf, 2, 3)));
extern const char *dump_indent_inc( struct dump *dump );
extern const char *dump_indent_dec( struct dump *dump );
extern void dump_obj( struct dump *dump, const void *obj, dumpfn fn );

static inline const char *dump_indent( struct dump *dump )
{
    return dump->indent;
}

static inline void dump_reset( struct dump *dump )
{
    dump->start  = dump->buffer;
    dump->indent = dump->indent_end;
}

#endif /* _WINE_PRETTY_DUMP_H */
