/*
 * A pretty C object/struct dumper
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

#ifndef _PRETTY_DUMP_H
#define _PRETTY_DUMP_H


struct dump {
    char             *start;            /* next write location */
    const char *const end;              /* one byte past end of buffer */
    const char       *indent;           /* next indention string to use */

    /* private data members */
    char       *const buffer;           /* output buffer */
    const char *const indent_str;       /* the full null-terimated max indention string */
    const char *const indent_end;       /* end of indent string (null pointer) */
    const unsigned    chars_per_level;  /* number of indent chars per level */
};

extern void dump_init( struct dump *dump, char *buf, size_t buf_size, const char *indent, unsigned chars_per_level);
extern const char *dump_printf( struct dump *dest, const char *format, ...) __attribute__((format (printf, 2, 3)));
extern const char *dump_indent_inc( struct dump *dump );
extern const char *dump_indent_dec( struct dump *dump );

static inline const char *dump_indent( struct dump *dump )
{
    return dump->indent;
}

static inline void dump_reset( struct dump *dump )
{
    dump->start  = dump->buffer;
    dump->indent = dump->indent_end;
}

#endif /* _PRETTY_DUMP_H */
