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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "pretty_dump.h"

void dump_init( struct dump *dump, char *buf, size_t buf_size, const char *indent, unsigned indent_chars_per_level)
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
        indent_chars_per_level
    };

    memcpy( dump, &prototype, sizeof(*dump));
}

const char *dump_printf( struct dump *dump, const char *format, ...)
{
    int count;
    va_list args;

    if (dump->start >= dump->end)
    {
        fprintf(stderr, "%s: output buffer full\n", __func__);
        return dump->buffer;
    }

    va_start(args, format);
    count = vsnprintf(dump->start, dump->end - dump->start, format, args);
    va_end(args);

    if (count < 0)
        perror("vsnprintf");
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
