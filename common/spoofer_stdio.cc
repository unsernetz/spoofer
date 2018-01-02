/* 
 * Copyright 2016-2017 The Regents of the University of California
 * All rights reserved.
 * 
 * This file is part of Spoofer.
 * 
 * Spoofer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Spoofer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Spoofer.  If not, see <http://www.gnu.org/licenses/>.
 */

/****************************************************************************
   Program:     $Id: spoofer_stdio.cc,v 1.3 2017/03/09 23:41:59 kkeys Exp $
   Date:        $Date: 2017/03/09 23:41:59 $
   Description: stdio thread safety
****************************************************************************/

#include <stdarg.h>
#include "port.h"
#include "spoofer_stdio.h"

namespace spoofer_stdio {

#ifdef _WIN32
 // Windows stdio functions are not atomic, so we wrap them with FileGuard.
 #define WindowsFileGuard(f)  FileGuard fileguard(f)
#else
 #define WindowsFileGuard(f)  /* empty */
#endif

static bool last_line_of_stdout_is_overwritable = false;

static inline void start_normal_output(FILE *f) {
    if (f == stdout) {
	// If last line was overwritable, we need a newline now.
	if (last_line_of_stdout_is_overwritable) (std::putc)('\n', f);
	last_line_of_stdout_is_overwritable=false;
    }
}

int (fflush)(FILE *f)
{
    WindowsFileGuard(f);
    start_normal_output(f);
    return (std::fflush)(f);
}

int (fputc)(int c, FILE *f)
{
    WindowsFileGuard(f);
    start_normal_output(f);
    return (std::fputc)(c, f);
}

int (fputs)(const char *s, FILE *f)
{
    WindowsFileGuard(f);
    start_normal_output(f);
    return (std::fputs)(s, f);
}

int (puts)(const char *s)
{
    WindowsFileGuard(stdout);
    start_normal_output(stdout);
    return (std::puts)(s);
}

size_t (fwrite)(const void *p, size_t sz, size_t n, FILE *f)
{
    WindowsFileGuard(f);
    start_normal_output(f);
    return (std::fwrite)(p, sz, n, f);
}

int (vfprintf)(FILE *f, const char *fmt, va_list ap)
{
    WindowsFileGuard(f);
    start_normal_output(f);
    return (std::vfprintf)(f, fmt, ap);
}

int (vprintf)(const char *fmt, va_list ap)
{
    return (spoofer_stdio::vfprintf)(stdout, fmt, ap);
}

int (fprintf)(FILE *f, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = (spoofer_stdio::vfprintf)(f, fmt, ap);
    va_end(ap);
    return r;
}

int (printf)(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int r = (spoofer_stdio::vfprintf)(stdout, fmt, ap);
    va_end(ap);
    return r;
}

// When one overwritable line follows another, the second overwrites the
// first.
int (overwritable_puts)(const char *s)
{
    FileGuard fileguard(stdout); // all platforms, not just Windows
    if ((std::fputs)(s, stdout) == EOF) return EOF;
    if ((std::fputc)('\r', stdout) == EOF) return EOF;
    last_line_of_stdout_is_overwritable = true;
    return 1;
}

}; // namespace spoofer_stdio
