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
   Program:     $Id: spoofer_stdio.h,v 1.6 2017/03/09 23:42:00 kkeys Exp $
   Date:        $Date: 2017/03/09 23:42:00 $
   Description: stdio thread safety
****************************************************************************/

#ifndef COMMON_SPOOFER_STDIO_H
#define COMMON_SPOOFER_STDIO_H 1

#include <cstdio>

#ifdef _WIN32
// define a POSIX-compatible flockfile()
#define flockfile(f)    _lock_file(f)
#define funlockfile(f)  _unlock_file(f)
#endif

// RAII-style FILE lock
class FileGuard {
    FileGuard(const FileGuard&) NO_METHOD;
    FileGuard operator=(const FileGuard&) NO_METHOD;
    FILE *f;
public:
    FileGuard(FILE *file) : f(file) { flockfile(f); }
    ~FileGuard() { funlockfile(f); }
};

namespace spoofer_stdio {

int fflush(FILE *f);
int fputc(int c, FILE *f);
int fputs(const char *s, FILE *f);
size_t fwrite(const void *p, size_t sz, size_t n, FILE *f);
int vfprintf(FILE *f, const char *fmt, va_list ap) FORMAT_PRINTF(2, 0);
int vprintf(const char *fmt, va_list ap) FORMAT_PRINTF(1, 0);
int printf(const char *fmt, ...) FORMAT_PRINTF(1, 2);
int fprintf(FILE *f, const char *fmt, ...) FORMAT_PRINTF(2, 3);
int puts(const char *s);
int overwritable_puts(const char *s);

}; // namespace spoofer_stdio

#define fflush(f)            (spoofer_stdio::fflush)(f)
#define fputc(c,f)           (spoofer_stdio::fputc)(c,f)
#define fputs(s,f)           (spoofer_stdio::fputs)(s,f)
#define fwrite(p,sz,n,f)     (spoofer_stdio::fwrite)(p,sz,n,f)
#define vfprintf(f,fmt,ap)   (spoofer_stdio::vfprintf)(f,fmt,ap)
#define vprintf(fmt,ap)      (spoofer_stdio::vprintf)(fmt,ap)
#define fprintf(f,...)       (spoofer_stdio::fprintf)(f,__VA_ARGS__)
#define printf(...)          (spoofer_stdio::printf)(__VA_ARGS__)
#define putc(c, f)           (spoofer_stdio::fputc)(c, f)
#define putchar(c)           (spoofer_stdio::fputc)(c, stdout)
#define puts(s)              (spoofer_stdio::puts)(s)
#define overwritable_puts(s) (spoofer_stdio::overwritable_puts)(s)

#endif // COMMON_SPOOFER_STDIO_H
