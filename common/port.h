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
   Program:     $Id: port.h,v 1.11 2017/11/17 22:09:17 kkeys Exp $
   Date:        $Date: 2017/11/17 22:09:17 $
   Description: general portability.  This file should be #included after
                system headers and headers of other packages we depend on,
                but before spoofer headers.
****************************************************************************/

#ifndef COMMON_PORT_H
#define COMMON_PORT_H 1

#ifdef __cplusplus
# include <cstddef>
# if __cplusplus >= 201103L // C++11
#  define NO_METHOD = delete
# else // pre C++11
#  ifndef nullptr
    class NULLPTR_T {
	// Like nullptr in C++11, this is convertable to any type of null
	// pointer, but NOT to an integer.  So, e.g., with overloads f(int)
	// and f(char*), calling f(nullptr) will correctly choose the latter.
    public:
	NULLPTR_T() {} // C++03 std (and some compilers) requires this
	template<class T> operator T*() const { return static_cast<T*>(0); }
	template<class C, class T> operator T C::*() const { return static_cast<T*>(0); }
    };
    static const NULLPTR_T nullptr;
#  endif // nullptr
#  define NO_METHOD /* declaration prevents compiler-generated default definition */
# endif // pre-C++11
#endif

// usage:  NORETURN static funcname(...)
#if __cplusplus >= 201103L // C++11
# define NORETURN                 [[noreturn]]
#elif defined(__GNUC__)
# define NORETURN                 __attribute__((__noreturn__))
#else
# define NORETURN                 /* empty */
#endif

#if __cplusplus >= 201700L // C++17
# define ATR_UNUSED               [[maybe_unused]]
#elif defined(__GNUC__)
# define ATR_UNUSED               __attribute__((__unused__))
#else
# define ATR_UNUSED               /* empty */
#endif

#if __cplusplus >= 201700L // C++17
# define ATR_UNUSED_MEMBER        [[maybe_unused]]
#elif defined(__clang__)
# define ATR_UNUSED_MEMBER        __attribute__((__unused__))
#else
# define ATR_UNUSED_MEMBER        /* empty */
#endif

// ATR_PURE: func has no side effcts, depends only on params or global variables
// ATR_CONST: func has no side effcts, depends only on params
// ATR_USED: var must be emitted even if it appears to be unused
// ATR_NONNULL: pointer parameters of function can not be null
#ifdef __GNUC__
# define ATR_USED                 __attribute__((__used__))
# define ATR_PURE                 __attribute__((__pure__))
# define ATR_CONST                __attribute__((__const__))
# define ATR_NONNULL(args)        __attribute__((__nonnull__ args))
# if !defined(__clang__) && __GNUC__ == 5 && __GNUC_MINOR__ == 1
   // silence -Wsuggest-attribute=format in gcc 5.1
#  define FORMAT_PRINTF(fmt, var) __attribute__((__format__(gnu_printf, fmt, var)))
# elif defined(_WIN32) && defined(__GNUC__)
   // mingw g++ thinks printf doesn't allow "z" width modifier, but it does
#  define FORMAT_PRINTF(fmt, var) __attribute__((__format__(gnu_printf, fmt, var)))
# else
   // prefer warnings for standard printf format
#  define FORMAT_PRINTF(fmt, var) __attribute__((__format__(printf, fmt, var)))
# endif
#else
# define ATR_USED                 /* empty */
# define ATR_PURE                 /* empty */
# define ATR_CONST                /* empty */
# define ATR_NONNULL(args)        /* empty */
# define FORMAT_PRINTF(fmt, var)  /* empty */
#endif

// Similar to static_assert(cond, msg), but doesn't require C++11, and tag
// must be a valid identifier, not a string.  Works by causing a compile-time
// divide-by-zero error if cond is false.
#define STATIC_ASSERT(cond, tag)  enum { assertion_failure__ ## tag = 1/(cond) }

// Rather than create a whole new header just to define PROGRESS_PREFIX, we
// shove it in here in the only file included by all code.
#define PROGRESS_PREFIX ">> [success+fail/tries/goal]:"

#endif // COMMON_PORT_H
