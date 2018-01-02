dnl 
dnl Copyright 2017 The Regents of the University of California
dnl All rights reserved.
dnl 
dnl This file is part of Spoofer.
dnl 
dnl Spoofer is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl 
dnl Spoofer is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with Spoofer.  If not, see <http://www.gnu.org/licenses/>.
dnl 

dnl SPF_SEARCH_LIBS(function, pcmodule, search-libs, [action-if-found],
dnl     [action-if-not-found], [other-libs])
dnl Like AC_SEARCH_LIBS, but checks for pkg-config $pcmodule before trying
dnl $search-libs.  If function is found in $pcmodule, this macro adds necessary
dnl flags to CPPFLAGS and LDFLAGS as well as LIBS.

AC_DEFUN([SPF_SEARCH_LIBS], [
    dnl First look in pkg-config
    AC_REQUIRE([PKG_PROG_PKG_CONFIG])
    AC_MSG_CHECKING([for $1 in pkg-config $2])
    unset ac_cv_search_$1
    if $($PKG_CONFIG '$2' --exists 2>/dev/null); then
	spf_search_libs_save_CPPFLAGS="$CPPFLAGS"
	spf_search_libs_save_LDFLAGS="$LDFLAGS"
	spf_search_libs_save_LIBS="$LIBS"
	CPPFLAGS="$CPPFLAGS $($PKG_CONFIG '$2' --cflags)"
	LDFLAGS="$LDFLAGS $($PKG_CONFIG '$2' --libs-only-L --libs-only-other)"
	LIBS="$($PKG_CONFIG '$2' --libs-only-l) $LIBS"
	exec AS_MESSAGE_FD>/dev/null;  # suppress output from AC_SEARCH_LIBS
	AC_SEARCH_LIBS($1, , , 
	    [
		unset ac_cv_search_$1
		CPPFLAGS="$spf_search_libs_save_CPPFLAGS"
		LDFLAGS="$spf_search_libs_save_LDFLAGS"
		LIBS="$spf_search_libs_save_LIBS"
	    ], $6)
	test "$silent" != yes && exec AS_MESSAGE_FD>&1; # resume output
    fi

    if test -n "$ac_cv_search_$1"; then
	AC_MSG_RESULT([yes ($($PKG_CONFIG '$2' --modversion))])
	$4
    else
	AC_MSG_RESULT([no])
	AC_SEARCH_LIBS($1, $3, $4, $5, $6)
    fi
])


