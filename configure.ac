## 
## Copyright 2004-2009 Rob Beverly
## Copyright 2015-2017 The Regents of the University of California
## All rights reserved.
## 
## This file is part of Spoofer.
## 
## Spoofer is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## 
## Spoofer is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
## 
## You should have received a copy of the GNU General Public License
## along with Spoofer.  If not, see <http://www.gnu.org/licenses/>.
## 

#
# $Id: configure.ac,v 1.170 2017/12/09 00:03:24 kkeys Exp $
#

# SUBST_NSIS(variable, value)
# Like AC_SUBST(<variable>, <value>), but also creates a <variable>_NSIS whose
# value is properly quoted for NSIS (and will not be defined as a make
# variable).
m4_define([SUBST_NSIS], [
AC_SUBST([$1], $2)
AC_SUBST([$1_NSIS], patsubst($2, ['], [$\\']))  dnl '
AM_SUBST_NOTMAKE([$1_NSIS])
])

# The version below is that of the prober.
AC_INIT([Spoofer], [1.3.1], [spoofer-info@caida.org], [spoofer], [http://spoofer.caida.org/])
AC_CONFIG_SRCDIR([prober/spoofer-prober.cc])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([-Wall foreign])
# Copyright for this configure script
AC_COPYRIGHT([Copyright 2004-2012 Robert Beverly
Copyright 2015-2017 The Regents of the University of California])
AC_CONFIG_HEADERS([config.h])
AC_DEFINE(VERSION, [131], [version of prober-server protocol])

AC_SUBST(ORG_NAME, "CAIDA")
AC_SUBST(ORG_DOMAIN, "caida.org")
AC_SUBST(ORG_DOMAIN_REVERSED, "org.caida")
AC_SUBST(PACKAGE_DESC, "CAIDA IP Spoofing Tester client")
SUBST_NSIS(PACKAGE_LONGDESC, "The spoofer client is part of a system to measure the Internet's resistance to packets with a spoofed (forged) source IP address.")
# Copyright for Spoofer.  Semicolon may be converted to newline by some uses.
AC_SUBST(COPYRIGHT, "Copyright 2004-2009 Rob Beverly; Copyright 2015-2017 The Regents of the University of California")
AC_SUBST(PRODUCT_VERSION, "1.3.1.0")  dnl for NSIS installer

AC_SUBST(DESC_SHARE_PUBLIC, "Allow anonymized test results to be shared publicly")
AC_SUBST(DESC_SHARE_REMEDY, "Allow unanonymized test results to be shared for remediation")



AC_DEFINE_UNQUOTED(ORG_NAME, ["$ORG_NAME"], [Organization name])
AC_DEFINE_UNQUOTED(ORG_DOMAIN, ["$ORG_DOMAIN"], [Organization domain name])
AC_DEFINE_UNQUOTED(ORG_DOMAIN_REVERSED, ["$ORG_DOMAIN_REVERSED"], [Organization domain name, reversed])
AC_DEFINE_UNQUOTED(PACKAGE_DESC, ["$PACKAGE_DESC"], [Short package description])
AC_DEFINE_UNQUOTED(PACKAGE_LONGDESC, ["$PACKAGE_LONGDESC"], [Longer package description])
AC_DEFINE_UNQUOTED(COPYRIGHT, ["$COPYRIGHT"], [Copyright notice])

AC_DEFINE_UNQUOTED(DESC_SHARE_PUBLIC, ["$DESC_SHARE_PUBLIC"], [Description of share_public option])
AC_DEFINE_UNQUOTED(DESC_SHARE_REMEDY, ["$DESC_SHARE_REMEDY"], [Description of share_remedy option])

AC_SUBST(WIN_INSTALLER, "${PACKAGE_NAME}-${PACKAGE_VERSION}-win32.exe")
AC_SUBST(MAC_INSTALLER, "${PACKAGE_NAME}-${PACKAGE_VERSION}-macosx.pkg")

AC_SUBST(WINPCAP_INSTALLER, "WinPcap_4_1_3.exe")
AC_SUBST(WINPCAP_VERSION, "4.1.3")

AC_SUBST(MSVCR_INSTALLER, "vc2012u4redist_x86.exe")
AC_SUBST(MSVCR_REGKEY, "SOFTWARE\Classes\Installer\Dependencies\{33d1fd90-4274-48a1-9bc1-97e33d9c2d6f}")

# test for files during autoconf
syscmd([test ! -f server/Makefile.am])
m4_define([Have_Server], sysval)

m4_include([m4/spf_search_libs.m4]) dnl

# Test for C++ compiler.
# Notes on AC_PROG_CXX:
# 1) it will not work inside a shell condition
# 2) when the argument is a shell variable, it is not empty at autoconf
#    time, so the macro won't fall back to its full default list
# 3) its last-ditch default of "g++" will not be tested for cross-compiling
#    prefix
CXX_CANDIDATES='g++ c++ gpp aCC CC cxx cc++ cl.exe FCC KCC RCC xlC_r xlC'
#              ^^^ that's the default list in autoconf 2.68.
case $host_os in
freebsd*|darwin*)
    # FreeBSD and OSX have standardized on clang++/libc++, which is
    # ABI-incompatible with g++/libstdc++.  We prefer clang++ under the
    # assumption that it was used to build other libraries we need to link
    # with.  (This will be true for anything installed via the platform's
    # package system, but maybe not for anything installed manually.)
    CXX_CANDIDATES="clang++ $CXX_CANDIDATES";;
esac
AC_PROG_CXX($CXX_CANDIDATES)
m4_include([m4/ax_cxx_compile_stdcxx.m4]) dnl
AX_CXX_COMPILE_STDCXX(14, , optional) dnl Prefer C++14 if available
if test "$HAVE_CXX14" != "1"; then
    AX_CXX_COMPILE_STDCXX(11) dnl Require at least C++11
fi
AC_LANG([C++])

CC="$CXX"; # Make AX_PTHREAD use our chosen C++ compiler.
AX_PTHREAD()

# Checks for other programs.
AC_PROG_CPP
AC_PROG_RANLIB
AM_PROG_AR
AC_PROG_MKDIR_P
AC_CHECK_TOOL(STRIP, [strip], [:])

# On some platforms, qmake is actually qtchooser, which chooses between Qt4
# and Qt5 versions of qmake based on $QT_SELECT.
: ${QT_SELECT:=5}
export QT_SELECT
AC_SUBST(QT_SELECT)
AC_CHECK_TOOLS(QMAKE, [qmake qmake-qt5])
AC_ARG_VAR(QMAKE, [Qt makefile creator])

AC_CHECK_TOOLS(PROTOC, [protoc])
AC_ARG_VAR(PROTOC, [Google Protobuf compiler])
if test "$PROTOC" = ""; then
    AC_MSG_ERROR([can not find protoc])
fi

# Define OS -- it's sent in prober's message to server for stats keeping
AC_MSG_RESULT(Determined host operating system: $host_os)
case $host_os in
*linux*)
    AC_DEFINE(OS,"LINUX",[Operating System String])
    ;;
*bsd*)
    AC_DEFINE(OS,"BSD",[Operating System String])
    AC_DEFINE(_BSD,1,[Define to 1 if a BSD-like operating system])
    ;;
*darwin*)
    AC_DEFINE(OS,"OSX",[Operating System String])
    AC_DEFINE(_BSD,1,[Define to 1 if a BSD-like operating system])
    AC_DEFINE(_OSX,1,[Define to 1 if an Apple OSX operating system])
    MACOS_VERSION="$(sw_vers -productVersion)"
    set ${MACOS_VERSION//\./ }
    MACOS_VERSION="$1.$2"
    define(DEV_MACOSX_DEPLOYMENT_TARGET, [10.7])
    AC_ARG_VAR(MACOSX_DEPLOYMENT_TARGET, [On Mac OSX: the earliest OSX version to support.  (Libraries must also be built with this.)])
    ;;
*solaris*)
    AC_DEFINE(OS,"SOLARIS",[Operating System String])
    ;;
*mingw32*)
    AC_DEFINE(OS,"WIN32",[Operating System String])
    AC_DEFINE(_WIN32,1,[Define to 1 if a Windows operating system])
    CPPFLAGS="-D_WIN32_WINNT=0x0600"; # require Vista or later
    ;;
*)
    AC_DEFINE(OS,"UNDEF",[Operating System String])
    ;;
esac

dnl Prober is enabled by default.  If Have_Server, user can disable prober.
dnl (Building without server OR prober would be pointless.)
ifelse(Have_Server, [1], [
    AC_ARG_ENABLE(prober,
	[AS_HELP_STRING([--disable-prober], [Do not build spoofer prober])],,
	[enable_prober=yes])
    ],
    [enable_prober=yes])

AC_ARG_ENABLE(manager,
    [AS_HELP_STRING([--disable-manager], [Do not build spoofer prober manager])],,
    [enable_manager=default])

dnl Server is disabled by default.  If Have_Server, user can enable server.
ifelse(Have_Server, [1], [
    AC_ARG_ENABLE([server], 
	[AS_HELP_STRING([--enable-server], [Build spoofer server])],,
	[enable_server=no])
    ],
    [enable_server=no])

AC_ARG_WITH(protobuf,
    [AS_HELP_STRING([--with-protobuf=DIR],
	[Directory prefix for Google Protobuf headers and libraries (default is computed from $PROTOC; use this to give an alternate value when cross compiling.)])],
    [], [with_protobuf=""])

AC_ARG_WITH(pcap,
    [AS_HELP_STRING([--with-pcap=DIR],
	[Windows: look for WinPcap Developer Pack in DIR])], [], [with_pcap="yes"])
AC_ARG_WITH(pcap,
    [AS_HELP_STRING([--without-pcap],
	[build without pcap library (and disable IPv6 probing)])], [], [with_pcap="yes"])

AC_ARG_WITH(scamper,
    [AS_HELP_STRING([--with-scamper=PATH],
	[Prober should look for scamper executable at PATH before looking in default locations])],
    [], [with_scamper=""])
AC_ARG_WITH(scamper,
    [AS_HELP_STRING([--without-scamper],
	[Prober should not try to use scamper, only traceroute])],
    [], [with_scamper=""])

ifelse(Have_Server, [1], [
    AC_ARG_WITH(mysql,
	[AS_HELP_STRING([--with-mysql=DIR], [base path for MySQL headers and libraries (for server)])],,
	[with_mysql=''])
    ])

default_dev="no"
if test -d $srcdir/CVS; then
    default_dev="yes"
else
    case "$PACKAGE_VERSION" in
    *alpha*) default_dev="yes";;
    esac
fi

AC_ARG_ENABLE([development], 
    [AS_HELP_STRING([--enable-development], [Enable development mode])],,
    [enable_dev="$default_dev" ])

AC_ARG_ENABLE([extra_warnings], 
    [AS_HELP_STRING([--enable-extra-warnings], [Enable extra warnings in development mode])],,
    [enable_extra_warnings="no" ])


if test "$enable_manager" != "no"; then
    if test "$enable_prober" = "no"; then
	test "$enable_manager" = "yes" &&
	    AC_MSG_ERROR([can not build manager without prober])
	enable_manager="no (because prober was disabled)"
    elif test -z "${QMAKE}"; then
	test "$enable_manager" = "yes" &&
	    AC_MSG_ERROR([can not build manager: qmake was not found])
	enable_manager="no (because qmake was not found)"
    else
	enable_manager=yes
    fi
fi

case $host_os in
*darwin*)
    : ${MACOSX_DEPLOYMENT_TARGET:=$MACOS_VERSION}
    AC_MSG_RESULT(MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET})
    AC_SUBST(MACOSX_DEPLOYMENT_TARGET)
    ;;
esac

case $host_os in
*mingw32*)
    if test "$with_pcap" = "yes"; then
	for d in "WpdPack" "$HOME/packages/WpdPack"; do
	    if test -d "$d"; then
		with_pcap="$d"
		break
	    fi
	done
    fi
    ;;
esac

if test "x$with_pcap" != "xno" && test "x$with_pcap" != "xyes"; then
   CPPFLAGS="${CPPFLAGS} -I${with_pcap}/Include"
   LDFLAGS="${LDFLAGS} -L${with_pcap}/Lib"
fi

QT_INCLUDE_FLAGS=""
if test "$enable_dev" = "yes" && test -n "$QMAKE" && test "$GXX" = "yes"; then
    # suppress warnings in Qt headers
    QT_HEADER_DIR=$(${QMAKE} -query QT_INSTALL_HEADERS)
    QT_INCLUDE_FLAGS="-isystem \"${QT_HEADER_DIR}\" -isystem \"${QT_HEADER_DIR}/QtNetwork\" -isystem \"${QT_HEADER_DIR}/QtWidgets\" -isystem \"${QT_HEADER_DIR}/QtGui\" -isystem \"${QT_HEADER_DIR}/QtCore\""
fi
AC_SUBST(QT_INCLUDE_FLAGS)


if test "x$with_scamper" = "xno"; then
  AC_DEFINE(SCAMPER_DISABLED,[1],[Define to not use scamper.])
elif test "x$with_scamper" != "xyes"; then
  AC_DEFINE_UNQUOTED(SCAMPER_PATH,["$with_scamper"],[Path of additional scamper executable.])
fi


# Checks for libraries.

case $host_os in
*mingw32*)
    # Replace MingW's default MSVCRT.DLL (from VC++ 6.0 (1998)) with
    # MSVCR110.DLL (from VC++ 11.0 (2012)), since the former does not follow
    # the C99 standard; in particular, stdio is not atomic.  NB: this will
    # require us to include "Microsoft Visual C++ 2012 Redistributable
    # Package" with our binary installer.
    specdir=$(cd "$srcdir" && pwd)
    CXXFLAGS="$CXXFLAGS -specs=$specdir/mingw-gcc-msvcr110.specs"
    # Verify it works by calling _lock_file(), which did not exist in msvcrt.
    AC_MSG_CHECKING([that linking with msvcr110 works])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <stdio.h>], [_lock_file(stdout);])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])
	AC_MSG_ERROR([msvcr110 required])])

    # Note: AC_CHECK_LIB([ws2_32], [WSAStartup]) does not always work (e.g., when
    # cross compiling with mingw32); we'd need the correct declaration of
    # WSAStartup from <winsock2.h>, including its WSAAPI calling convention, and
    # then a matching call.  Easier to just check for the library and assume that
    # if it exists it will define everything it should.
    AC_CHECK_LIB([ws2_32], [main])
    ;;
esac

AC_SEARCH_LIBS([socket], [socket])            # UNIX-SysV-like
AC_SEARCH_LIBS([gethostbyname], [nsl])        # Solaris
AC_SEARCH_LIBS([pcap_close], [pcap wpcap],,   # UNIX-like, Windows
    [if test "x$with_pcap" != "xno"; then
	AC_MSG_ERROR(A pcap library is required for IPv6 probing.  Use --without-pcap to force building without pcap.)
    fi])
    dnl note: later code checks for "$ac_cv_search_pcap_close"


# Default location of Protobuf headers and libs is based on location of protoc.
path_of_prog() {
    case "$1" in
    */*) ( cd $(dirname "$1") && pwd; ) ;;
    *) ( IFS=':'; for d in $PATH; do AS_EXECUTABLE_P(["$d/$1"]) && echo "$d" && break; done;) ;;
    esac
}
if test -z "$with_protobuf"; then
    with_protobuf=$(path_of_prog "$PROTOC")
    if test $(basename "$with_protobuf") = "bin"; then
	with_protobuf=$(cd "$with_protobuf/.." && pwd)
    fi
fi
if test -f "$with_protobuf/include/google/protobuf/message_lite.h"; then
    AC_SUBST(PROTOBUFCPPFLAGS, ["-I$with_protobuf/include"])
    AC_SUBST(PROTOBUFLDFLAGS, ["-L$with_protobuf/lib"])
elif test -f "$with_protobuf/google/protobuf/message_lite.h"; then
    AC_SUBST(PROTOBUFCPPFLAGS, ["-I$with_protobuf"])
    AC_SUBST(PROTOBUFLDFLAGS, ["-L$with_protobuf"])
fi

AC_MSG_CHECKING([for protobuf library])
orig_LIBS="$LIBS"
orig_CPPFLAGS="$CPPFLAGS"
orig_LDFLAGS="$LDFLAGS"
CPPFLAGS="$CPPFLAGS $PROTOBUFCPPFLAGS"
LDFLAGS="$LDFLAGS $PROTOBUFLDFLAGS"
PROTOBUFLDADD=""
# we prefer libprotobuf-lite because it's smaller, but libprotobuf also works
for lib in protobuf-lite protobuf; do
    LIBS="-l$lib $orig_LIBS"
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([#include <google/protobuf/message_lite.h>], [google::protobuf::ShutdownProtobufLibrary()])],
      [PROTOBUFLDADD="-l$lib"; AC_MSG_RESULT([$PROTOBUFLDADD]); break])
done
if test -z "$PROTOBUFLDADD"; then
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([protobuf library required])
fi
CPPFLAGS="$orig_CPPFLAGS"
LDFLAGS="$orig_LDFLAGS"
LIBS="$orig_LIBS"
AC_SUBST(PROTOBUFLDADD)
AC_SUBST(PROTOBUF_OPTIONS, ["option optimize_for = LITE_RUNTIME;"])
AM_SUBST_NOTMAKE([PROTOBUF_OPTIONS])

AC_MSG_CHECKING([whether $PROTOC supports "oneof"])
cat >pbtest.proto <<EOF
    syntax = "proto2";
    message Test {
	oneof Union {
	    int32 foo = 1;
	    string bar = 2;
	}
    }
EOF
if "$PROTOC" --proto_path=. --cpp_out=. pbtest.proto >pbtest.log 2>&1; then
    AC_MSG_RESULT([yes])
    AC_SUBST(ONEOF, [])
    AC_SUBST(ONEOF_MEMBER, [])
else
    # Protobuf <2.6 did not support "oneof", but the wire format is the same
    # when all the members are optional and at most one is set.
    AC_MSG_RESULT([no])
    AC_SUBST(ONEOF, [//])
    AC_SUBST(ONEOF_MEMBER, [optional])
fi
rm -f pbtest.proto pbtest.log pbtest.pb.cc pbtest.pb.h
AM_SUBST_NOTMAKE([ONEOF])
AM_SUBST_NOTMAKE([ONEOF_MEMBER])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h])
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h strings.h])
AC_CHECK_HEADERS([sys/param.h sys/types.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([netinet/in_systm.h])
AC_CHECK_HEADERS([netinet/ip.h netinet/ip6.h], [], [], [
   #ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETINET_IN_SYSTM_H
   #include <netinet/in_systm.h>
   #endif
   #ifdef HAVE_NETINET_IN_H
   #include <netinet/in.h>
   #endif
])
AC_CHECK_HEADERS([ws2tcpip.h])
if test "$with_pcap" != "no"; then
    for header in "pcap/pcap.h" "pcap.h"; do
	AC_CHECK_HEADER([$header], [
	    AC_DEFINE_UNQUOTED(PCAP_H, [<$header>], [name of pcap header])
	    break
	])
    done
fi
AC_CHECK_HEADERS([cxxabi.h])

AC_MSG_CHECKING([for <unordered_map>])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <unordered_map>]],
	[[using std::unordered_map;]])],
    AC_MSG_RESULT(yes); AC_DEFINE(HAVE_UNORDERED_MAP,1,[Define if <unordered_map> is available.]),
    AC_MSG_RESULT(no))

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_STDBOOL
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T


# Check architecture endianness
AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
  AC_DEFINE(HAVE_BIG_ENDIAN,1,[Define to 1 for big endian, 0 otherwise.])
fi

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([alarm bzero gethostbyname gethostname inet_ntoa inet_ntop \
  inet_pton memmove memset socket strtol strtoul getopt_long])
AC_CHECK_FUNCS([arc4random srandomdev srandom gettimeofday])
if test "$with_pcap" != "no"; then
    AC_CHECK_FUNCS([pcap_close pcap_create pcap_open_live pcap_sendpacket \
	pcap_datalink_val_to_name])
fi

AC_CHECK_TYPES([struct sockaddr_in6, sa_family_t], , , [
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
])

if test "$enable_dev" = "yes"; then
    AC_MSG_RESULT(Development mode enabled)
    DEBUG=1
    if test "$GCC" = "yes"; then
        CWARNINGS=`echo \
	    -std=gnu99 \
	    -Wall \
	    -Wextra \
	    -Waggregate-return \
	    -Wcast-qual \
	    -Wformat=2 \
	    -Winit-self \
	    -Winline \
	    -Wmissing-declarations \
	    -Wmissing-format-attribute \
	    -Wmissing-include-dirs \
	    -Wmissing-noreturn \
	    -Wmissing-prototypes \
	    -Wnested-externs \
	    -Wold-style-definition \
	    -Wpacked \
	    -Wpointer-arith \
	    -Wshadow \
	    -Wstrict-prototypes \
	    -Wvariadic-macros \
	    -Wwrite-strings`
    fi
    if test "$GXX" = "yes"; then

	DIAG="-fdiagnostics-color=always"
	AC_MSG_CHECKING(whether CXX accepts "$DIAG")
	dnl  We avoid AC_COMPILE_IFELSE etc because they would pull in all the
	dnl  DEFINES, which are not needed for this test and could lead to a
	dnl  false negative.
	echo "int main() { return 0; }" >conftest.cc
	if $CXX -c -o conftest.$OBJEXT -Werror $DIAG conftest.cc >/dev/null 2>&1; then
	    CXXWARNINGS="$DIAG"
	    AC_MSG_RESULT(yes)
	else
	    CXXWARNINGS=''
	    AC_MSG_RESULT(no)
	fi
	rm conftest.$OBJEXT

        CXXWARNINGS=`echo "$CXXWARNINGS" \
	    -Wall \
	    -Wextra \
	    -Wcast-qual \
	    -Wformat=2 \
	    -Winit-self \
	    -Wmissing-declarations \
	    -Wmissing-format-attribute \
	    -Wmissing-include-dirs \
	    -Wmissing-noreturn \
	    -Wpacked \
	    -Wpointer-arith \
	    -Wshadow \
	    -Wvariadic-macros \
	    -Wwrite-strings \
	    -Wno-unused-parameter \
	    `
# protobuf headers generate too many warnings with -Wunused-parameter 

	if test "$enable_extra_warnings" = "yes"; then
	    CXXWARNINGS=`echo "" $CXXWARNINGS \
	        -Wabi \
		-Wcast-align \
		-Wcast-qual \
		-Wclobbered \
		-Wconversion \
	        -Wconversion-null \
		-Wcoverage-mismatch \
	        -Wctor-dtor-privacy \
		-Wdisabled-optimization \
		-Wdouble-promotion \
	        -Weffc++ \
		-Wempty-body \
		-Wenum-compare \
		-Wfloat-equal \
		-Wformat=2 \
		-Wformat-nonliteral \
		-Wformat-security \
		-Wformat-y2k \
		-Wignored-qualifiers \
		-Winit-self \
		-Winvalid-pch \
		-Wlogical-op \
		-Wmissing-field-initializers \
		-Wmissing-format-attribute \
		-Wmissing-include-dirs \
	        -Wnoexcept \
	        -Wnon-virtual-dtor \
		-Woverlength-strings \
	        -Woverloaded-virtual \
		-Wpacked \
		-Wpacked-bitfield-compat \
		-Wpointer-arith \
		-Wredundant-decls \
		-Wsign-conversion \
		-Wshadow \
	        -Wsign-promo \
		-Wstack-protector \
	        -Wstrict-null-sentinel \
		-Wsuggest-attribute=pure \
		-Wsuggest-attribute=const \
		-Wsuggest-attribute=noreturn \
		-Wswitch-default \
		-Wsync-nand \
		-Wtrampolines \
		-Wtype-limits \
		-Wundef \
		-Wunused \
		-Wunused-parameter \
		-Wunused-but-set-parameter \
		-Wunused-but-set-variable \
		-Wvariadic-macros \
		-Wvla \
		-Wwrite-strings \
		-Wno-unknown-warning-option \
		`
	fi


	  ### unimportant
	  # -Wpadded \
          # -Wunsafe-loop-optimizations \

	  ### noisy and not very useful
	  # -Waggregate-return \
	  # -Winline \
	  # -Wlong-long \
	  # -Wswitch-enum \
          # -Wsystem-headers \

	  ### no
          # -Wno-attributes
	  # -Wno-builtin-macro-redefined
	  # -Wno-cpp
	  # -Wno-deprecated
          # -Wno-deprecated-declarations
          # -Wno-div-by-zero
          # -Wno-endif-labels
          # -Wno-format-contains-nul
	  # -Wno-format-extra-args
          # -Wno-int-to-pointer-cast
	  # -Wno-invalid-offsetof
          # -Wno-mudflap \
          # -Wno-multichar \
	  # -Wno-overflow \
	  # -Wno-pragmas \
	  # -Wno-unused-result \



#-Wall:
#          -Waddress
#          -Warray-bounds (only with `-O2')
#          -Wc++0x-compat
#          -Wchar-subscripts
#          -Wenum-compare (in C/Objc; this is on by default in C++)
#          -Wimplicit-int (C and Objective-C only)
#          -Wimplicit-function-declaration (C and Objective-C only)
#          -Wcomment
#          -Wformat
#          -Wmain (only for C/ObjC and unless `-ffreestanding')
#          -Wmissing-braces
#          -Wnonnull
#          -Wparentheses
#          -Wpointer-sign
#          -Wreorder
#          -Wreturn-type
#          -Wsequence-point
#          -Wsign-compare (only in C++)
#          -Wstrict-aliasing
#          -Wstrict-overflow=1
#          -Wswitch
#          -Wtrigraphs
#          -Wuninitialized
#          -Wunknown-pragmas
#          -Wunused-function
#          -Wunused-label
#          -Wunused-value
#          -Wunused-variable
#          -Wvolatile-register-var

    fi
else
    DEBUG=0
fi

# shorter version of CXXWARNINGS
if test -n "$CXXWARNINGS"; then
    echo "$CXXWARNINGS" > "CXXWARNINGS"
    CXXWARNINGS='$$(cat ${top_builddir}/CXXWARNINGS)'
fi

AC_DEFINE_UNQUOTED(DEBUG, $DEBUG, [Define as 1 or 0 to enable or disable debugging])
AC_SUBST(DEBUG)
AC_SUBST(CWARNINGS)
AC_SUBST(CXXWARNINGS)

case $host_os in
*mingw32*)
    AC_CHECK_LIB(gdi32, main) # libcrypto needs libgdi32
    AC_CHECK_LIB(z, inflate) # libcrypto needs libz
    AC_CHECK_LIB(crypt32, main) # for CertOpenSystemStoreA()
    ;;
esac

# AX_CHECK_OPENSSL will find libssl and libcrypto
# Undocumented: "--with-openssl=disabled" will force building without ssl.
AX_CHECK_OPENSSL([], [if test "$ssldirs" = "disabled"; then AC_MSG_WARN([SSL disabled]); else AC_MSG_ERROR([An openssl library is required.]); fi])
if test -n "$OPENSSL_LIBS"; then
    # Check for X509_VERIFY_PARAM_set1_host() without polluting LIBS or LDFLAGS
    AC_CHECK_LIB(ssl, X509_VERIFY_PARAM_set1_host,
	[AC_DEFINE([HAVE_LIBSSL],1,[Define if -lssl is available.])],
	[AC_MSG_ERROR([This version of ssl does not support certificate hostname verification.])],
	[$OPENSSL_LDFLAGS $OPENSSL_LIBS])
fi

if test "$enable_server" != "no"; then
    enable_server=yes
    MAYBE_SERVER="server"

    # calculate options needed to find <mysql.h>
    origCPPFLAGS="$CPPFLAGS"; # save
    for dir in "$with_mysql" "/usr" "/usr/local" "/usr/local/mysql"; do
	for subdir in "include" "include/mysql"; do
	    MYSQLCPPFLAGS="${dir:+-I$dir/$subdir}"
	    CPPFLAGS="$origCPPFLAGS $MYSQLCPPFLAGS"
	    AC_MSG_NOTICE([trying MYSQLCPPFLAGS=$MYSQLCPPFLAGS])
	    AC_CHECK_HEADER([mysql.h], [
		    AC_SUBST(MYSQLCPPFLAGS)
		    break 2])
	    unset ac_cv_header_mysql_h; # erase failure from cache
	    if test -z "$dir"; then break; fi
	done
    done
    CPPFLAGS="$origCPPFLAGS"; # restore
    if test -z "$ac_cv_header_mysql_h"; then
	AC_MSG_ERROR([A mysql.h header is required to build the server.])
    fi

    # calculate options needed to link with -lmysqlclient
    for dir in "$with_mysql" "/usr" "/usr/local" "/usr/local/mysql"; do
	for subdir in "lib" "lib/mysql"; do
	    MYSQLLDFLAGS="${dir:+-L$dir/$subdir}"
	    AC_MSG_NOTICE([trying MYSQLLDFLAGS=$MYSQLLDFLAGS])
	    AC_CHECK_LIB(mysqlclient, my_init, [
		    AC_SUBST(MYSQLLDADD, "-lmysqlclient")
		    AC_SUBST(MYSQLLDFLAGS)
		    break 2
		], [], [$MYSQLLDFLAGS])
	    unset ac_cv_lib_mysqlclient_my_init; # erase failure from cache
	    if test -z "$dir"; then break; fi
	done
    done
    if test -z "$ac_cv_lib_mysqlclient_my_init"; then
	AC_MSG_ERROR([A mysqlclient library is required to build the server.])
    fi

else
    MAYBE_SERVER=""
fi ; # $enable_server
AC_SUBST(MAYBE_SERVER)

AM_CONDITIONAL([COND_PROBER], [test "$enable_prober" = "yes"])
AM_CONDITIONAL([COND_MANAGER], [test "$enable_manager" = "yes"])

AC_CONFIG_FILES([Makefile common/Makefile])
test "$enable_prober" = "yes" && AC_CONFIG_FILES([prober/Makefile])
test "$enable_manager" = "yes" && AC_CONFIG_FILES([manager/Makefile])
ifelse(Have_Server, [1],
    [test "$enable_server" = "yes" && AC_CONFIG_FILES([server/Makefile])])
AC_CONFIG_FILES([common/spoofer.proto])

case $host_os in
*mingw32*)
    AC_CONFIG_FILES([nsis/spoofer.nsi])
    ;;
*darwin*)
    AC_CONFIG_FILES([mac-scripts/header])
    AC_CONFIG_FILES([mac-distribution.xml])
    ;;
esac
AC_OUTPUT

dnl summary
AC_MSG_RESULT()
AC_MSG_RESULT([Will build spoofer prober:  $enable_prober])
AC_MSG_RESULT([Will build spoofer prober manager:  $enable_manager])
AC_MSG_RESULT([Will build spoofer server:  $enable_server])
if test "$ac_cv_search_pcap_close" = "no"; then
    AC_MSG_WARN([IPv6 probing will not be available because the pcap library was not found.])
fi
