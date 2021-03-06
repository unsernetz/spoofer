## 
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

# $Id: Makefile.am,v 1.19 2017/10/20 18:40:01 kkeys Exp $

SUFFIXES = .proto .pb.cc .pb.h

.proto.pb.cc:
	$(AM_V_GEN)$(PROTOC) --proto_path=$$(dirname $<) --cpp_out=$$(dirname $@) $<
	$(AM_V_at){ echo "#pragma GCC system_header"; cat $*.pb.h; } >$*.pb.h.tmp && mv $*.pb.h.tmp $*.pb.h

.proto.pb.h:
	$(AM_V_GEN)$(PROTOC) --proto_path=$$(dirname $<) --cpp_out=$$(dirname $@) $<
	$(AM_V_at){ echo "#pragma GCC system_header"; cat $*.pb.h; } >$*.pb.h.tmp && mv $*.pb.h.tmp $*.pb.h

spoofer_pb_enum.cc: spoofer.pb.h
	$(AM_V_GEN)SRC=spoofer.pb.h; \
	{ \
	echo "// Automatically generated by common/Makefile from $$SRC"; \
	echo '#include <spoof.h>'; \
	echo; \
	echo '#define ARRAY_RANGE(a)   a, a+sizeof(a)/sizeof(a[0])'; \
	echo '#define VALUES(name) static const EnumName<Spoofer##name> values_##name[] = '; \
	echo '#define DECL(name) const EnumNames<Spoofer##name> names_##name(ARRAY_RANGE(values_##name))'; \
	echo; \
	sed -E -n -e '/^enum Spoofer(SpoofReport|ResultSummary|TestType|ReportStatus)/,/};/{ /^enum/h; /^enum/!H; /};/{ g; s/enum Spoofer([A-Za-z_]+)(.*)};/VALUES(\1)\2};@DECL(\1);@/; y/@/\n/; s/([A-Za-z_]+_)?([A-Za-z]+) = ([0-9]*)/{ \1\2, "\2" }/g; p; }; }' $$SRC; \
	} >$@

BUILT_SOURCES = spoofer.pb.h
DISTCLEANFILES = spoofer.pb.h spoofer.pb.cc spoofer_pb_enum.cc

noinst_LIBRARIES = libspooferpb.a libspoofer.a

# libspooferpb is separate from libspoofer so it can have different CXXFLAGS
nodist_libspooferpb_a_SOURCES = spoofer.pb.cc spoofer.pb.h
libspoofer_a_SOURCES = util.cc net.cc port.h spoof.h safe_int.h spoof_pcap.h \
	messages.cc messages.h PBStreamer.cc PBStreamer.h \
	spoofer_stdio.cc spoofer_stdio.h
nodist_libspoofer_a_SOURCES = spoofer.pb.h spoofer_pb_enum.cc

AM_CXXFLAGS = $(CXXWARNINGS)
# disable warnings in generated code that we can't fix
libspooferpb_a_CXXFLAGS = 
AM_CPPFLAGS = $(PROTOBUFCPPFLAGS) $(OPENSSL_INCLUDES)
