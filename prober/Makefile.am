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

# $Id: Makefile.am,v 1.30 2017/11/01 22:17:43 kkeys Exp $

bin_PROGRAMS = spoofer-prober

spoofer_prober_SOURCES = routetracer.h routetracer.cc unix_routetracer.cc win_routetracer.cc spoofer-prober.cc prober.h AppInfo.cc AppInfo.h
AM_CXXFLAGS = $(PTHREAD_CFLAGS) $(CXXWARNINGS)
AM_CPPFLAGS = -I$(top_srcdir)/common -I$(top_builddir)/common $(PROTOBUFCPPFLAGS) $(OPENSSL_INCLUDES)
AM_LDFLAGS = -L$(top_srcdir)/common $(PROTOBUFLDFLAGS) $(OPENSSL_LDFLAGS)
LDADD = ../common/libspoofer.a ../common/libspooferpb.a $(PROTOBUFLDADD) $(PTHREAD_LIBS) $(OPENSSL_LIBS)

AM_DEFAULT_SOURCE_EXT=.cc
# bin_PROGRAMS += pbs-client pbs-server
