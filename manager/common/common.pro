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

!include($$VARS) {
    error(failed to included $$VARS)
}

QT            = core network
TEMPLATE      = lib

CONFIG       += staticlib create_prl c++11
CONFIG       -= debug_and_release
CONFIG       += release

SOURCES       = common.cpp \
	        SpooferUI.cpp
HEADERS       = common.h \
                SpooferUI.h \
                InputReader.h \
                FileTailThread.h \
		BlockReader.h

# qmake does not do this, so we have to
QMAKE_DISTCLEAN = libcommon.prl

macx:LIBS    += -dead_strip
