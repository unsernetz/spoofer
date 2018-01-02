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

QT             = core network
TEMPLATE       = app
TARGET         = spoofer-scheduler

CONFIG        += console c++11
macx:CONFIG   -= app_bundle
CONFIG        -= debug_and_release
CONFIG        += release

HEADERS        = app.h BlockWriter.h
win32:HEADERS += appwin.h \
                 ServiceStarterThread.h
unix:HEADERS  += appunix.h
macx:HEADERS  += appmac.h
SOURCES        = main.cpp \
                 app.cpp
win32:SOURCES += appwin.cpp
unix:SOURCES  += appunix.cpp
macx:SOURCES  += appmac.cpp

include(../common/common.inc)

unix {
    # Note: If target.path looks relative to qmake, qmake will prepend srcdir.
    target.path = /$(bindir)
    INSTALLS += target
}
