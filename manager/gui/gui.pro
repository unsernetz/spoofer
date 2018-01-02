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

QT            = core network gui widgets
TEMPLATE      = app
TARGET        = spoofer-gui

CONFIG       += windows c++11
CONFIG       -= debug_and_release
CONFIG       += release

HEADERS       = mainwindow.h \
                ActionButton.h \
		PreferencesDialog.h \
		ColoredLabel.h
SOURCES       = main.cpp \
                mainwindow.cpp \
		ActionButton.cpp \
		PreferencesDialog.cpp

include(../common/common.inc)

win32:RC_ICONS=../../icons/spoofer.ico
macx:ICON = ../../icons/spoofer.icns

RESOURCES = gui.qrc

macx {
# qmake by default creates an Info.plist file with CFBundleIdentifier set to
# "CAIDA.org.spoofer-gui".  I do not know where "CAIDA.org" comes from, but
# it can be overridden by setting QMAKE_TARGET_BUNDLE_PREFIX (undocumented).
# The "spoofer-gui" apparently comes from TARGET, and can not be overridden.
# So we rewrite CFBundleIdentifier manually after linking.
# The temporary dev id we use here will be replaced when building a release
# package to prevent the OS from ever confusing dev and release bundles.
QMAKE_POST_LINK = /usr/libexec/PlistBuddy \
    -c $$shell_quote("set CFBundleIdentifier $(ORG_DOMAIN_REVERSED).spoofer.dev") \
    $$shell_quote($$TARGET).app/Contents/Info.plist
}

unix {
    # Note: If qmake thinks target.path is relative, it will prepend srcdir.
    target.path = /$(bindir)
    INSTALLS += target
}
