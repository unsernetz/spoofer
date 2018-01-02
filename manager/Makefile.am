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

EXTRA_DIST = \
	manager.pro \
	Makefile.am \
	Makefile.in \
	cli/app.cpp \
	cli/app.h \
	cli/main.cpp \
	cli/cli.pro \
	common/FileTailThread.h \
	common/InputReader.h \
	common/SpooferUI.cpp \
	common/SpooferUI.h \
	common/common.cpp \
	common/common.h \
	common/common.inc \
	common/port.h \
	common/spoof_qt.h \
	common/common.pro \
	common/BlockReader.h \
	common/BlockWriter.h \
	gui/main.cpp \
	gui/mainwindow.cpp \
	gui/mainwindow.h \
	gui/ActionButton.cpp \
	gui/ActionButton.h \
	gui/ColoredLabel.h \
	gui/PreferencesDialog.cpp \
	gui/PreferencesDialog.h \
	gui/gui.qrc \
	gui/gui.pro \
	scheduler/ServiceStarterThread.h \
	scheduler/app.cpp \
	scheduler/app.h \
	scheduler/appmac.cpp \
	scheduler/appmac.h \
	scheduler/appunix.cpp \
	scheduler/appunix.h \
	scheduler/appwin.cpp \
	scheduler/appwin.h \
	scheduler/main.cpp \
	scheduler/org.caida.spoofer-scheduler.plist \
	scheduler/scheduler.pro

EXCLUDE_DIST = \
	.cvsignore \
	cli/.cvsignore \
	common/.cvsignore \
	gui/.cvsignore \
	scheduler/.cvsignore


all debug release clean: manager.mak
	$(MAKE) -f manager.mak \
	    bindir='$(bindir)' \
	    ORG_DOMAIN_REVERSED='$(ORG_DOMAIN_REVERSED)' \
	    $@

distclean-local: manager.mak
	$(MAKE) -f manager.mak \
	    bindir='$(bindir)' \
	    ORG_DOMAIN_REVERSED='$(ORG_DOMAIN_REVERSED)' \
	    distclean
	-rm manager.vars CXX_W; # can't be done with DISTCLEANFILES

install-exec-local: all
	$(MAKE) -f manager.mak \
	    bindir='$(DESTDIR)$(bindir)' \
	    ORG_DOMAIN_REVERSED='$(ORG_DOMAIN_REVERSED)' \
	    install

uninstall-local: manager.mak
	$(MAKE) -f manager.mak \
	    bindir='$(DESTDIR)$(bindir)' \
	    ORG_DOMAIN_REVERSED='$(ORG_DOMAIN_REVERSED)' \
	    uninstall

CXX_W: $(top_builddir)/config.status
	{ echo "#!/bin/sh"; echo "$(CXX) $(CXXWARNINGS)" '"$$@"'; } >CXX_W
	chmod ugo+x CXX_W

manager.vars: $(top_builddir)/config.status
	@$(AM_V_P) && set -x || echo "  GEN      manager.vars"; \
	{ echo QMAKE_CXX="../CXX_W"; \
	echo QMAKE_LINK="$(CXX)"; \
	echo QMAKE_LINK_SHLIB="$(CXX)"; \
	echo QMAKE_CXXFLAGS+="$(CXXFLAGS) $(QT_INCLUDE_FLAGS)"; \
	echo QMAKE_LFLAGS+="$(LDFLAGS)"; \
	echo QMAKE_LIBS+="$(LIBS)"; \
	echo QMAKE_CXXFLAGS_DEBUG=""; \
	echo QMAKE_CXXFLAGS_RELEASE=""; \
	echo QMAKE_MACOSX_DEPLOYMENT_TARGET="$(MACOSX_DEPLOYMENT_TARGET)"; \
	} >manager.vars

manager.mak: $(srcdir)/manager.pro $(top_builddir)/config.status CXX_W manager.vars
	-rm common/Makefile scheduler/Makefile cli/Makefile gui/Makefile 2>/dev/null || :
	$(AM_V_GEN)QT_SELECT=$(QT_SELECT) $(QMAKE) $$($(AM_V_P) || echo "-config silent") VARS="$$(pwd)/manager.vars" $(srcdir)/manager.pro


dist-hook:
	@unfound=""; \
	for file in $$(cd $(srcdir) && find . -name CVS -prune -o -name '.*.swp' -o -type f -print | sed -e 's#./##'); do \
	    found=0; \
	    for listedfile in $(EXTRA_DIST) $(EXCLUDE_DIST); do \
		if test "$$file" = "$$listedfile"; then \
		    found=1; \
		fi; \
	    done; \
	    test $$found = 0 && unfound="$$unfound $$file"; \
	done; \
	if test -n "$$unfound"; then \
	    echo; \
	    echo "ERROR: To avoid accidentally omitting files from the" \
		"distribution, all files in '$$(basename $$(pwd))' must be" \
		"listed in either EXTRA_DIST or EXCLUDE_DIST in Makefile.am. " \
		"The following files were not listed:" | fmt; \
	    for f in $$unfound; do echo "  $$f"; done; \
	    echo; \
	    exit 1; \
	fi
