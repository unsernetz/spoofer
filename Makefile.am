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

if COND_PROBER
    MAYBE_PROBER = prober
endif
if COND_MANAGER
    MAYBE_MANAGER = manager
endif
# MAYBE_SERVER isn't wrapped in COND_SERVER because server shouldn't be disted
MAYBE_SERVER = @MAYBE_SERVER@

SUBDIRS = common $(MAYBE_PROBER) $(MAYBE_MANAGER) $(MAYBE_SERVER)

MAC_INSTALLSCRIPTS = \
    mac-scripts/apps/preinstall.in mac-scripts/apps/postinstall.in \
    mac-scripts/start-now/postinstall.in \
    mac-scripts/start-gui/postinstall.in \
    mac-scripts/uninstall/uninstall.in \
    mac-scripts/uninstall/restore.in
MAC_EXTRA_DIST = icons/spoofer.icns mac-distribution.xml $(MAC_INSTALLSCRIPTS)

WIN_EXTRA_DIST = icons/spoofer.ico


EXTRA_DIST = $(WIN_EXTRA_DIST) $(MAC_EXTRA_DIST) \
    icons/spoofer16.png icons/spoofer32.png icons/spoofer48.png \
    icons/spoofer64.png icons/spoofer128.png icons/spoofer256.png

DISTCLEANFILES = CXXWARNINGS

SUFFIXES = .pkg .root

.PHONY: FORCE

FORCE:


# code signing parameters
CS_PKCS12 = $${CS_DIR}/ucsd-code-signing-cert.p12
CS_PASS = $${CS_DIR}/ucsd-code-signing-cert.pass
CS_URL = 'http://spoofer.caida.org/'
CS_TIME = 'http://timestamp.comodoca.com/'

#OSX_CS_IDENTITY = 'Mac Developer: Ken Keys (4G86BCHPT2)'
OSX_CS_IDENTITY = 'Developer ID Application: University of California, San Diego (Business Affairs) (G789749RTK)'


###########################################################################
# Windows distribution
###########################################################################

SPOOFER = spoofer-prober$(EXEEXT)
WIN_INSTALLER = @WIN_INSTALLER@
TEXTFILES = README.txt THANKS.txt CHANGES.txt LICENSE.txt

# Convert \n in "foo" to \r\n in "foo.txt" (for Windows)
%.txt :: %
	sed -e's/$$/\r/' $< > $@

# Windows unsigned binary distribution
unsigned: all
	-rm -r unsigned
	mkdir unsigned
	cp $(top_builddir)/prober/spoofer-prober.exe \
	   $(top_builddir)/manager/scheduler/spoofer-scheduler.exe \
	   $(top_builddir)/manager/gui/spoofer-gui.exe \
	   $(top_builddir)/manager/cli/spoofer-cli.exe \
	   unsigned
	$(STRIP) unsigned/spoofer-*.exe

unsigned/uninstall.exe: nsis/spoofer.nsi unsigned
	cd nsis && makensis -WX -DUNINSTALL -DOUTFILE="../$@" spoofer.nsi

unsigned/restore.exe: nsis/spoofer.nsi unsigned
	cd nsis && makensis -WX -DRESTORE -DOUTFILE="../$@" spoofer.nsi

unsigned-$(WIN_INSTALLER): nsis/spoofer.nsi unsigned $(TEXTFILES) unsigned/restore.exe unsigned/uninstall.exe $(top_srcdir)/win-bin/@WINPCAP_INSTALLER@
	cd nsis && makensis -WX -DINSTALL -DOUTFILE="../$@" -DDISTBINS="../unsigned" spoofer.nsi

windist-unsigned: unsigned-$(WIN_INSTALLER)

# Windows signed binary distribution
WINSIGN = winsign() { echo "Codesigning $$1 to $$2"; osslsigncode sign -pkcs12 $(CS_PKCS12) -h sha256 -readpass $(CS_PASS) -i $(CS_URL) -ts $(CS_TIME) -n '@PACKAGE_NAME@' -in "$$1" -out "$$2"; }; winsign

signed: unsigned unsigned/uninstall.exe unsigned/restore.exe
	-rm -r signed
	mkdir signed
	@for f in unsigned/*; do \
	    $(WINSIGN) $$f signed/`basename $$f` || exit $$?; \
	done

$(WIN_INSTALLER): nsis/spoofer.nsi signed $(TEXTFILES) $(top_srcdir)/win-bin/@WINPCAP_INSTALLER@
	cd nsis && makensis -WX -DINSTALL -DOUTFILE="../tmp-unsigned" -DDISTBINS="../signed" spoofer.nsi
	@$(WINSIGN) tmp-unsigned $@
	rm tmp-unsigned

windist-signed: $(WIN_INSTALLER)

# How to sign Windows binaries with mono's signcode:
#	$(STRIP) binary
#	signcode -a sha1 -spc $(CS_SPC) -v $(CS_PVK) -i $(CS_URL) -t $(CS_TIME) -n "desc" binary

# How to sign Windows binaries with osslsigncode:
#	mv binary unsigned-binary
#	osslsigncode sign -pkcs12 $(CS_PKCS12) -readpass $(CS_PASS) -i $(CS_URL) -t $(CS_TIME) -n "desc" -in unsigned-binary binary



###########################################################################
# Mac OSX distribution
###########################################################################

# Mac OSX unsigned application

MAC_INSTALLER = @MAC_INSTALLER@
SCHEDPATH = Spoofer.app/Contents/MacOS/spoofer-scheduler
LAUNCHCFG = org.caida.spoofer-scheduler.plist
PlistBuddy = /usr/libexec/PlistBuddy

Spoofer.app macbundle: .timestamp.Spoofer.app

.timestamp.Spoofer.app: manager/scheduler/$(LAUNCHCFG) built/mac-scripts all
	-rm -r .timestamp.Spoofer.app Spoofer.app spoofer-gui.app
	cp -r manager/gui/spoofer-gui.app .
	cp \
	    manager/scheduler/spoofer-scheduler \
	    manager/cli/spoofer-cli \
	    prober/spoofer-prober \
	    built/mac-scripts/uninstall/uninstall \
	    built/mac-scripts/uninstall/restore \
	    spoofer-gui.app/Contents/MacOS
	$(STRIP) spoofer-gui.app/Contents/MacOS/spoofer-*
	cp $(top_srcdir)/mac-bin/scamper \
	    spoofer-gui.app/Contents/MacOS
# macdeployqt exits with status 0 even on error, so we wrap it with a function
# that exits with nonzero status if it sees "error" in the output.
	@detectError() { \
		echo "$$@"; \
		set -o pipefail; \
		"$$@" 2>&1 | \
		perl -ne 'print; if (/error/i) {$$x=1;} END {exit $$x||0;}'; \
	    }; detectError \
	    $$($(QMAKE) -query QT_HOST_BINS)/macdeployqt spoofer-gui.app \
		-executable=spoofer-gui.app/Contents/MacOS/spoofer-cli \
		-executable=spoofer-gui.app/Contents/MacOS/spoofer-scheduler \
		-executable=spoofer-gui.app/Contents/MacOS/spoofer-prober \
		-executable=spoofer-gui.app/Contents/MacOS/scamper
	cp $< spoofer-gui.app/Contents/Resources
	$(PlistBuddy) -c 'set Program $(abs_builddir)/$(SCHEDPATH)' \
	    spoofer-gui.app/Contents/Resources/$(LAUNCHCFG)
	mv spoofer-gui.app Spoofer.app
	touch .timestamp.Spoofer.app
# macdeployqt must happen before the bundle rename, because (in Qt 5.4.2)
# it seems to expect the main executable to have the same name as the .app
# bundle directory (instead of getting the name from Info.plist).

# "pkgbuild --scripts" needs a clean copy of JUST the necessary files, because
# it will slurp up everything in the directory, including CVS/, .*.swp, etc.
# We replace each "@mac_scripts_header@" line with the contents of file
# "mac-scripts/header".
built/mac-scripts: mac-scripts/header $(MAC_INSTALLSCRIPTS)
	-rm -r built/mac-scripts
	for f in $(MAC_INSTALLSCRIPTS); do \
	    out=$$(echo "$$f" | sed -e's/\.in$$//'); \
	    $(MKDIR_P) `dirname "built/$$f"`; \
	    sed -e'/@mac_scripts_header@/ { r mac-scripts/header' -e 'd' -e'}' \
		"$(srcdir)/$$f" >"built/$$out" \
		&& chmod +x "built/$$out" || exit $$?; \
	done

apps.root: .timestamp.Spoofer.app
	-rm -r $@
	$(MKDIR_P) $@/Applications
	cp -R Spoofer.app $@/Applications
#	# Replace the temporary development id with a release id to prevent
#	# the OS from ever confusing a dev version with a release version.
	$(PlistBuddy) \
	    -c "set CFBundleIdentifier $(ORG_DOMAIN_REVERSED).spoofer" \
	    $@/Applications/Spoofer.app/Contents/Info.plist
#	codesign --verbose --sign $(OSX_CS_IDENTITY) \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-gui \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-cli \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-scheduler \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-prober \
#		$$(find apps.root/Applications/Spoofer.app/Contents/PlugIns -name '*.dylib')
#	codesign --verbose --verify \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-gui \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-cli \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-scheduler \
#		apps.root/Applications/Spoofer.app/Contents/MacOS/spoofer-prober \
#		$$(find apps.root/Applications/Spoofer.app/Contents/PlugIns -name '*.dylib')
	$(MKDIR_P) $@/Library/LaunchDaemons
	mv \
	    $@/Applications/Spoofer.app/Contents/Resources/$(LAUNCHCFG) \
	    $@/Library/LaunchDaemons
	$(PlistBuddy) -c 'set Program /Applications/$(SCHEDPATH)' \
	    $@/Library/LaunchDaemons/$(LAUNCHCFG)

apps.pkg: apps.root built/mac-scripts
	pkgbuild --root $*.root --analyze $*.plist
# By default, if the installer finds another copy of the app in a
# different location, it will install in that location instead of
# where we want.  The next line prevents that.
	$(PlistBuddy) -c 'set :0:BundleIsRelocatable false' $*.plist
	pkgbuild --root $*.root \
	    --component-plist $*.plist \
	    --identifier org.caida.spoofer.$* \
	    --version $(VERSION) \
	    --scripts built/mac-scripts/$* \
	    $@
#	codesign --verbose --sign $(OSX_CS_IDENTITY) $@

start-now.pkg start-gui.pkg: built/mac-scripts
	pkgbuild --nopayload \
	    --identifier org.caida.spoofer.$* \
	    --version $(VERSION) \
	    --scripts built/mac-scripts/$* \
	    $@
#	codesign --verbose --sign $(OSX_CS_IDENTITY) $@

resources: FORCE
	-rm -r resources
	mkdir resources
	cp $(srcdir)/mac-resources/conclusion.txt resources
	cp $(srcdir)/LICENSE resources
	cp $(srcdir)/README resources

unsigned-$(MAC_INSTALLER): mac-distribution.xml resources apps.pkg \
	start-now.pkg start-gui.pkg
	productbuild \
	    --identifier org.caida.spoofer \
	    --version $(VERSION) \
	    --distribution $< \
	    --resources resources \
	    $@
	@test "$(MACOSX_DEPLOYMENT_TARGET)" = "10.7" || \
	echo "WARNING: MACOSX_DEPLOYMENT_TARGET $(MACOSX_DEPLOYMENT_TARGET) != 10.7"

macdist-unsigned: unsigned-$(MAC_INSTALLER)

$(MAC_INSTALLER): unsigned-$(MAC_INSTALLER)
	productsign --sign $(OSX_CS_IDENTITY) $< $@
	pkgutil --check-signature $@
	@test "$(MACOSX_DEPLOYMENT_TARGET)" = "10.7" || \
	echo "WARNING: MACOSX_DEPLOYMENT_TARGET $(MACOSX_DEPLOYMENT_TARGET) != 10.7"

macdist-signed: $(MAC_INSTALLER)

#--------------------------------------------------------------------------
# TODO: sign all spoofer binaries and package
# TODO: include CHANGES THANKS
#--------------------------------------------------------------------------

