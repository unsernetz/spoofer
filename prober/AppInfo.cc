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
   Author:      Ken Keys, CAIDA
   Date:        $Date: 2017/11/02 21:33:57 $
   Description: get application name
****************************************************************************/

#include "spoof.h"
#ifdef _WIN32
 #include <windows.h>
#else
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <unistd.h>
 #include <cstdio>
 #include <string.h>
#endif // _WIN32
#include <libgen.h>
#include "AppInfo.h"

static const char cvsid[] ATR_USED = "$Id: AppInfo.cc,v 1.6 2017/11/02 21:33:57 kkeys Exp $";

char *AppInfo::appPath = nullptr;
char *AppInfo::appDir = nullptr;

#ifndef _WIN32
AppInfo::AppInfo(const char *argv0)
{
    if (appPath) return;
    char buf[PATH_MAX];

    // Get the app name from /proc on systems that have it.
    if ((readlink("/proc/self/exe", buf, PATH_MAX) > 0) ||        // Linux
        (readlink("/proc/curproc/file", buf, PATH_MAX) > 0) ||    // FreeBSD
        (readlink("/proc/self/path/a.out", buf, PATH_MAX) > 0))   // Solaris
	    { appPath = strdup(buf); return; }

    // Absolute argv[0]
    if (argv0[0] == '/') {
	appPath = strdup(argv0);
	return;
    }

    // Reconstruct the app name from cwd and relative argv[0].
    char cwd[PATH_MAX];
    if (!getcwd(cwd, PATH_MAX))
	strcpy(cwd, "."); // shouldn't happen
    if (strchr(argv0, '/')) {
	sprintf(buf, "%s/%s", cwd, argv0);
	appPath = strdup(buf);
	return;
    }

    // Reconstruct the app name from $PATH and unqualified argv[0].
    const char *epath = getenv("PATH");
    if (!epath || !*epath)
	return;
    while (true) {
	int len = safe_int<int>(strcspn(epath, ":\0"));
	if (epath[0] == '/')
	    sprintf(buf, "%.*s/%s", len, epath, argv0);
	else // e.g. "."
	    sprintf(buf, "%s/%.*s/%s", cwd, len, epath, argv0);
	if (access(buf, X_OK) == 0) {
	    appPath = strdup(buf);
	    break;
	}
	if (!epath[len])
	    break;
	epath += len + 1;
    }
}

#else // _WIN32
AppInfo::AppInfo(const char *argv0 ATR_UNUSED) { appPath = nullptr; }
#endif // !_WIN32

const char *AppInfo::path()
{
#ifdef _WIN32
    if (!appPath) {
	char buf[PATH_MAX];
	GetModuleFileNameA(NULL, buf, PATH_MAX);
	appPath = strdup(buf);
    }
#endif
    return appPath;
}

const char *AppInfo::dir()
{
    if (!appDir) {
	if (!path()) return ".";
	char *result = dirname(appDir = strdup(path()));
	if (result != appDir) // in case dirname() returns a pointer to a static buffer
	    strcpy(appDir, result);
    }
    return appDir;
}
