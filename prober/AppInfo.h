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
   Date:        $Date: 2017/10/13 19:06:06 $
   Description: get application name
****************************************************************************/

/*
 * Usage: at the beginning of main(), declare
 *     AppInfo appInfo(argv[0]);
 * then, anywhere in the program (within the lifetime of appInfo), get the
 * application name by calling the static method
 *     AppInfo::path()
 */

class AppInfo {
    static char *appPath;
    static char *appDir;

    AppInfo(const AppInfo&) NO_METHOD;
    AppInfo operator=(const AppInfo&) NO_METHOD;
public:
    AppInfo(const char *argv0);
    ~AppInfo() { if (appPath) free(appPath); appPath = nullptr; }

    static const char *path() ATR_PURE;
    static const char *dir() ATR_PURE;
};
