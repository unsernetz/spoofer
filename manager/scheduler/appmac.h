/* 
 * Copyright 2015-2017 The Regents of the University of California
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

#ifndef SCHEDULER_APPMAC_H
#define SCHEDULER_APPMAC_H

#include "appunix.h"
#include <launch.h>

QT_BEGIN_NAMESPACE
class QFileSystemWatcher;
QT_END_NAMESPACE

class AppMac : public AppUnix {
    Q_OBJECT

    AppMac(const AppMac&) NO_METHOD; // no copy-ctor
    AppMac operator=(const AppMac&) NO_METHOD; // no copy-assign

public:
    AppMac(int &argc, char **argv) : AppUnix(argc, argv), exeWatcher(0) {}
    bool prestart(int &exitCode) Q_DECL_OVERRIDE;
    void shutdown() Q_DECL_OVERRIDE;

private:
    QFileSystemWatcher *exeWatcher;
    launch_data_t launchdRequest(const char *key);
    bool isLaunchdService();
    void removeLaunchdService();

private slots:
    void executableChanged(const QString &path);
};

#endif // SCHEDULER_APPMAC_H
