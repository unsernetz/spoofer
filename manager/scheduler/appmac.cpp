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

#include <unistd.h>
#include <errno.h>
#include <launch.h>
#include "spoof_qt.h"
#include <QFileSystemWatcher>
#include "../../config.h"
#include "app.h"
#include "appmac.h"
#include "common.h"
static const char cvsid[] ATR_USED = "$Id: appmac.cpp,v 1.4 2017/03/09 23:42:04 kkeys Exp $";

bool AppMac::prestart(int &exitCode)
{
    if (isLaunchdService()) {
	if (optDetach) {
	    qDebug() << "Scheduler: ignoring detatch option";
	    optDetach = false;
	}

	// Try to detect if our own executable is deleted (i.e. user is trying
	// to uninstall by dragging the Spoofer.app bundle to the trash).
	QString bundleDir(appDir);
	bundleDir.remove(QSL("/Contents/MacOS")); // -> "/Applications/Spoofer.app"
	QString bundleParent(bundleDir % QSL("/.."));
	exeWatcher = new QFileSystemWatcher();
	QStringList list = (QStringList() <<
	    appFile << bundleDir << bundleParent);
	qDebug() << "watching" << list;
	QStringList failed = exeWatcher->addPaths(list);
	if (!failed.isEmpty()) {
	    qDebug() << "failed to watch" << failed;
	}
	if (failed.size() == list.size()) {
	    delete exeWatcher;
	} else {
	    connect(exeWatcher, &QFileSystemWatcher::fileChanged,
		this, &AppMac::executableChanged);
	    connect(exeWatcher, &QFileSystemWatcher::directoryChanged,
		this, &AppMac::executableChanged);
	}
    }

    return AppUnix::prestart(exitCode);
}

#define SERVICENAME ORG_DOMAIN_REVERSED ".spoofer-scheduler"
#define LAUNCHERCFG "/Library/LaunchDaemons/" SERVICENAME ".plist"

// The launchd API is undocumented, but see:
// /usr/include/launch.h
// http://opensource.apple.com//source/samba/samba-187/tools/prefsync/lib/launchctl.cpp
launch_data_t AppMac::launchdRequest(const char *key)
{
    launch_data_t req = 0;
    launch_data_t resp = 0;

    if (!(req = launch_data_alloc(LAUNCH_DATA_DICTIONARY))) {
	sperr << "launch_data_alloc failed" << endl;
	return 0;
    }
    launch_data_dict_insert(req, launch_data_new_string(SERVICENAME), key);
    resp = launch_msg(req);
    if (!resp)
	sperr << "launchd " << key << " " << SERVICENAME << ": error: " <<
	    strerror(errno) << endl;
    launch_data_free(req);
    return resp;
}

bool AppMac::isLaunchdService()
{
    bool result = false;
    launch_data_t resp = 0;
    launch_data_t data = 0;
    pid_t servicePid = 0, myPid = getpid();

    // Verify that this process is the spoofer-scheduler service in launchd.
    if (!(resp = launchdRequest(LAUNCH_KEY_GETJOB)))
	return false;
    if ((data = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_PID)))
	servicePid = (pid_t)launch_data_get_integer(data);
    if (!(result = (servicePid == myPid))) {
	qDebug() << "service pid" << servicePid << "!= scheduler pid" << myPid;
    } else {
	qDebug() << "confirmed: running with pid" << myPid <<
	    "under launchd as" << SERVICENAME;
    }
    launch_data_free(resp);
    return result;
}

void AppMac::removeLaunchdService()
{
    launch_data_t resp;
    launch_data_type_t type;

    // Remove the service.
    if (!(resp = launchdRequest(LAUNCH_KEY_REMOVEJOB)))
	return;
    if ((type = launch_data_get_type(resp)) != LAUNCH_DATA_ERRNO) {
	sperr << "unexpected launchd response type " << type << endl;
    } else {
	errno = launch_data_get_errno(resp);
	if (errno)
	    sperr << "launchd " << LAUNCH_KEY_REMOVEJOB << " " << SERVICENAME <<
		": error: " << strerror(errno) << endl;
	else
	    sperr << "launchd remove " << SERVICENAME << ": success" << endl;
    }

    launch_data_free(resp);
}

void AppMac::executableChanged(const QString &path)
{
    qDebug() << "change detected in" << path;
    if (QFile(appFile).exists())
	return;
    sperr << "appFile " << appFile << " was deleted" << endl;

    if (!isLaunchdService())
	return;

    removeLaunchdService();

    // delete our launchd config file
    if (unlink(LAUNCHERCFG) == 0)
	sperr << "Deleted " << LAUNCHERCFG << endl;
    else
	sperr << "Error deleting " << LAUNCHERCFG << ": " << strerror(errno) <<
	    endl;

    this->exit(1);
}

void AppMac::shutdown()
{
    // If we're running under launchd, remove ourselves so we're not
    // automatically restarted as soon as we exit.  But we don't delete the
    // config file, so we can be reloaded later (e.g. at next boot).
    if (isLaunchdService())
	removeLaunchdService();
    App::shutdown();
}

