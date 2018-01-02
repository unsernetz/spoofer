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
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h> // umask()
#include <syslog.h> // syslog()
#include "spoof_qt.h"
#include <QSocketNotifier>
#include <QCoreApplication>
#include "../../config.h"
#include "app.h"
#include "appunix.h"
#include "common.h"
static const char cvsid[] ATR_USED = "$Id: appunix.cpp,v 1.22 2017/03/09 23:42:04 kkeys Exp $";

int AppUnix::psPipe[2]; // pipe for reporting posix signals

bool AppUnix::Syslog::open(QIODevice::OpenMode mode) {
    Q_UNUSED(mode);
    openlog(APPNAME, LOG_PID, LOG_USER);
    return QIODevice::open(WriteOnly|Unbuffered);
}

qint64 AppUnix::Syslog::writeData(const char *data, qint64 maxSize)
{
    syslog(LOG_NOTICE, "%.*s", (int)maxSize, data);
    return maxSize;
}

AppUnix::AppUnix(int &argc, char **argv) : App(argc, argv), psNotifier()
{
    isInteractive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
    if (getppid() == 1) { // started by unix init or mac osx launchd
	errdev.setDevice(new Syslog(), QSL("syslog"));
	errdev.setTimestampEnabled(false);
    }
}

bool AppUnix::prestart(int &exitCode)
{
    if (optDetach) {
	// NB: we must NOT detach (daemonize) if started from Mac OSX launchd
	pid_t pid;
	if ((pid = fork()) < 0) {
	    sperr << "can't fork: " << strerror(errno) << endl;
	    return false; // skip app.exec()
	} else if (pid > 0) {
	    // parent
	    exitCode = 0; // success
	    return false; // skip app.exec() in parent
	}
	// child
	if (errdev.type() == typeid(Syslog)) {
	    // parent was using syslog; child continues to use syslog
	} else {
	    // parent was using logfile or stderr; child opens new logfile
	    errdev.setDevice(new AppLog());
	}
	setsid(); // become session leader
    }

    umask(022);
    return true;
}

void AppUnix::psHandler(int sig)
{
    if (::write(psPipe[1], &sig, sizeof(sig)) < 0)
	return; // shouldn't happen, and there's nothing we can do anyway
}

void AppUnix::psSlot()
{
    int sig = 0;
    psNotifier->setEnabled(false);
    if (::read(psPipe[0], &sig, sizeof(sig)) < 0)
	sig = 0; // shouldn't happen
    sperr << "Scheduler caught signal " << sig << endl;
    this->exit(255);
    psNotifier->setEnabled(true);
}

bool AppUnix::initSignals()
{
    // It's not safe to call Qt functions from POSIX signal handlers.  So we
    // convert POSIX signals to Qt signals using a POSIX signal handler that
    // safely writes to a pipe and a QSocketNotifier that emits a Qt signal
    // when the pipe has something to read.
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, psPipe) < 0)
	sperr << "socketpair " << strerror(errno) << endl;
    psNotifier = new QSocketNotifier(psPipe[0], QSocketNotifier::Read, this);
    connect(psNotifier, &QSocketNotifier::activated, this, &AppUnix::psSlot);

    struct sigaction act;
    act.sa_handler = AppUnix::psHandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    int sigs[] = {SIGTERM, SIGINT, SIGHUP};
    for (unsigned i = 0; i < sizeof(sigs)/sizeof(*sigs); i++) {
	int sig = sigs[i];
	if (sigaction(sig, &act, 0) < 0)
	    sperr << "sigaction(" << sig << "): " << strerror(errno) << endl;
    }
    return true;
}

#ifndef EVERYONE_IS_PRIVILEGED
void AppUnix::startProber()
{
    mode_t oldmask = 07000;
    if (!config->unprivView.variant().toBool())
	oldmask = umask(0077);
    App::startProber();
    if (oldmask != 07000)
	umask(oldmask);
}
#endif
