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

#ifndef SCHEDULER_APPUNIX_H
#define SCHEDULER_APPUNIX_H

#include "app.h"

QT_BEGIN_NAMESPACE
class QSocketNotifier;
QT_END_NAMESPACE

class AppUnix : public App {
    Q_OBJECT

    AppUnix(const AppUnix&) NO_METHOD; // no copy-ctor
    AppUnix operator=(const AppUnix&) NO_METHOD; // no copy-assign

    class Syslog : public QIODevice {
    public:
	Syslog() : QIODevice() {}
	bool open(QIODevice::OpenMode mode) Q_DECL_OVERRIDE;
    protected:
	qint64 readData(char *data, qint64 maxSize) Q_DECL_OVERRIDE
	    { Q_UNUSED(data); Q_UNUSED(maxSize); return -1; }
	qint64 writeData(const char *data, qint64 maxSize) Q_DECL_OVERRIDE;
    };

    // posix signal handling
    static int psPipe[2];
    QSocketNotifier *psNotifier;
    static void psHandler(int sig);
public:
    AppUnix(int &argc, char **argv);
    bool prestart(int &exitCode) Q_DECL_OVERRIDE;
    bool initSignals() Q_DECL_OVERRIDE;
#ifndef EVERYONE_IS_PRIVILEGED
    void startProber() Q_DECL_OVERRIDE;
#endif
private slots:
    void psSlot();
};

#endif // SCHEDULER_APPUNIX_H
