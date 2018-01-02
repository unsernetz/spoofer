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

#ifndef SPOOFERUI_H
#define SPOOFERUI_H

#include <QLocalSocket>
#include "common.h"

// forward declarations
class FileTailThread;

// base class for Spoofer user interface applications
class SpooferUI : public SpooferBase {
private:
    SpooferUI(const SpooferUI&) NO_METHOD; // no copy-ctor
    void operator=(const SpooferUI&) NO_METHOD; // no copy-assign
protected:
    QLocalSocket *scheduler;
    FileTailThread *fileTail;
    int proberExitCode;
    int proberExitStatus;
    sc_msg_scheduled nextProberStart;
    bool connectionIsPrivileged;
    bool schedulerPaused;
    bool schedulerNeedsConfig;
private:
    ATR_UNUSED_MEMBER uint8_t unused_padding[2];
protected:

    SpooferUI() :
	scheduler(), fileTail(), proberExitCode(), proberExitStatus(),
	nextProberStart(), connectionIsPrivileged(false),
	schedulerPaused(false), schedulerNeedsConfig(false)
	{ }
    virtual ~SpooferUI() {}

    bool connectToScheduler(bool privileged) {
	if (!config->sync()) // make sure we have the latest settings
	    return false;
	QString schedulerSocketName = config->schedulerSocketName();
	if (schedulerSocketName.isEmpty()) {
	    qCritical().nospace() << "There is no scheduler running "
		"using settings in " << qPrintable(config->fileName()) <<
		" (\"schedulerSocketName\" is not set).";
	    return false;
	}
	if (!privileged) schedulerSocketName.append(QSL("o"));
	connectionIsPrivileged = privileged;
	scheduler->setServerName(schedulerSocketName);
	qDebug() << "UI: connecting to scheduler at" <<
	    qPrintable(schedulerSocketName) << "...";
	scheduler->connectToServer();
	return true;
    }

#ifdef VISIT_URL
    static bool visitURL(const char *url);
    static void visitEmbeddedURLs(const QString *text);
#endif
    virtual void startFileTail(QString logname) = 0;
    virtual bool finishProber(void);
    virtual void printNextProberStart(void);
    void readScheduler(void);
    void handleProberText(QString *text);
    virtual void doneCmd(int code) { Q_UNUSED(code); /* do nothing */ }
    virtual void configChanged() { /* do nothing */ }
    virtual void needConfig() { /* do nothing */ }
};

#endif // SPOOFERUI_H
