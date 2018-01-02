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

#include <time.h>
#include "spoof_qt.h"
#include <QCommandLineParser>
#include <QtGlobal>
#include <QDir>
#include <QProcess>
#ifdef VISIT_URL
 #ifdef Q_OS_WIN32
  #include <windows.h> // for shellapi.h
  #include <shellapi.h> // for ShellExecute()
 #endif
 #ifdef Q_OS_UNIX
  #include <sys/wait.h>
 #endif
#endif
#include "../../config.h"
#include "SpooferUI.h"
#include "FileTailThread.h"
#include "BlockReader.h"
static const char cvsid[] ATR_USED = "$Id: SpooferUI.cpp,v 1.34 2017/09/29 19:04:10 kkeys Exp $";

#ifdef VISIT_URL
// Visit a URL using the default web browser.  (Unlike
// QDesktopServices::openUrl(), this does not require linking with QtGui.)
bool SpooferUI::visitURL(const char *url)
{
#if defined(Q_OS_WIN32)
    return (int)ShellExecuteA(nullptr, nullptr, url, nullptr, nullptr,
	SW_SHOWNORMAL) > 32;
#else
    char buf[1024];
#if defined(Q_OS_MAC)
    snprintf(buf, sizeof(buf), "open '%s'", url);
#elif defined(Q_OS_UNIX)
    snprintf(buf, sizeof(buf), "xdg-open '%s'", url);
#endif
    int rc = system(buf);
    return rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0;
#endif
}

void SpooferUI::visitEmbeddedURLs(const QString *text)
{
    // If text contains a URL, open it in a web browser.
    static QString prefix("http://");
    int i = 0;
    while (i < text->size()) {
	if ((*text)[i].isSpace()) {
	    i++; // skip leading space on a line
	} else {
	    int n = text->indexOf("\n", i);
	    if (n < 0) n = text->size();
	    QStringRef line = text->midRef(i, n-i);
	    if (line.startsWith(prefix))
		visitURL(qPrintable(line.toString()));
	    i = n+1; // jump to next line
	}
    }
}
#endif

void SpooferUI::printNextProberStart()
{
    time_t when = nextProberStart.when;
    if (when)
	spout << "Next prober scheduled for " << qPrintable(ftime(QString(), &when)) << endl;
    else
	spout << "No prober scheduled." << endl;
}

void SpooferUI::readScheduler()
{
    qint32 type;
    sc_msg_text msg;
    QStringList keys;
    while (!scheduler->atEnd()) {
	BlockReader in(scheduler);
	in >> type;
	switch (type) {
	    case SC_DONE_CMD:
		doneCmd(0);
		break;
	    case SC_CONFIG_CHANGED:
		spout << "Settings changed." << endl;
		config->sync();
		configChanged();
		break;
	    case SC_ERROR:
		in >> msg;
		qCritical() << "Error:" << qPrintable(msg.text);
		doneCmd(1);
		break;
	    case SC_TEXT:
		in >> msg;
		spout << "Scheduler: " << msg.text << endl;
		doneCmd(0);
		break;
	    case SC_PROBER_STARTED:
		in >> msg;
		spout << "Prober started; log: " <<
		    QDir::toNativeSeparators(msg.text) << endl;
		nextProberStart.when = 0;
		proberExitCode = 0;
		proberExitStatus = QProcess::CrashExit;
		startFileTail(msg.text);
		break;
	    case SC_PROBER_FINISHED:
		// Don't print exit code/status, just store them, and ask
		// fileTail to stop.  When fileTail is done reading the log,
		// it will signal finished, and finishProber() will run.
		in >> proberExitCode >> proberExitStatus;
		if (fileTail && fileTail->isRunning())
		    fileTail->requestInterruption();
		else // fileTail failed to start or exited early
		    finishProber();
		break;
	    case SC_PROBER_ERROR:
		in >> msg;
		qWarning() << "Prober error:" << qPrintable(msg.text);
		doneCmd(1);
		break;
	    case SC_SCHEDULED:
		in >> nextProberStart;
		if (!fileTail || !fileTail->isRunning()) printNextProberStart();
		    // else, wait until finishProber()
		break;
	    case SC_PAUSED:
		spout << "Scheduler paused." << endl;
		nextProberStart.when = 0;
		schedulerPaused = true;
		printNextProberStart();
		break;
	    case SC_RESUMED:
		spout << "Scheduler resumed." << endl;
		schedulerPaused = false;
		break;
	    case SC_NEED_CONFIG:
		for (auto m : config->members) {
		    if (!m->isSet() && m->required)
			keys << m->key;
		}
		spout << "The following required settings must be set: " <<
		    keys.join(QSL(", ")) << endl;
		schedulerNeedsConfig = true;
		needConfig();
		break;
	    case SC_CONFIGED:
		spout << "Scheduler is configured." << endl;
		schedulerNeedsConfig = false;
		break;
	    default:
		qCritical() << "Illegal message from scheduler.";
		scheduler->abort();
	}
    }
}

void SpooferUI::handleProberText(QString *text)
{
    // remove each backspace and the character before it
    int n = 1;
    while ((n = text->indexOf(QSL("\b"))) > 0) {
	text->remove(n-1, 2);
    }

    spout << *text << flush;
#ifdef VISIT_URL
    visitEmbeddedURLs(text);
#endif
    delete text;
}

bool SpooferUI::finishProber()
{
    if (proberExitStatus == QProcess::NormalExit) {
	spout << "prober exited normally, exit code " << proberExitCode << endl;
    } else {
	sperr << "prober exited abnormally" << endl;
    }
    if (fileTail) fileTail->deleteLater();
    fileTail = nullptr;
    printNextProberStart();
    doneCmd(0);
    return true;
}
