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

#include "spoof_qt.h"
#include <QTimer>
#include <QDir>
#include <QCommandLineParser>
#include "../../config.h"
#include "InputReader.h"
#include "FileTailThread.h"
#include "app.h"
static const char cvsid[] ATR_USED = "$Id: app.cpp,v 1.67 2017/07/26 00:31:13 kkeys Exp $";

const QString App::help = QSL(
    "run - run the prober (and update the schedule)\n"
    "abort - stop a running prober process\n"
    "pause - prevent scheduled prober runs\n"
    "resume - resume scheduled prober runs\n"
    "shutdown - shutdown the scheduler process\n"
    "set - display all settings\n"
    "set <name> <value> - change a setting\n"
    "help - display this help\n"
    "quit - exit the manager CLI\n");

App::App(int &argc, char **argv) :
    QCoreApplication(argc, argv), SpooferUI(),
    inReader(), command()
{ }

App::~App() {
    qDebug() << "CLI: App dtor";
    // avoid "QThread: Destroyed while thread is still running"
    if (fileTail) fileTail->wait(1000);
    if (inReader) inReader->wait(1000);
    qDebug() << "CLI: App dtor done";
}

bool App::parseCommandLine(QCommandLineParser &clp)
{
    clp.addPositionalArgument(QSL("command"), QSL(
	"Execute a single spoofer scheduler command.  If <command> is omitted "
	"on the command line, the cli will run in interactive mode.\n") %
	App::help,
	QSL("[command]"));
    if (!SpooferBase::parseCommandLine(clp, QSL("Spoofer scheduler command line interface")))
	return false;

    QStringList args = clp.positionalArguments();
    if (!args.isEmpty())
	command = args.join(QSL(" "));

    return true;
}

// Do extra initialization before QCoreApplication::exec().
int App::exec()
{
    QTimer::singleShot(1, this, SLOT(initEvents()));
    return QCoreApplication::exec();
}

bool App::connectScheduler(bool privileged)
{
    connect(scheduler, &QLocalSocket::connected, this, &App::schedConnected);
    connect(scheduler, &QLocalSocket::disconnected,
	this, &App::schedDisconnected);
    connect(scheduler, SIGCAST(QLocalSocket, error, (QLocalSocket::LocalSocketError)),
	this, &App::schedError);
    connect(scheduler, &QLocalSocket::readyRead, this, &App::readScheduler);

    return connectToScheduler(privileged);
}

// Initialize things that expect event loop to be running (including anything
// that might trigger App::exit()).
void App::initEvents()
{
    scheduler = new QLocalSocket(this);
    if (command.isEmpty()) {
	inReader = new InputReader(this);
	connect(inReader, &InputReader::dataReady, this, &App::execCmd);
	connect(inReader, &InputReader::finished, this, &App::quit); // EOF
	connect(this, &App::aboutToQuit, inReader, &InputReader::abort);
	inReader->start();
    }

    if (!connectScheduler(true)) {
	if (command.isEmpty()) this->exit(1);
	else execCmd(new std::string(command.toStdString()));
    }
}

void App::schedConnected()
{
    spout << "Connected to scheduler." << endl;
    connect(this, &App::aboutToQuit, scheduler, &QLocalSocket::close);
    schedulerPaused = false; // until told otherwise
    if (fileTail) // stale
	fileTail->requestInterruption();
    if (!command.isEmpty()) {
	execCmd(new std::string(command.toStdString()));
    }
}

void App::schedDisconnected()
{
    spout << "Scheduler disconnected" << endl;
    disconnect(this, nullptr, scheduler, nullptr);
    disconnect(scheduler, nullptr, nullptr, nullptr);
    this->exit(1);
}

void App::schedError()
{
    spout << "Scheduler error: " << scheduler->errorString() << endl;
    scheduler->abort();
    scheduler->close();
    scheduler->deleteLater();
    scheduler = new QLocalSocket(this);
#ifndef EVERYONE_IS_PRIVILEGED
    if (connectionIsPrivileged && connectScheduler(false))
	return;
#endif
    disconnect(this, nullptr, scheduler, nullptr);
    disconnect(scheduler, nullptr, nullptr, nullptr);
    this->exit(1);
}

void App::startFileTail(QString logname)
{
    fileTail = new FileTailThread(logname, this);
    connect(fileTail, &FileTailThread::dataReady,
	this, &App::handleProberText);
    connect(fileTail, &FileTailThread::finished,
	this, &App::finishProber);
    connect(this, &App::aboutToQuit,
	fileTail, &FileTailThread::abort);
    fileTail->start();
}

void App::execCmd(std::string *str)
{
    qDebug() << "execCmd:" << str->c_str();
    if (str->compare("quit") == 0 || str->compare("exit") == 0) {
	qDebug() << "CLI: quit";
	this->quit();
    } else if (str->compare("help") == 0 || str->compare("?") == 0) {
	spout << App::help << endl;
	doneCmd(0);
    } else if (str->compare("set") == 0) {
	for (auto m : Config::members) {
	    spout << "# " << m->key << ": " << m->desc;
	    if (m->required) spout << " (REQUIRED)";
	    spout << endl;
	    if (!m->isSet()) spout << "# ";
	    spout << "set " << m->key << " " <<
		m->variant().toString() << endl << endl;
	}
	doneCmd(0);
    } else if (str->size() > 0) {
	qDebug() << "CLI: send:" << str->c_str();
	if (scheduler->state() == QLocalSocket::ConnectedState) {
	    scheduler->write(str->c_str(), static_cast<qint64>(str->size()));
	} else {
	    spout << "Warning: Not connected to scheduler." << endl;
	    doneCmd(1);
	}
    }
    delete str;
}

