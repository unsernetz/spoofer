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

// InputReader reads lines from stin and delivers them with a Qt signal,
// allowing integration with a Qt event loop.
#ifndef INPUTREADER_H
#define INPUTREADER_H

#include <QtGlobal>
#ifdef Q_OS_UNIX
 #include <cstdio>
 #include <unistd.h>
 #include <errno.h>
 #include <QSocketNotifier>
#else
 #include <iostream>
 #include <QThread>
#endif
#include <QString>
#include <QDebug>
#include "port.h"

class InputReader
#ifdef Q_OS_UNIX
    : public QObject
#else
    : public QThread
#endif
{
    Q_OBJECT

    InputReader(const InputReader&) NO_METHOD; // no copy-ctor
    InputReader operator=(const InputReader&) NO_METHOD; // no copy-assign

#ifdef Q_OS_UNIX
    // Use a QSocketNotifier to signal us when stdin is readable.
    QSocketNotifier notifier;
    std::string *str;

public:
    InputReader(QObject *_parent = nullptr) :
	QObject(_parent),
	notifier(STDIN_FILENO, QSocketNotifier::Read, this),
	str(new std::string())
    { }

    void wait(unsigned long t) { Q_UNUSED(t); } // for compatibility

private slots:
    // Read available text from stdin.  Won't block if triggered by
    // notifer->activated().  If a newline is seen, emits dataReady().
    void read() {
	char buf[1024];
	ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
	if (n == 0) {
	    qDebug() << "InputReader eof";
	    emit finished();
	} else if (n < 0 && errno != EINTR) {
	    qDebug("InputReader error %d: %s", errno, strerror(errno));
	    emit finished();
	} else if (n > 0) {
	    unsigned int i, lineStart = 0;
	    for (i = 0; i < unsigned(n); i++) {
		if (buf[i] != '\n') continue;
		str->append(buf+lineStart, i-lineStart);
		emit dataReady(str); // receiver will delete str
		str = new std::string();
		lineStart = i+1;
	    }
	    str->append(buf+lineStart, i-lineStart); // save incomplete line
	}
    }

signals:
    void finished();
    void dataReady(std::string *str);

public slots:
    void start() {
	connect(&notifier, &QSocketNotifier::activated, this, &InputReader::read);
    }

    void abort() { // terminate without delivering finished() or other signals
	qDebug() << "InputReader abort";
	disconnect(this, nullptr, nullptr, nullptr);
	disconnect(&notifier, nullptr, nullptr, nullptr);
    }


#else // ! Q_OS_UNIX
    // On platforms where QSocketNotifier does not work (Windows), do a
    // blocking read in a thread.  This is less preferred because some
    // platforms (Mac) provide no way to cleanly terminate the thread while
    // it's in a blocking read.
public:
    InputReader(QObject *_parent = nullptr) :
	QThread(_parent)
	{ }
    void run() Q_DECL_OVERRIDE {
	while (!this->isInterruptionRequested()) {
	    std::string *str = new std::string();
	    std::getline(std::cin, *str);
	    if (std::cin.eof() || std::cin.bad()) {
		delete str;
		break;
	    }
	    emit dataReady(str); // receiver will delete str
	}
	qDebug() << "InputReader exiting";
    };

signals:
    void dataReady(std::string *str);

public slots:
    void abort() { // terminate without delivering finished() or other signals
	qDebug() << "InputReader abort";
	disconnect(this, nullptr, nullptr, nullptr);
	this->terminate();
    }
#endif

public:
    ~InputReader() {
	qDebug() << "InputReader dtor";
    }
};

#endif // INPUTREADER_H
