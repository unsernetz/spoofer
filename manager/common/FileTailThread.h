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

#ifndef FILETAILTHREAD_H
#define FILETAILTHREAD_H

#include <QThread>
#include <QFile>
#include <QDebug>
// #include <iostream> // std::cerr
#include "port.h"

class FileTailThread : public QThread
{
    Q_OBJECT
    QFile file;
    unsigned long timeout;
    bool opened;
    ATR_UNUSED_MEMBER uint8_t unused_padding[3];

public:
    FileTailThread(const QString &filename, QObject *_parent = nullptr) :
	QThread(_parent), file(filename), timeout(0), opened(false)
    {
	typedef QIODevice D;
	if (file.fileName().isEmpty()) {
	    qWarning() << "missing file name";
	} else if (!file.open(D::ReadOnly | D::Text | D::Unbuffered)) {
	    qWarning().nospace() << qPrintable(file.fileName()) << ": " <<
		qPrintable(file.errorString());
	} else {
	    opened = true;
	}
    }

    ~FileTailThread() {
	// std::cerr << "FileTailThread dtor\n";
    }

    void run() Q_DECL_OVERRIDE {
	// Note: it may not be safe to generate log messages from this thread
	if (!opened) return;
	char data[4096];
	int n;
	unsigned long waited = 0;
	while ((n = int(file.read(data, sizeof(data) - 1))) >= 0) {
	    if (n > 0) {
		waited = 0;
		emit dataReady(new QString(QString::fromLocal8Bit(data, n)));
	    } else if (isInterruptionRequested()) {
		break;
	    } else { // no data
		if (timeout > 0 && waited > timeout)
		    break;
		msleep(20);
		waited += 20;
	    }
	}
	// std::cerr << "FileTailThread exiting\n";
    };

    // Tell run() to exit after a period of inactivity.
    void setTimeout(unsigned long usec) { timeout = usec; }

signals:
    void dataReady(QString *s);

public slots:
    void abort() { // terminate without delivering finished() or other signal
	// std::cerr << "FileTailThread abort\n";
	disconnect(this, nullptr, nullptr, nullptr);
	this->terminate();
    }
};

#endif // FILETAILTHREAD_H
