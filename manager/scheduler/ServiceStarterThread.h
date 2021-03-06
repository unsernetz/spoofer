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

#ifndef SERVICESTARTERTHREAD_H
#define SERVICESTARTERTHREAD_H

#include <QThread>
#include <QDebug>

class ServiceStarterThread : public QThread
{
public:
    ServiceStarterThread(QObject *_parent = nullptr) : QThread(_parent) { }
public slots:
    void run() Q_DECL_OVERRIDE;
};

#endif // SERVICESTARTERTHREAD_H
