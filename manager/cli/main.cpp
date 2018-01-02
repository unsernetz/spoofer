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

#include <iostream>
#include "spoof_qt.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QtDebug>
#include "../../config.h"
#include "app.h"
static const char cvsid[] ATR_USED = "$Id: main.cpp,v 1.14 2017/03/09 23:42:01 kkeys Exp $";

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int retval = -1;
    App app(argc, argv);

    QCommandLineParser clp;
    if (!app.parseCommandLine(clp)) {
	retval = 1;
	goto done;
    }

    if (!app.initConfig()) {
	retval = 1;
	goto done;
    }

    retval = app.exec();
done:
    qDebug() << "exit " << retval;
    return retval;
}
