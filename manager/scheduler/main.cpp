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
#include <stdexcept>
#include "spoof_qt.h"
#include <QThread>
#include "../../config.h"
#include "app.h"
#include "common.h"
static const char cvsid[] ATR_USED = "$Id: main.cpp,v 1.32 2017/03/09 23:42:05 kkeys Exp $";

int main(int argc, char *argv[])
{
    setvbuf(stderr, NULL, _IONBF, 0); // in case it's not a terminal/console
    int retval = 1; // fail
    App *app = App::newapp(argc, argv);

    if (!app->init(retval)) goto done;
    app->readyService(retval);
    retval = app->exec();

done:
    app->endService(retval);
    app->sperr << App::appname << " exiting, code " << retval << endl;
    app->end();
    delete app;
    return retval;
}
