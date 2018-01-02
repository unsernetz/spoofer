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

#ifndef SCHEDULER_APPWIN_H
#define SCHEDULER_APPWIN_H

#include <shlobj.h> // HANDLE
#include "app.h"

class AppWin : public App {
    HANDLE winIn, winOut, winErr;
    AppWin(const AppWin&) NO_METHOD; // no copy-ctor
    AppWin operator=(const AppWin&) NO_METHOD; // no copy-assign
public:
    AppWin(int &argc, char **argv);
    void dumpPaths() const Q_DECL_OVERRIDE;
    QString chooseDataDir(bool debug) Q_DECL_OVERRIDE;
    bool parseCommandLine(QCommandLineParser &clp) Q_DECL_OVERRIDE;
    bool init(int &exitCode) Q_DECL_OVERRIDE;
    bool prestart(int &exitCode) Q_DECL_OVERRIDE;
    void readyService(int exitCode) const Q_DECL_OVERRIDE;
    void endService(int exitCode) Q_DECL_OVERRIDE;
    void end() const Q_DECL_OVERRIDE;
    bool initSignals() Q_DECL_OVERRIDE;
    void pause() Q_DECL_OVERRIDE;
    void resume() Q_DECL_OVERRIDE;
    void killProber() Q_DECL_OVERRIDE;
};

#endif // SCHEDULER_APPWIN_H
