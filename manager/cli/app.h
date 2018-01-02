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

#include <QCoreApplication>
#include "SpooferUI.h"

// forward declarations
QT_BEGIN_NAMESPACE
class QLocalSocket;
class QSocketNotifier;
class QTextStream;
QT_END_NAMESPACE
class InputReader;

class App : public QCoreApplication, public SpooferUI {
    App(const App&) NO_METHOD; // no copy-ctor
    App operator=(const App&) NO_METHOD; // no copy-assign
    Q_OBJECT

public:
    App(int &argc, char **argv);
    ~App();
    int exec();
    bool parseCommandLine(QCommandLineParser &clp);
private:
    static const QString help;
    InputReader *inReader;
    QString command;
    void startFileTail(QString logname) Q_DECL_OVERRIDE;
    bool connectScheduler(bool privileged);
private slots:
    void initEvents();
    void schedConnected();
    void schedDisconnected();
    void schedError();
    void readScheduler() { SpooferUI::readScheduler(); }
    void execCmd(std::string *str);
    void handleProberText(QString *text) { SpooferUI::handleProberText(text); }
    bool finishProber() Q_DECL_OVERRIDE { return SpooferUI::finishProber(); }
    void doneCmd(int code) Q_DECL_OVERRIDE
	{ if (!command.isEmpty()) this->exit(code); }
};
