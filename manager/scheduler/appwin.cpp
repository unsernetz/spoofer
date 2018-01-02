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
#include <QDir>
#include <QMutex>
#include <QWaitCondition>
#include <QCommandLineParser>
#include <windows.h> // GetConsoleMode(), CTRL_*_EVENT, etc
#include <shlobj.h> // SHGetFolderPath()
#include "../../config.h"
#include "appwin.h"
#include "common.h"
#include "ServiceStarterThread.h"
static const char cvsid[] ATR_USED = "$Id: appwin.cpp,v 1.30 2017/03/09 23:42:04 kkeys Exp $";

static QString lastWindowsError(void)
{
    DWORD err = GetLastError();
    wchar_t str[1024];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	nullptr, err, 0, str, sizeof(str), nullptr);
    return QString(QSL("%1 (error %2)"))
	.arg(QString::fromWCharArray(str).trimmed())
	.arg(err);
}

static bool isaconsole(HANDLE h)
{
    DWORD mode;
    return h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode);
}

AppWin::AppWin(int &argc, char **argv) : App(argc, argv),
    winIn(GetStdHandle(STD_INPUT_HANDLE)),
    winOut(GetStdHandle(STD_OUTPUT_HANDLE)),
    winErr(GetStdHandle(STD_ERROR_HANDLE))
{
    isInteractive = isaconsole(winIn) && isaconsole(winOut);
}

void AppWin::dumpPaths() const
{
    App::dumpPaths();

#define dumpWinPath(id)   do { \
    if (!SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_##id, nullptr, 0, szPath))) \
	qDebug() << #id << "\n  " << "???"; \
    else \
	qDebug() << #id << "\n  " << QString::fromWCharArray(szPath); \
} while (0)
    {
	TCHAR szPath[MAX_PATH];
	dumpWinPath(APPDATA);
	dumpWinPath(COMMON_APPDATA);
	dumpWinPath(LOCAL_APPDATA);
	dumpWinPath(PERSONAL);
	dumpWinPath(COMMON_DOCUMENTS);
	dumpWinPath(PROGRAM_FILES);
	dumpWinPath(PROGRAM_FILES_COMMON);
	dumpWinPath(PROGRAM_FILES_COMMONX86);
    }
}

QString AppWin::chooseDataDir(bool debug)
{
    // QStandardPaths::standardLocations(QStandardPaths::DataLocation) on
    // Windows seems to return only user-specific locations.  So we use
    // Windows SHGetFolderPath() instead.
    int nFolder = debug ? CSIDL_LOCAL_APPDATA : CSIDL_COMMON_APPDATA;
    TCHAR szPath[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPath(nullptr, nFolder, nullptr, 0, szPath))) {
	sperr << "can't get data folder path" << endl;
	return QString();
    }
    return QString::fromWCharArray(szPath) %
	QSL("\\") % QCoreApplication::organizationName() %
	QSL("\\") % QCoreApplication::applicationName();
}

bool AppWin::parseCommandLine(QCommandLineParser &clp)
{
    if (this->isService) {
	// QCommandLineParser gets its args from Windows GetCommandLine(),
	// with no way for us to supply our alternate arguments from SvcMain.
	// Fortunately there are no useful options when running as a service.
	return true;
    }

    if (!App::parseCommandLine(clp))
	return false;

    return true;
}

enum AppState { APPSTATE_NOTREADY, APPSTATE_READY, APPSTATE_DONE };
static QMutex appStateMutex;
static QWaitCondition appStateCond;
static AppState appState = APPSTATE_NOTREADY;
static ServiceStarterThread *starter = nullptr;

static SERVICE_STATUS svcStatus;
static SERVICE_STATUS_HANDLE svcStatusHandle;
//static HANDLE svcStopEvent = nullptr;

static void WINAPI SvcCtrlHandler(DWORD);
static void WINAPI SvcMainA(DWORD, LPSTR *);

static void ReportSvcStatus(DWORD, DWORD, DWORD);
// static void SvcReportEvent(LPTSTR);

static const SERVICE_TABLE_ENTRYA serviceTable[] = {
    { const_cast<char *>(APPNAME), SvcMainA },
    { nullptr, nullptr }
};

static void ReportSvcStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkpoint = 1;
    svcStatus.dwCurrentState = state;
    svcStatus.dwWin32ExitCode = exitCode;
    svcStatus.dwWaitHint = waitHint;

    if (state == SERVICE_START_PENDING)
	svcStatus.dwControlsAccepted = 0;
    else
	svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
	svcStatus.dwCheckPoint = checkpoint++;
    else
	svcStatus.dwCheckPoint = 0;

    SetServiceStatus(svcStatusHandle, &svcStatus);
}

void AppWin::pause()
{
    ReportSvcStatus(SERVICE_PAUSE_PENDING, NO_ERROR, 0);
    App::pause();
    ReportSvcStatus(SERVICE_PAUSED, NO_ERROR, 0);
}

void AppWin::resume()
{
    ReportSvcStatus(SERVICE_CONTINUE_PENDING, NO_ERROR, 0);
    App::resume();
    ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
}

static void WINAPI SvcCtrlHandler(DWORD ctrl)
{
    AppWin *app = static_cast<AppWin*>(QCoreApplication::instance());
    switch (ctrl) {
	case SERVICE_CONTROL_STOP:
	    App::sperr << "received SERVICE_CONTROL_STOP" << endl;
	    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
	    app->exit(0);
	    break;
	case SERVICE_CONTROL_SHUTDOWN:
	    App::sperr << "received SERVICE_CONTROL_SHUTDOWN" << endl;
	    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
	    app->exit(0);
	    break;
	case SERVICE_CONTROL_PAUSE:
	    App::sperr << "received SERVICE_CONTROL_PAUSE" << endl;
	    app->pause();
	    break;
	case SERVICE_CONTROL_CONTINUE:
	    App::sperr << "received SERVICE_CONTROL_CONTINUE" << endl;
	    app->resume();
	    break;
	case SERVICE_CONTROL_INTERROGATE:
	    qDebug() << "received SERVICE_CONTROL_INTERROGATE";
	    break;
	default:
	    break;
    }
}

static void SvcMainA(DWORD argc, LPSTR *argv)
{
    Q_UNUSED(argc);
    Q_UNUSED(argv);

    // tell main thread it can start app.exec()
    // qDebug() << "SvcMain sending READY";
    appStateMutex.lock();
    appState = APPSTATE_READY;
    appStateCond.wakeAll();

    // wait for main thread to finish app.exec()
    // qDebug() << "SvcMain waiting for DONE";
    while (appState < APPSTATE_DONE) appStateCond.wait(&appStateMutex);
    appStateMutex.unlock();
    // qDebug() << "SvcMain got DONE";
}

void ServiceStarterThread::run() {
    App *app = (App*)QCoreApplication::instance();
    app->isService = true;
    if (StartServiceCtrlDispatcherA(serviceTable)) {
	// Ran as service; SvcMain has already run in another thread.
    } else if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
	// Failed to run as service.
	app->isService = false;
	qDebug() << "StartServiceCtrlDispatcher: " << lastWindowsError();
	qDebug() << "starter sending DONE";
	appStateMutex.lock();
	appState = APPSTATE_DONE;
	appStateCond.wakeAll();
	appStateMutex.unlock();
    } else {
	// We are running as a console app, not a service.
	app->isService = false;
	SvcMainA(0, nullptr);
    }
}

bool AppWin::init(int &exitCode)
{
    exitCode = 1; // default result is failure

    // App::exec() must be run in the main thread.  But Windows'
    // StartServiceCtrlDispatcher() launches a new thread to run SvcMain(),
    // and blocks its own thread until the SvcMain() thread exits.
    // Solution:
    // Main thread launches "Starter" thread, then waits for READY.
    // Starter thread calls StartServiceCtrlDispatcher() and blocks.
    // SvcMain() thread signals READY, then waits for DONE.
    // Main thread wakes on READY, calls App::exec(), signals DONE, and exits.
    // SvcMain() thread wakes on DONE and exits.
    // Starter thread wakes on return of SvcMain(), and exits.

    // start a thread that starts a Windows Service
    starter = new ServiceStarterThread(this);
    starter->start();

    // wait for starter to tell us it's ready
    qDebug() << "main waiting for READY";
    appStateMutex.lock();
    while (appState < APPSTATE_READY) appStateCond.wait(&appStateMutex);
    appStateMutex.unlock();
    if (appState == APPSTATE_DONE) { // error in starter
	qDebug() << "main got DONE";
	return false;
    }
    qDebug() << "main got READY";

    if (this->isService) {
	svcStatusHandle = RegisterServiceCtrlHandlerA(APPNAME, SvcCtrlHandler);
	if (!svcStatusHandle) {
	    // SvcReportEvent(TEXT("RegisterServiceCtrlHandler"));
	    qDebug() << "RegisterServiceCtrlHandler failed: " << lastWindowsError();
	    return false;
	}

	svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	svcStatus.dwServiceSpecificExitCode = 0;

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
	// TODO: use a lower waitHint here so control panel doesn't wait so
	// long; and, to make sure control panel doesn't give up too early, we
	// should call ReportSvcStatus(SERVICE_START_PENDING,...) occasionally
	// to increment checkpoint between now and readyService().  Then we
	// can lower the sleep in readyService().
    }

    return App::init(exitCode);
}

bool AppWin::prestart(int &exitCode)
{
    if (!this->isService && GetConsoleWindow() && this->optDetach) {
	// Start a child process with same command line as this one, but
	// detached, with stdout and stderr redirected to a log file.
	// Exit parent without waiting for child to finish.
	QString logname = AppLog::makeName();

	STARTUPINFO startupinfo;
	memset(&startupinfo, 0, sizeof(startupinfo));
	startupinfo.cb = sizeof(STARTUPINFO);
	startupinfo.dwFlags = STARTF_USESTDHANDLES;
	startupinfo.hStdInput = INVALID_HANDLE_VALUE;

#if 1 // Windows API
	SECURITY_ATTRIBUTES secattr;
	memset(&secattr, 0, sizeof(secattr));
	secattr.nLength = sizeof(secattr);
	secattr.bInheritHandle = true;
	startupinfo.hStdOutput = startupinfo.hStdError = CreateFileA(
	    qPrintable(logname), GENERIC_WRITE, FILE_SHARE_READ,
	    &secattr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (startupinfo.hStdError == INVALID_HANDLE_VALUE) {
	    sperr << "log file " << logname << ": " << lastWindowsError() << endl;
	    return false;
	}
#else // stdio API
        FILE *out = fopen(qPrintable(logname), "wt");
        if (!out) {
            sperr << "log file " << logname << ": " << strerror(errno) << endl;
	    return false;
	}
        startupinfo.hStdOutput = startupinfo.hStdError =
	    (HANDLE)_get_osfhandle(_fileno(out));
#endif

	PROCESS_INFORMATION procinfo;
	TCHAR exename[MAX_PATH];
	GetModuleFileName(nullptr, exename, MAX_PATH);
	if (CreateProcess(exename, GetCommandLine(), nullptr, nullptr, TRUE,
	    DETACHED_PROCESS, nullptr, nullptr, &startupinfo, &procinfo))
	{
	    exitCode = 0; // success
	    qDebug() << "Detached; child pid =" << procinfo.dwProcessId;
	    sperr << "Log file: " << QDir::toNativeSeparators(logname) << endl;
	} else {
	    sperr << "Detach failed: " << lastWindowsError() << endl;
	}
	return false; // skip app.exec()
    }

    return true;
}

void AppWin::readyService(int exitCode) const
{
    if (!isService) return;
    ReportSvcStatus(SERVICE_RUNNING, (DWORD)exitCode, 0);
    if (paused) {
	QThread::msleep(3100); // hack: give control panel a chance to see SERVICE_RUNNING before we switch to SERVICE_PAUSED.
	ReportSvcStatus(SERVICE_PAUSED, NO_ERROR, 0);
    }
}

void AppWin::endService(int exitCode)
{
    if (isService)
	ReportSvcStatus(SERVICE_STOPPED, (DWORD)exitCode, 0);
    // tell starter we're done
    qDebug() << "main sending DONE";
    appStateMutex.lock();
    appState = APPSTATE_DONE;
    appStateCond.wakeAll();
    appStateMutex.unlock();
    starter->wait(1000);
    delete starter;
    App::endService(exitCode);
}

void AppWin::end() const
{
    DWORD proclist[1];
    DWORD numProcsOnConsole = GetConsoleProcessList(proclist, 1);
    if (this->isInteractive && numProcsOnConsole == 1) {
	const char prompt[] = "Press enter.\n";
	char c;
	WriteFile(this->winErr, prompt, sizeof(prompt)-1, nullptr, nullptr);
	ReadFile(this->winIn, &c, 1, nullptr, nullptr);
    }
    App::end();
}

static BOOL ConsoleCtrlHandler(DWORD type)
{
    const char *name;
    QCoreApplication *app = QCoreApplication::instance();
    switch (type) {
	case CTRL_C_EVENT:
	    name = "C";     break;
	case CTRL_CLOSE_EVENT:    // closed console or "End Task"
	    name = "Close"; break;
	case CTRL_BREAK_EVENT:
	    name = "Break"; break;
	case CTRL_LOGOFF_EVENT:
	    return true;
	case CTRL_SHUTDOWN_EVENT:
	    return true;
	default:
	    return true;
    }
    qDebug().nospace() << "Scheduler: caught Ctrl-" << name << ".";
    app->exit(255); // request app to end its event loop
    QThread::msleep(10000); // if app exits cleanly now, it'll kill this thread
    return false; // app hasn't exited; kill all threads
}

bool AppWin::initSignals()
{
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleCtrlHandler, TRUE);
    return true;
}

void AppWin::killProber()
{
    // prober->terminate() does not work with non-gui processes like prober
    prober->kill();
}
