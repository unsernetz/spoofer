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

#ifndef SCHEDULER_APP_H
#define SCHEDULER_APP_H

#include <QProcess>
#include <QSet>
#include <QFile>
#include <QTimer>
#include <QHash>
#include "common.h"

QT_BEGIN_NAMESPACE
class QLocalSocket;
class QLocalServer;
class QNetworkConfigurationManager;
class QLockFile;
class QCommandLineOption;
class QFileSystemWatcher;
QT_END_NAMESPACE

#define APPNAME "spoofer-scheduler"

class SubnetAddr : public QPair<QHostAddress,int> {
public:
    SubnetAddr(const QHostAddress &haddr, int len) : QPair(haddr, len) {}
    SubnetAddr(const QPair<QHostAddress,int> &pair) : QPair(pair) {}
    QHostAddress addr() const { return first; }
    int pfxlen() const { return second; }
    SubnetAddr prefix() const;
    QString toString() const {
	return addr().toString() % QSL("/") % QString::number(pfxlen());
    }
};

class App : public QCoreApplication, public SpooferBase {
    Q_OBJECT

    App(const App&) NO_METHOD; // no copy-ctor
    void operator=(const App&) NO_METHOD; // no copy-assign

protected:
    class AppLog : public QFile {
    public:
	static QString makeName();
	AppLog() : QFile(makeName()) {}
    };

    struct RunRecord {
	time_t t;
	int errors;
    };

    App(int &argc, char **argv) :
	QCoreApplication(argc, argv), SpooferBase(),
	optSharePublic(-1), optShareRemedy(-1), optInitOnly(false),
	optDeleteData(false), optDeleteSettings(false),
	optSaveSettings(false), optRestoreSettings(false), altSettingsFile(),
	optDumpPaths(false), optDumpSettings(false), optCheckSettings(false),
	optDetach(false),
	optLogfile(false), optStartPaused(-1), optDataDir(),
	isInteractive(false), isService(false), paused(false),
	settingLockFile(), dataLockFile(), privServer(), unprivServer(),
	uiSet(), prober(), proberOutputFileName(), scheduledSubnets(),
	nextProberStart(), proberTimer(), netPollTimer(), pastRuns(),
	hangTimer(), proberWatcher()
	{ }
public:
    virtual ~App();
    static App *newapp(int &argc, char **argv);
    void cleanup(void);
    virtual bool parseCommandLine(QCommandLineParser &clp);
    bool parseOptionFlag(int &opt, QCommandLineParser &clp,
	const QCommandLineOption &clo);
    virtual void dumpPaths(void) const;
    virtual void dumpSettings(void) const;
    virtual QString chooseDataDir(bool debug);
    QLockFile *lockLockFile(QString name);
    virtual bool init(int &exitCode);
    virtual bool prestart(int &exitCode) { Q_UNUSED(exitCode); return true; }
    virtual void readyService(int exitCode) const { Q_UNUSED(exitCode); }
    virtual void endService(int exitCode) { Q_UNUSED(exitCode); }
    virtual void end() const {};
    virtual bool initSignals() = 0;
    virtual void pause();
    virtual void resume();
    static const QString appname;
    static const QString schedulerLogFtime;
    static const QString schedulerLogGlob;
    int optSharePublic;
    int optShareRemedy;
    bool optInitOnly;
    bool optDeleteData;
    bool optDeleteSettings;
    bool optSaveSettings;
    bool optRestoreSettings;
    QString altSettingsFile;
    bool optDumpPaths;
    bool optDumpSettings;
    bool optCheckSettings;
    bool optDetach;
    bool optLogfile;
    int optStartPaused;
    QString optDataDir;
    bool isInteractive;
    bool isService;
    bool paused; // actual current state (cf. config->paused(), desired state)
protected:
    static QString defaultDataDir;
    static QString dataDir;

    QLockFile *settingLockFile, *dataLockFile;
    QLocalServer *privServer;
    QLocalServer *unprivServer;
    QSet<QLocalSocket *> uiSet;
    QProcess *prober;
    QString proberOutputFileName;
    QSet<SubnetAddr> scheduledSubnets;
    sc_msg_scheduled nextProberStart;
    QTimer proberTimer;
    QTimer netPollTimer;
    // pastRuns is indexed not by the full address of interfaces, but by their
    // subnet prefixes, so that:  1) a new prober run is not triggered when
    // the host moves within a subnet or uses a different temporary IPv6
    // address; 2) history isn't cluttered with random temporary IPv6 addrs.
    QHash<SubnetAddr, RunRecord> pastRuns;
    QTimer *hangTimer;
    QFileSystemWatcher *proberWatcher;

    QLocalServer *listen(bool privileged);
    bool opAllowed(QLocalSocket *ui, const Config::MemberBase &cfgItem);
    bool opAllowedVerbose(QLocalSocket *ui, const Config::MemberBase &cfgItem);
    void recordRun(bool success);
    virtual void startProber();
    virtual void killProber();
    virtual void shutdown() { this->exit(0); }
    QList<SubnetAddr> getAddresses() const;
#ifdef ENABLE_QNetworkConfigurationManager
    QNetworkConfigurationManager *ncm; // experimental
#endif

private slots:
    void uiRead();
    void uiAccept();
    void uiDelete();
    void resetHangTimer();
    void proberStarted();
    void proberError(QProcess::ProcessError);
    void proberFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void dumpNetCfg(QLocalSocket *ui);
    void handleNetChange();
    void scheduleNextProber();
};

#endif // SCHEDULER_APP_H
