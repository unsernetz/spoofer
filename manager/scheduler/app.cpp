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

#include <string>
#include <sstream>
#include <exception>
#include <stdexcept>
#include <cstdio>
#include <time.h>
#include <errno.h>
#include "spoof_qt.h"
#include <QDebug>
#include <QtDebug>
#include <QCommandLineParser>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QStandardPaths>
#include <QDir>
#ifdef ENABLE_QNetworkConfigurationManager
#include <QNetworkConfigurationManager> // experimental
#endif
#include <QNetworkInterface>
#include <QCoreApplication>
#include <QLockFile>
#include <QRegularExpression>
#include <QTextStream>
#include <QFileSystemWatcher>
#include "../../config.h"
#include "app.h"
#include "BlockWriter.h"

#ifdef Q_OS_UNIX
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h> // getpid()
#endif

static const char cvsid[] ATR_USED = "$Id: app.cpp,v 1.196 2017/12/06 02:09:04 kkeys Exp $";

const QString App::appname(QSL(APPNAME));
const QString App::schedulerLogFtime = QSL("'" APPNAME "-'yyyy~MM~dd-HH~mm~ss'.txt'");
const QString App::schedulerLogGlob = QSL(APPNAME "-\?\?\?\?\?\?\?\?-\?\?\?\?\?\?.txt"); 
QString App::defaultDataDir;
QString App::dataDir;

#if defined(Q_OS_WIN32)
#   include "appwin.h"
    App *App::newapp(int &argc, char **argv) { return new AppWin(argc, argv); }
#elif defined(Q_OS_MAC) // must come before Q_OS_UNIX
#   include "appmac.h"
    App *App::newapp(int &argc, char **argv) { return new AppMac(argc, argv); }
#elif defined(Q_OS_UNIX)
#   include "appunix.h"
    App *App::newapp(int &argc, char **argv) { return new AppUnix(argc, argv); }
#endif

static void copySettings(QSettings &dst, const QSettings &src)
{
    QStringList keys = src.allKeys();
    for (auto key : keys) {
	dst.setValue(key, src.value(key));
    }
}

QString App::AppLog::makeName()
{
    QDir dir(dataDir);
    return dir.filePath(ftime_utc(schedulerLogFtime));
}

QList<SubnetAddr> App::getAddresses() const
{
    QList<SubnetAddr> addrs;
    QList<QNetworkInterface> ifaces = QNetworkInterface::allInterfaces();
    foreach (QNetworkInterface iface, ifaces) {
	if (!iface.isValid()) continue;
	if (!(iface.flags() & QNetworkInterface::IsRunning)) continue;
	if (!(iface.flags() & QNetworkInterface::IsUp)) continue;
	if ((iface.flags() & QNetworkInterface::IsLoopBack)) continue;
	QList<QNetworkAddressEntry> addrentries = iface.addressEntries();
#define _container_ _container2_  // avoid a shadow warning in Qt's foreach()
	foreach (QNetworkAddressEntry addrentry, addrentries) {
	    QHostAddress addr = addrentry.ip();
	    if (addr.isNull()) continue;
	    if (addr.isLoopback()) continue;
	    if (!addr.scopeId().isEmpty()) continue; // link-local or site-local
	    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
		if (!config->enableIPv4()) continue;
		if (addrentry.prefixLength() == 32)
		    continue; // skip address with full-length mask
	    } else if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
		if (!config->enableIPv6()) continue;
		if (addrentry.prefixLength() == 128)
		    continue; // skip address with full-length mask
	    }
	    addrs.push_back(SubnetAddr(addr, addrentry.prefixLength()));
	}
    }
    return addrs;
}

SubnetAddr SubnetAddr::prefix() const
{
    if (addr().protocol() == QAbstractSocket::IPv4Protocol) {
	quint32 raw = addr().toIPv4Address();
	raw &= (0xFFFFFFFF << (32 - pfxlen()));
	return SubnetAddr(QHostAddress(raw), pfxlen());

    } else if (addr().protocol() == QAbstractSocket::IPv6Protocol) {
	Q_IPV6ADDR raw = addr().toIPv6Address();
	for (int i = 0, n = pfxlen(); i < 16; i++, n -= 8) {
	    if (n <= 0) {
		raw[i] = 0;
	    } else if (n < 8) {
		raw[i] = quint8(raw[i] & (~0xFFu >> n));
	    }
	}
	return SubnetAddr(QHostAddress(raw), pfxlen());
    } else {
	return SubnetAddr(QHostAddress(), 0);
    }
}

void App::handleNetChange()
{
    qDebug() << "possible network change detected" << qPrintable(ftime_utc());
    proberTimer.stop(); // Temporarily prevent prober from starting.
    // Do NOT reset nextProberStart.when here.  If scheduleNextProber() finds
    // no relevant change in the network config, it will restart the timer to
    // resume the original schedule.
    if (prober) return; // prober is running now
    // Wait 1s (in case of a burst of changes), then scheduleNextProber()
    netPollTimer.start(1000*1);
}

void App::scheduleNextProber()
{
    time_t now, nextProbe = 0, nextPoll = 0;
    if (prober) return; // prober is running now
    if (paused || !config->hasRequiredSettings()) return;
    proberTimer.stop();
    netPollTimer.stop();
    time(&now);
    nextPoll = now + config->netPollInterval();

    QList<SubnetAddr> addrs = getAddresses();
    QSet<SubnetAddr> subnets;
    foreach (SubnetAddr addr, addrs) {
	subnets.insert(addr.prefix());
    }

    if (nextProberStart.when && subnets == scheduledSubnets) {
	// No change.  Resume original schedule.
	qDebug() << "scheduleNextProber: no relevant change in network config";
	nextProbe = nextProberStart.when;

    } else if (!subnets.isEmpty()) {
	foreach (SubnetAddr subnet, subnets) {
	    if (!scheduledSubnets.contains(subnets))
		sperr << "new subnet detected: " << subnet.toString() << endl;
	}
	qDebug() << "scheduleNextProber" << qPrintable(ftime_utc(QString(), &now));
	foreach (SubnetAddr subnet, subnets) {
	    const RunRecord &rr = pastRuns[subnet];
	    time_t interval = config->proberInterval();
	    if (rr.errors > 0 && rr.errors <= config->maxRetries()) {
		// exponential backoff, capped at proberInterval
		interval = config->proberRetryInterval();
		for (int i = 1; i < rr.errors; i++) {
		    interval <<= 1;
		    if (interval >= config->proberInterval()) {
			interval = config->proberInterval();
			break;
		    }
		}
	    }
	    time_t t = rr.t + interval;
	    if (!nextProbe || t < nextProbe) nextProbe = t;
	}
	qDebug() << "  earliest" << qPrintable(ftime_utc(QString(), &nextProbe));
	if (nextProbe < now + config->delayInterval())
	    nextProbe = now + config->delayInterval();
	// Re-check the network configuration <delayInterval> before the next
	// scheduled run, or after <netPollInterval>, whichever is earlier.
	if (nextPoll > nextProbe - config->delayInterval() && nextProbe - config->delayInterval() > now)
	    nextPoll = nextProbe - config->delayInterval();
    }

    scheduledSubnets = subnets;

    if (!nextProbe || nextProbe > nextPoll) {
	// Schedule another netPoll before the next prober.
	netPollTimer.start(1000 * static_cast<int>(nextPoll - now));
    } else {
	// Schedule a prober before the next netPoll.
	// NB: more than ~24 days would overflow proberTimer.start()'s int
	// parameter (but nextPoll is guaranteed to earlier than that).
	proberTimer.start(nextProbe <= now ? 1 : 1000 * static_cast<int>(nextProbe - now));
    }

    QString label = nextProbe ? ftime_utc(QString(), &nextProbe) : QSL("never");
    if (nextProbe != nextProberStart.when) {
	sperr << "next prober run: " << label << endl;
	nextProberStart.when = safe_int<qint32>(nextProbe);
	foreach (QLocalSocket *ui, uiSet) {
	    if (opAllowed(ui, config->unprivView))
		BlockWriter(ui) << (qint32)SC_SCHEDULED << nextProberStart;
	}
    } else {
	qDebug() << "next prober run:" << qPrintable(label) << "(silent)";
    }
}

void App::dumpNetCfg(QLocalSocket *ui)
{
    QList<SubnetAddr> addrs = getAddresses();
    foreach (SubnetAddr addr, addrs) {
	QString msg =
	    (addr.addr().protocol() == QAbstractSocket::IPv4Protocol ? QSL("ipv4") :
	     addr.addr().protocol() == QAbstractSocket::IPv6Protocol ? QSL("ipv6") :
	     QSL("????")) % QSL(": ") %
	    addr.toString() % QSL("  ") % addr.prefix().toString();
	BlockWriter(ui) << (qint32)SC_TEXT << msg;
    }
}

bool App::parseCommandLine(QCommandLineParser &clp)
{
    QCommandLineOption cloVersion(
	QStringList() << QSL("v") << QSL("version"),
	QSL("Print version information and exit."));
    clp.addOption(cloVersion);

    QCommandLineOption cloDetached(QStringList() << QSL("D") <<
#ifdef Q_OS_WIN32
	QSL("detach"), QSL("Detach from console, if there is one.")
#else
	QSL("daemon"), QSL("Run as a daemon.")
#endif
	);
    clp.addOption(cloDetached);

    QCommandLineOption cloSharePublic(
	QStringList() << QSL("s") << QSL("share-public"),
	config->sharePublic.optionHelpString(), QSL("1|0"));
    clp.addOption(cloSharePublic);

    QCommandLineOption cloShareRemedy(
	QStringList() << QSL("r") << QSL("share-remedy"),
	config->shareRemedy.optionHelpString(), QSL("1|0"));
    clp.addOption(cloShareRemedy);

    QCommandLineOption cloStartPaused(
	QStringList() << QSL("p") << QSL("paused"),
	config->paused.optionHelpString(), QSL("1|0"));
    clp.addOption(cloStartPaused);

    QCommandLineOption cloInitOnly(
	QSL("init"),
	QSL("Store the values of the --datadir, --paused, --share-public, and/or --share-remedy options to persistent settings, and exit."));
    clp.addOption(cloInitOnly);

    QCommandLineOption cloDeleteData(
	QSL("delete-data"),
	QSL("Delete all data and exit."));
    clp.addOption(cloDeleteData);

    QCommandLineOption cloDumpSettings(
	QSL("dump-settings"),
	QSL("Print current settings and exit."));
    clp.addOption(cloDumpSettings);

    QCommandLineOption cloCheckSettings(
	QSL("check-settings"),
	QSL("Exit with status indicating if all required settings are set."));
    clp.addOption(cloCheckSettings);

    QCommandLineOption cloDeleteSettings(
	QSL("delete-settings"),
	QSL("Delete all settings and exit."));
    clp.addOption(cloDeleteSettings);

    QCommandLineOption cloSaveSettings(
	QSL("save-settings"),
	QSL("Save a copy of settings to <file> in INI format, and exit."),
	QSL("file"));
    clp.addOption(cloSaveSettings);

    QCommandLineOption cloRestoreSettings(
	QSL("restore-settings"),
	QSL("Restore settings from <file> (created with --save-settings), and exit."),
	QSL("file"));
    clp.addOption(cloRestoreSettings);

    QCommandLineOption cloDumpPaths(
	QSL("dump-paths"),
	QSL("Print list of QStandardPaths, for debugging."));
    clp.addOption(cloDumpPaths);

    QCommandLineOption cloLogfile(
	QStringList() << QSL("l") << QSL("logfile"),
	QSL("Log to \"<datadir>/%1-<time>.txt\".").arg(App::appname));
    clp.addOption(cloLogfile);

    QCommandLineOption cloDataDir(
	QStringList() << QSL("d") << QSL("datadir"),
	config->dataDir.optionHelpString(), QSL("dir"));
    clp.addOption(cloDataDir);

    if (!SpooferBase::parseCommandLine(clp, QSL("Spoofer scheduler service")))
	return false;

    if (clp.isSet(cloVersion)) {
	spout << App::appname << QSL(" version " PACKAGE_VERSION) << endl;
	return false;
    }

    this->optDeleteData = clp.isSet(cloDeleteData);
    this->optDeleteSettings = clp.isSet(cloDeleteSettings);
    this->optDumpPaths = clp.isSet(cloDumpPaths);
    this->optDumpSettings = clp.isSet(cloDumpSettings);
    this->optCheckSettings = clp.isSet(cloCheckSettings);
    this->optDetach = clp.isSet(cloDetached);
    this->optLogfile = clp.isSet(cloLogfile);
    this->optInitOnly = clp.isSet(cloInitOnly);

    if (clp.isSet(cloDataDir))
	this->optDataDir = clp.value(cloDataDir);

    if (clp.isSet(cloSaveSettings)) {
	this->optSaveSettings = true;
	this->altSettingsFile = clp.value(cloSaveSettings);
    }

    if (clp.isSet(cloRestoreSettings)) {
	this->optRestoreSettings = true;
	this->altSettingsFile = clp.value(cloRestoreSettings);
    }

    if (!parseOptionFlag(optSharePublic, clp, cloSharePublic))
	return false;

    if (!parseOptionFlag(optShareRemedy, clp, cloShareRemedy))
	return false;

    if (!parseOptionFlag(optStartPaused, clp, cloStartPaused))
	return false;

    return true;
}

bool App::parseOptionFlag(int &opt, QCommandLineParser &clp,
    const QCommandLineOption &clo)
{
    if (!clp.isSet(clo))
	return true;
    QString value = clp.value(clo);
    if (value == QSL("0"))
	opt = 0;
    else if (value == QSL("1"))
	opt = 1;
    else {
	sperr << "illegal option value " << value << endl;
	return false;
    }
    return true;
}

void App::dumpPaths(void) const
{
    spout << "applicationDirPath: " << "\"" << appDir << "\"" << endl;
    spout << "applicationFilePath: " << "\"" << appFile << "\"" << endl;
    spout << "homePath: " << "\"" << QDir::homePath() << "\"" << endl;

#define dumpQtPaths(id) \
    do { \
	QStandardPaths::StandardLocation type = QStandardPaths:: id ## Location; \
	spout << (int)type << " " << #id << " # " << QStandardPaths::displayName(type) << endl; \
	QStringList list = QStandardPaths::standardLocations(type); \
	for (int i = 0; i < list.size(); ++i) { \
	    spout << "    \"" << list.at(i) << "\"" << endl; \
	} \
    } while (0)

    dumpQtPaths(Temp          );          // 7
    dumpQtPaths(Home          );          // 8
    dumpQtPaths(Data          );          // 9
    dumpQtPaths(GenericData   );          // 11
    dumpQtPaths(Runtime       );          // 12
    dumpQtPaths(Config        );          // 13
    dumpQtPaths(GenericConfig );          // 16
}

void App::dumpSettings(void) const
{
    spout << "Settings in " << config->fileName() << endl;
    spout << "  " << qSetFieldWidth(25) << left << "" << "current value" <<
	"default value" << qSetFieldWidth(0) << endl;
    for (int i = 0; i < config->members.size(); i++) {
	Config::MemberBase *m = config->members[i];
	spout << "  " << qSetFieldWidth(25) << m->key;
	if (m->isSet()) 
	    spout << m->variant().toString();
	else if (m->required)
	    spout << QSL("(unset, required)");
	else
	    spout << QSL("(unset)");
	spout << m->defaultVal.toString();
	spout << qSetFieldWidth(0) << endl;
    }
}

QString App::chooseDataDir(bool debug)
{
    // QStandardPaths::standardLocations(QStandardPaths::DataLocation) may
    // return multiple types of locations, in no particular order:
    //   1 global:    linux example:  /usr/share/CAIDA/Spoofer        
    //                mac example:    /Library/Application Support/CAIDA/Spoofer
    //   2 app base:  mac example:    /Applications/Spoofer.app
    //   3 user:      linux example:  $HOME/.local/share/CAIDA/Spoofer
    // We prefer them in the order listed above (or reversed if debugging).
    QString result;
    int best_score = -1;
    QString appBase = appDir;
#ifdef Q_OS_MAC
    appBase.remove(QSL("/Contents/MacOS"));
#endif
#ifdef Q_OS_UNIX
    // Set HOME env var to a value that we can recognize when
    // standardLocations() inserts it into a path.
    const char *envHome = getenv("HOME");
    if (envHome) envHome = strdup(envHome);
    setenv("HOME", "/@HOME@", 1);
#endif

    QStringList paths =
	QStandardPaths::standardLocations(QStandardPaths::DataLocation);
#ifdef Q_OS_UNIX
    // Restore HOME.
    if (envHome)
	setenv("HOME", envHome, 1);
    else
	unsetenv("HOME");
#endif
    qDebug() << "homePath:" << QDir::homePath();
    qDebug() << "rootPath:" << QDir::rootPath();
    foreach (QString path, paths) {
	if (path.isEmpty()) continue;
	QString cleanpath = QDir::cleanPath(path);
	int score = 1;
	if (cleanpath.startsWith(appBase))
	    score = 2;
	else if (cleanpath.startsWith(QSL("/@HOME@")))
	    score = 3;
	// On Mac OSX, standardLocations() doesn't use $HOME to generate paths
	// (maybe it uses NSSearchPathForDirectoriesInDomains()?), so we need
	// to check for the real home path in addition to our "/@HOME@" token.
	else if (QDir::homePath() != QDir::rootPath() &&
	    cleanpath.startsWith(QDir::homePath()))
		score = 3;
#ifdef Q_OS_MAC
	else if (cleanpath.startsWith(QSL("/private/")))
	    score = 3;
#endif
	qDebug() << "dataDir option, score" << score << ":" << cleanpath;
	if (result.isEmpty() ||
	    (debug ? (score > best_score) : (score < best_score)))
	{
	    best_score = score;
	    result = cleanpath;
	}
    }
    result.replace(QSL("/@HOME@"), QDir::homePath());
    return result;
}

QLocalServer *App::listen(bool privileged)
{
    QLocalServer *server = new QLocalServer(this);
    connect(server, &QLocalServer::newConnection, this, &App::uiAccept);
    
    server->setSocketOptions(
#ifndef EVERYONE_IS_PRIVILEGED
	privileged ? QLocalServer::UserAccessOption :
#endif
	QLocalServer::WorldAccessOption);

    QString serverName =
#ifdef Q_OS_UNIX
	// Use our own directory because the default directory may not be
	// readable by everyone (seen in Qt 5.9 on OSX 10.12)
	config->dataDir() % QSL("/") %
#endif
	QSL("spoofer-") % QString::number(applicationPid());
    if (!privileged) serverName.append(QSL("o"));
    if (!server->listen(serverName)) {
	sperr << "listen: " << server->errorString() << endl;
	delete server;
	return nullptr;
    }
    sperr << "Scheduler listening for " <<
#ifndef EVERYONE_IS_PRIVILEGED
	(privileged ? "privileged " : "unprivileged ") <<
#endif
	"connections on " << server->fullServerName() << endl;
    return server;
}

QLockFile *App::lockLockFile(QString name)
{
    qDebug() << "lockFile:" << qPrintable(QDir::toNativeSeparators(name));
    QDir().mkpath(QDir(name % QSL("/..")).absolutePath()); // make sure dir exists
    QLockFile *lockfile = new QLockFile(name);
    lockfile->setStaleLockTime(0);
#ifdef Q_OS_UNIX
    bool stale = false;
    bool retried = false; // we want to retry only once
    pid_t pid;
retry:
#endif
    errno = 0;
    if (!lockfile->tryLock(0)) {
	int err = errno;
	qint64 qpid;
	QString host, app;
	sperr << "Error locking \"" << QDir::toNativeSeparators(name);
	switch (lockfile->error()) {
	    case QLockFile::LockFailedError:
		lockfile->getLockInfo(&qpid, &host, &app);
		sperr << "\": locked by pid " << qpid << " " << app << endl;
#ifdef Q_OS_UNIX
		// On OSX, under conditions I haven't been able to reliably
		// reproduce, tryLock() may fail to remove a stale lock file.
		// We check for the possibility that the old process' pid is
		// being used by a new process (maybe even this one), which is
		// especially likely if the old process started at boot time.
		if (retried) break;
		stale = false;
		pid = static_cast<pid_t>(qpid);
		if (pid == getpid()) {
		    sperr << "... but I am pid " << pid << "." << endl;
		    stale = true;
		} else if (kill(pid, 0) < 0 && errno == ESRCH) {
		    // kill() is more reliable than the "ps" below
		    sperr << "... but there is no pid " << pid << endl;
		    stale = true;
		} else {
		    char buf[1024];
		    // POSIX ps requires "-ocomm=", but not "-ocommand="; but
		    // the latter works on at least OSX, Linux, FreeBSD.
		    sprintf(buf, "ps -p%lu -ocommand=", static_cast<unsigned long>(pid));
		    FILE *ps = popen(buf, "r");
		    if (!ps) {
			sperr << "Error while verifying pid " << pid <<
			    " with ps: " << strerror(errno) << endl;
			break;
		    }
		    stale = true;
		    while (fgets(buf, sizeof(buf), ps)) {
			char *procname;
			if ((procname = strstr(buf, APPNAME)) && (procname == buf || procname[-1] == '/')) {
			    stale = false;
			    break;
			}
		    }
		    if (stale) {
			sperr << "... but pid " << pid << " is not " << APPNAME << endl;
		    } else {
			sperr << "... and pid " << pid << " is " << buf << endl;
		    }
		    fclose(ps);
		}

		if (!stale) break;
		if (lockfile->removeStaleLockFile()) {
		    sperr << "Stale lock file removed." << endl;
		    retried = true;
		    goto retry;
		} else {
		    err = errno;
		    sperr << "Failed to remove stale lock file: " <<
			strerror(err) << endl;
		}
#endif
		break;
	    case QLockFile::PermissionError:
		sperr << "\": permission error" << endl;
		break;
	    case QLockFile::NoError:
		sperr << "\": no error" << endl;
		break;
	    case QLockFile::UnknownError:
	    default:
		sperr << "\": unknown error";
		if (err)
		    sperr << " (" << strerror(err) << ")";
		sperr << endl;
		break;
	}
	delete lockfile;
	return nullptr;
    }
    return lockfile;
}

static void removeFiles(QDir dir, QString glob, int keep_n = 0)
{
    QStringList filenames = dir.entryList(QStringList() << glob,
	QDir::Files, QDir::Name);
    for (int i = 0; i < filenames.size() - keep_n; i++) {
	qDebug() << "removing file" << filenames.at(i);
	if (!dir.remove(filenames.at(i)))
	    App::sperr << "error removing file " << filenames.at(i) << ": " <<
		strerror(errno) << endl;
    }
}

// Returns true if caller should continue with app.exec().
bool App::init(int &exitCode)
{
    exitCode = 1; // default result is failure
    errdev.setTimestampEnabled(!isInteractive);
    connect(this, &QCoreApplication::aboutToQuit, this, &App::cleanup);
    QCommandLineParser clp;
    defaultDataDir = chooseDataDir(false);
    config->dataDir.setDefault(defaultDataDir);

    if (!parseCommandLine(clp)) return false;

    // Before changing working directory
    if (!initConfig(!optDumpSettings)) return false;

    if (optDumpSettings) {
	dumpSettings();
	exitCode = 0; // success
	return false;
    }

    if (optCheckSettings) {
	exitCode = config->hasRequiredSettings() ? 0 : 1;
	return false;
    }

    if (optDumpPaths) dumpPaths();

    if (!optDataDir.isEmpty()) {
	dataDir = optDataDir;
    } else if (!config->dataDir().isEmpty()) {
	dataDir = config->dataDir();
    } else if (!defaultDataDir.isEmpty()) {
	dataDir = defaultDataDir;
    } else {
	sperr << "can't determine a suitable data folder" << endl;
	return false;
    }
    sperr << "dataDir: " << dataDir << endl;

    QDir dir;
    dir.mkpath(dataDir); // make sure it exists
    QDir::setCurrent(dataDir);
    // don't "config->dataDir(dataDir)" until we have lock and are listening

    // Maybe open new log file using new value of dataDir
    if (optLogfile || errdev.type() == typeid(AppLog)) {
	errdev.setDevice(new AppLog());
    } else {
	errdev.setFallbackDevice(new AppLog());
    }

    if (!optInitOnly && !optDeleteData && !optDeleteSettings && !optSaveSettings && !optRestoreSettings)
	if (!prestart(exitCode)) return false;
    errdev.setTimestampEnabled(true);

    // Make sure we are the only running scheduler using this settings file
    // (after potential detach in prestart(), so we'll write the correct PID
    // to the lock file)
    settingLockFile = lockLockFile(config->lockFileName());
    if (!settingLockFile) return false;

    // Save or restore settings (after getting settings lock)
    if (optSaveSettings || optRestoreSettings) {
	QSettings altSettings(altSettingsFile, QSettings::IniFormat);
	if (optSaveSettings) {
	    altSettings.clear();
	    copySettings(altSettings, *config->settings);
	    qDebug() << "saved settings to" << altSettings.fileName();
	} else {
	    config->settings->clear();
	    copySettings(*config->settings, altSettings);
	    qDebug() << "restored settings from" << altSettings.fileName();
	}
	exitCode = 0; // success
	return false;
    }

    // Delete data (after getting settings lock)
    if (optDeleteData) {
	QDir qdir(dataDir);
	removeFiles(qdir, proberLogGlob);
	removeFiles(qdir, schedulerLogGlob);
	QString dataDirName = qdir.dirName();
	qdir.cdUp();
	if (qdir.rmdir(dataDirName)) {
	    sperr << "Deleted " << dataDir << endl;
	    exitCode = 0;
	} else {
	    sperr << "Error deleting " << dataDir << ": " <<
		strerror(errno) << endl;
	    exitCode = 1;
	}
	return false; // caller should not do app.exec()
    }

    // Delete settings (after getting settings lock)
    if (optDeleteSettings) {
	config->remove();
	sperr << "Deleted settings in " << config->fileName() << endl;
	exitCode = 0; // success
	return false; // caller should not do app.exec()
    }

    // Write command line options to settings (after getting settings lock)
    if (optSharePublic >= 0) {
	qDebug() << "config->sharePublic" << (optSharePublic == 1);
	config->sharePublic(optSharePublic == 1);
    }

    if (optShareRemedy >= 0) {
	qDebug() << "config->shareRemedy" << (optShareRemedy == 1);
	config->shareRemedy(optShareRemedy == 1);
    }

    if (optStartPaused >= 0) {
	qDebug() << "config->paused" << (optStartPaused == 1);
	config->paused(optStartPaused == 1);
    }

    if (optInitOnly) {
	config->dataDir(dataDir);
	config->sync();
	exitCode = 0; // success
	return false; // caller should not do app.exec()
    }

    // Make sure we are the only running scheduler using this dataDir (in case
    // two different settings files have the same dataDir value, or there's an
    // older version of scheduler that locked only dataDir, not settings)
    dataLockFile = lockLockFile(dataDir % QSL("/spoofer.lock"));
    if (!dataLockFile) return false;

    if (!initSignals()) return false;

    {
	// load history
	config->settings->beginGroup(QSL("history"));
	QStringList groups = config->settings->childGroups();
	foreach (QString group, groups) {
	    QString subnetstr = group;
	    subnetstr.replace(QSL(";"),QSL("/")); // QSettings doesn't allow "/" in keys
	    if (!subnetstr.contains(QSL("/"))) {
		qDebug() << "removing non-subnet group:" << group;
		config->settings->remove(group);
		continue;
	    }
	    SubnetAddr subnet(QHostAddress::parseSubnet(subnetstr));
	    if (subnet.pfxlen() <= 0) {
		qDebug() << "skipping invalid subnet group:" << group;
		continue;
	    }
	    config->settings->beginGroup(group);
	    RunRecord &rr = pastRuns[subnet];
	    rr.t = static_cast<time_t>(config->settings->value(QSL("time")).toLongLong());
	    rr.errors = config->settings->value(QSL("errors")).toInt();
	    config->settings->endGroup();
	}
	config->settings->endGroup();
    }

    if (!(privServer = listen(true)))
	return false;
#ifndef EVERYONE_IS_PRIVILEGED
    if (!(unprivServer = listen(false)))
	return false;
#endif

    config->dataDir(dataDir);
    config->schedulerSocketName(privServer->fullServerName());
    config->sync();

#ifdef ENABLE_QNetworkConfigurationManager
    // QNetworkConfigurationManager on some platforms does very frequent
    // polling which can be very cpu-intensive and disruptive, maybe even
    // causing some drivers to drop connections.
    ncm = new QNetworkConfigurationManager(this);

    connect(ncm, &QNetworkConfigurationManager::configurationChanged,
	this, &App::handleNetChange);
    connect(ncm, &QNetworkConfigurationManager::configurationAdded,
	this, &App::handleNetChange);
    connect(ncm, &QNetworkConfigurationManager::configurationRemoved,
	this, &App::handleNetChange);
#endif

#if 0 // DEBUGGING: simulate frequent network change signal from OS or Qt
    QTimer *thrashTimer = new QTimer();
    connect(thrashTimer, &QTimer::timeout, this, &App::handleNetChange);
    thrashTimer->start(1000*10);
#endif

    proberTimer.setSingleShot(true);
    connect(&proberTimer, &QTimer::timeout, this, &App::startProber);

    netPollTimer.setSingleShot(true);
    connect(&netPollTimer, &QTimer::timeout, this, &App::scheduleNextProber);

    if (!(paused = config->paused())) {
	// Wait 1s (in case of a burst of changes), then scheduleNextProber()
	netPollTimer.start(1000*1);
    }

    return true; // caller should continue with app.exec()
}

void App::cleanup()
{
    if (prober) {
	killProber();
	if (hangTimer) delete(hangTimer); hangTimer = nullptr;
	if (proberWatcher) delete(proberWatcher); proberWatcher = nullptr;
	delete prober;
	prober = nullptr;
    }
    if (privServer) {
	if (config)
	    config->schedulerSocketName.remove();
	delete privServer;
	privServer = nullptr;
    }
    if (unprivServer) {
	delete unprivServer;
	unprivServer = nullptr;
    }
    if (dataLockFile) {
	delete dataLockFile;
	dataLockFile = nullptr;
    }
    if (settingLockFile) {
	delete settingLockFile;
	settingLockFile = nullptr;
    }
}

App::~App()
{
    cleanup();
}

void App::uiAccept()
{
    QLocalServer *server = static_cast<QLocalServer*>(QObject::sender());
    bool privileged = (server == privServer);
    const char *label = privileged ? "privileged" : "unprivileged";
    qDebug() << "new" << label << "connection detected on" <<
	server->fullServerName();
    QLocalSocket *ui = server->nextPendingConnection();
    if (!ui) {
	qDebug() << "SCHEDULER ERROR: connection:" << server->errorString();
	return;
    }
    qDebug() << "accepted" << label << "connection";
    connect(ui, &QLocalSocket::readyRead, this, &App::uiRead);
    connect(ui, &QLocalSocket::disconnected, this, &App::uiDelete);
    uiSet.insert(ui);

    if (opAllowed(ui, config->unprivView)) {
	if (paused)
	    BlockWriter(ui) << (qint32)SC_PAUSED;

	if (prober) {
	    // notify new UI of prober in progress
	    const sc_msg_text msg(proberOutputFileName);
	    BlockWriter(ui) << (qint32)SC_PROBER_STARTED << msg;
	} else if (nextProberStart.when) {
	    // notify new UI of next scheduled prober
	    BlockWriter(ui) << (qint32)SC_SCHEDULED << nextProberStart;
	}

	if (opAllowed(ui, config->unprivPref) && !config->hasRequiredSettings())
	    BlockWriter(ui) << (qint32)SC_NEED_CONFIG;
    }
}

void App::uiDelete()
{
    QLocalSocket *ui = static_cast<QLocalSocket*>(sender());
    qDebug() << "UI disconnected";
    uiSet.remove(ui);
    ui->deleteLater();
}

bool App::opAllowed(QLocalSocket *ui, const Config::MemberBase &cfgItem)
{
    if (ui->parent() == privServer) return true;
    if (cfgItem.variant().toBool()) return true;
    return false;
}

bool App::opAllowedVerbose(QLocalSocket *ui, const Config::MemberBase &cfgItem)
{
    if (opAllowed(ui, cfgItem)) return true;
    qDebug() << "Permission denied.";
    const sc_msg_text msg(QSL("Permission denied."));
    BlockWriter(ui) << (qint32)SC_ERROR << msg;
    return false;
}

void App::uiRead()
{
    static QRegularExpression set_re(QSL("set\\s+(\\w+)\\s+(.*)"));
    QRegularExpressionMatch match;

    qDebug() << "uiRead()";

    QLocalSocket *ui = static_cast<QLocalSocket*>(sender());

    char data[1024];
    qint64 n;
    while ((n = ui->readLine(data, sizeof(data) - 1)) > 0) {
	while (n > 0 && data[n-1] == '\n') data[--n] = '\0';
	sperr << "UI read: " << data << endl;
	if (data[0] == '#') {
	    // ignore comment
	} else if (strcmp(data, "shutdown") == 0) {
	    sperr << "shutdown by command" << endl;
	    this->shutdown();
	} else if (strcmp(data, "run") == 0) {
	    if (!opAllowedVerbose(ui, config->unprivTest)) continue;
	    if (prober) {
		const sc_msg_text msg(QSL("There is already a prober running."));
		BlockWriter(ui) << (qint32)SC_ERROR << msg;
	    } else if (!config->hasRequiredSettings()) {
		BlockWriter(ui) << (qint32)SC_NEED_CONFIG;
	    } else {
		startProber();
	    }
	} else if (strcmp(data, "abort") == 0) {
	    if (!opAllowedVerbose(ui, config->unprivTest)) continue;
	    if (!prober) {
		const sc_msg_text msg(QSL("There is no prober running."));
		BlockWriter(ui) << (qint32)SC_ERROR << msg;
	    } else {
		killProber();
		// const sc_msg_text msg(QSL("Killing prober."));
		// BlockWriter(ui) << (qint32)SC_TEXT << msg;
	    }
	} else if (strcmp(data, "pause") == 0) {
	    if (!opAllowedVerbose(ui, config->unprivPref)) continue;
	    if (paused) {
		const sc_msg_text msg(QSL("The scheduler is already paused."));
		BlockWriter(ui) << (qint32)SC_ERROR << msg;
	    } else {
		pause();
		BlockWriter(ui) << (qint32)SC_DONE_CMD;
	    }
	} else if (strcmp(data, "resume") == 0) {
	    if (!opAllowedVerbose(ui, config->unprivPref)) continue;
	    if (!paused) {
		const sc_msg_text msg(QSL("The scheduler is not paused."));
		BlockWriter(ui) << (qint32)SC_ERROR << msg;
	    } else {
		resume();
		BlockWriter(ui) << (qint32)SC_DONE_CMD;
	    }
	} else if ((match = set_re.match(QString::fromLocal8Bit(data))).hasMatch()) {
	    if (!opAllowedVerbose(ui, config->unprivPref)) continue;
	    QString name = match.captured(1);
	    QString value = match.captured(2);
	    SpooferBase::Config::MemberBase *cfgItem = config->find(name);
	    if (cfgItem) {
		sc_msg_text msg;
		bool wasConfiged = config->hasRequiredSettings();
		if (!cfgItem->setFromString(value, msg.text)) {
		    BlockWriter(ui) << (qint32)SC_ERROR << msg;
		} else {
		    bool isConfiged = config->hasRequiredSettings();
		    config->sync();
		    BlockWriter(ui) << (qint32)SC_DONE_CMD;
		    foreach (QLocalSocket *connectedUi, uiSet) {
			BlockWriter(connectedUi) << (qint32)SC_CONFIG_CHANGED;
			if (!wasConfiged && isConfiged)
			    BlockWriter(connectedUi) << (qint32)SC_CONFIGED;
		    }
		    // scheduleNextProber() in case any scheduling parameters
		    // changed (but wait 1s in case of a burst of changes)
		    scheduledSubnets.clear(); // force rescheduling
		    netPollTimer.start(1000*1);
		    dataDir = config->dataDir(); // in case it changed
		}
	    } else {
		const sc_msg_text msg(QSL("No such setting \"%1\".").arg(name));
		BlockWriter(ui) << (qint32)SC_ERROR << msg;
	    }
	} else if (strcmp(data, "sync") == 0) {
	    if (!opAllowedVerbose(ui, config->unprivPref)) continue;
	    config->sync();
	    BlockWriter(ui) << (qint32)SC_DONE_CMD;
	} else if (strcmp(data, "dumpnetcfg") == 0) {
	    dumpNetCfg(ui);
	    BlockWriter(ui) << (qint32)SC_DONE_CMD;
	} else {
	    qDebug() << "Unknown command:" << data;
	    const sc_msg_text msg(QSL("Unknown command."));
	    BlockWriter(ui) << (qint32)SC_ERROR << msg;
	}
    }
    if (n < 0) {
	qDebug() << "UI read error:" << ui->errorString();
    }
}

void App::startProber()
{
    proberTimer.stop();
    nextProberStart.when = 0;
    if (prober) {
	qDebug() << "startProber: there is already a prober running.";
	return;
    }
    QDir dir(dataDir);
    proberOutputFileName = dir.filePath(ftime_utc(proberLogFtime));
    sperr << "startProber: " << QDir::toNativeSeparators(proberOutputFileName)
	<< endl;

    prober = new QProcess(this);
    prober->setProcessChannelMode(QProcess::MergedChannels); // ... 2>&1
    prober->setStandardInputFile(QProcess::nullDevice()); // ... </dev/null
    prober->setStandardOutputFile(proberOutputFileName,
	QIODevice::Text | QIODevice::Truncate | QIODevice::WriteOnly); // ... >file
    QStringList args;
#if DEBUG
    if (config->useDevServer()) args << QSL("-T");
    if (config->pretendMode()) args << QSL("-P");
    if (config->standaloneMode()) args << QSL("-S");
#endif
    args << (config->sharePublic() ? QSL("-s1") : QSL("-s0"));
    args << (config->shareRemedy() ? QSL("-r1") : QSL("-r0"));
    if (config->enableIPv4()) args << QSL("-4");
    if (config->enableIPv6()) args << QSL("-6");
    if (!config->enableTLS()) args << QSL("--no-tls");

    connect(prober, &QProcess::started, this, &App::proberStarted);
#if QT_VERSION >= 0x050600 // 5.6.0 or later
    connect(prober, &QProcess::errorOccurred, this, &App::proberError);
#else
    connect(prober, SIGCAST(QProcess, error, (QProcess::ProcessError)),
	this, &App::proberError);
#endif
    connect(prober, SIGCAST(QProcess, finished, (int,QProcess::ExitStatus)),
	this, &App::proberFinished);

    QString proberPath = appDir % QSL("/spoofer-prober");
    prober->start(proberPath, args);
    // Unfortunately, if this process exits, ~QProcess() will kill the prober
    // process.  QProcess::startDetached() would avoid that, but then we can't
    // set up its input/output and signals/slots.

    // If prober output file goes unmodified for 5 minutes, assume the prober
    // is hung, and kill it.
    proberWatcher = new QFileSystemWatcher(this);
    proberWatcher->addPath(proberOutputFileName);
    hangTimer = new QTimer(this);
    hangTimer->setSingleShot(true);
    resetHangTimer();
    connect(hangTimer, &QTimer::timeout, this, &App::killProber);
    connect(proberWatcher, &QFileSystemWatcher::fileChanged, this, &App::resetHangTimer);
}

void App::resetHangTimer()
{
    hangTimer->start(5 * 60 * 1000); // 5 minutes
}

void App::killProber()
{
    if (!prober) return;
    prober->terminate();
    if (!prober->waitForFinished(1000) &&
	prober->state() != QProcess::NotRunning)
    {
	qDebug() << "prober did not terminate; killing by force.";
	prober->kill();
    }
}

void App::proberStarted()
{
    qint64 pid =
#if QT_VERSION >= 0x050300 // 5.3.0 or later
	prober->processId();
#elif defined(Q_OS_WIN32)
	prober->pid()->dwProcessId;
#else
	prober->pid();
#endif
    sperr << "prober started, pid " << pid << endl;
    const sc_msg_text msg(proberOutputFileName);
    foreach (QLocalSocket *ui, uiSet) {
	if (opAllowed(ui, config->unprivView))
	    BlockWriter(ui) << (qint32)SC_PROBER_STARTED << msg;
    }
}

void App::proberError(QProcess::ProcessError e)
{
    // If this is not the first error, prober was aleady nulled.
    QProcess *p = dynamic_cast<QProcess*>(sender());

    QString msg;
    switch (e) {
	case QProcess::FailedToStart: msg = QSL("failed to start ");  break;
	case QProcess::Crashed:       msg = QSL("crashed in ");       break;
	case QProcess::Timedout:      msg = QSL("timed out in ");     break;
	case QProcess::WriteError:    msg = QSL("write error in ");   break;
	case QProcess::ReadError:     msg = QSL("read error in ");    break;
	case QProcess::UnknownError:  msg = QSL("unknown error in "); break;
	default:                      msg = QSL("error in ");         break;
    }
    msg.append(p->program() % QSL(": ") % p->errorString());
    qCritical() << "prober error:" << qPrintable(msg);
    if (p->state() == QProcess::NotRunning) {
	sc_msg_text scmsg(msg);
	foreach (QLocalSocket *ui, uiSet) {
	    if (opAllowed(ui, config->unprivView))
		BlockWriter(ui) << (qint32)SC_PROBER_ERROR << scmsg;
	}
	if (prober) {
	    qDebug() << "delete prober";
	    if (hangTimer) delete(hangTimer); hangTimer = nullptr;
	    if (proberWatcher) delete(proberWatcher); proberWatcher = nullptr;
	    prober->deleteLater();
	    prober = nullptr;
	    recordRun(false);
	    scheduleNextProber();
	}
    }
}

void App::proberFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    char buf[80];
    bool success = false;
    qDebug() << "prober finished" << qPrintable(ftime_utc());

    sc_msg_text msg;
    if (exitStatus == QProcess::NormalExit) {
	sperr << "prober exited normally, exit code " << exitCode << endl;
	sprintf(buf, "normally (exit code %d).", exitCode);
	msg.text = QString::fromLocal8Bit(buf);
	success = (exitCode == 0);
    } else {
	sperr << "prober exited abnormally" << endl;
	msg.text = QSL("abnormally.");
    }
    foreach (QLocalSocket *ui, uiSet) {
	if (opAllowed(ui, config->unprivView))
	    BlockWriter(ui) << (qint32)SC_PROBER_FINISHED <<
		exitCode << (int)exitStatus;
    }
    if (hangTimer) delete(hangTimer); hangTimer = nullptr;
    if (proberWatcher) delete(proberWatcher); proberWatcher = nullptr;
    if (prober) delete prober;
    prober = nullptr;

    recordRun(success);
    scheduleNextProber();

    QDir dir(dataDir);
    int nlogs = config->keepLogs();
    if (nlogs > 0) {
	removeFiles(dir, proberLogGlob, nlogs);
    }
}

void App::recordRun(bool success)
{
    QList<SubnetAddr> addrs = getAddresses();
    time_t now;
    time(&now);
    config->settings->beginGroup(QSL("history"));
    foreach (SubnetAddr addr, addrs) {
	SubnetAddr subnet = addr.prefix();
	RunRecord &rr = pastRuns[subnet];
	if (rr.t == now) continue; // don't duplicate
	rr.t = now;
	if (success)
	    rr.errors = 0;
	else
	    rr.errors++;
	config->settings->beginGroup(subnet.toString().replace(QSL("/"),QSL(";"))); // QSettings doesn't allow "/" in keys
	config->settings->setValue(QSL("time"), (qlonglong)rr.t);
	config->settings->setValue(QSL("errors"), rr.errors);
	config->settings->endGroup();
    }
    config->settings->endGroup();
    config->sync();
}

void App::pause()
{
    if (!config->paused()) {
	config->paused(true);
	config->sync();
    }
    if (paused) return;
    sperr << "pausing" << endl;
    paused = true;
    proberTimer.stop();
    netPollTimer.stop();
    nextProberStart.when = 0;
    scheduledSubnets.clear();
    foreach (QLocalSocket *ui, uiSet) {
	if (opAllowed(ui, config->unprivView))
	    BlockWriter(ui) << (qint32)SC_PAUSED;
    }
}

void App::resume()
{
    if (config->paused()) {
	config->paused(false);
	config->sync();
    }
    if (!paused) return;
    sperr << "resuming" << endl;
    paused = false;
    foreach (QLocalSocket *ui, uiSet) {
	if (opAllowed(ui, config->unprivView))
	    BlockWriter(ui) << (qint32)SC_RESUMED;
    }
    scheduleNextProber();
}
