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

#include <time.h>
#include <locale.h>
#include <cstdio>
#include <errno.h>
#include <unistd.h> // unlink()
#include "spoof_qt.h"
#include <QCommandLineParser>
#include <QtGlobal>
#include <QDir>
#ifdef Q_OS_WIN32
# include <windows.h> // RegGetValue()
#endif
#include "../../config.h"
#include "common.h"
static const char cvsid[] ATR_USED = "$Id: common.cpp,v 1.73 2017/10/19 21:42:20 kkeys Exp $";

SpooferBase::OnDemandDevice SpooferBase::outdev(stdout);
SpooferBase::OnDemandDevice SpooferBase::errdev(stderr);
QTextStream SpooferBase::spout(&SpooferBase::outdev);
QTextStream SpooferBase::sperr(&SpooferBase::errdev);
QString SpooferBase::optSettings;
SpooferBase::Config *SpooferBase::config;
QSettings *SpooferBase::Config::settings;
QList<SpooferBase::Config::MemberBase*> SpooferBase::Config::members;

// We avoid ".log" Suffix because OSX "open" would launch a log reader app
// we don't want.
const QString SpooferBase::proberLogFtime = QSL("'spoofer-prober-'yyyy~MM~dd-HH~mm~ss'.txt'");
const QString SpooferBase::proberLogGlob = QSL("spoofer-prober-\?\?\?\?\?\?\?\?-\?\?\?\?\?\?.txt"); // backslashes prevent trigraphs
const QString SpooferBase::proberLogRegex = QSL("spoofer-prober-(\\d{4})(\\d{2})(\\d{2})-(\\d{2})(\\d{2})(\\d{2}).txt$");

SpooferBase::Config::Config() :
    forWriting(false),
    // Internal
    dataDir(QSL("dataDir"), QString(),
	QSL("Use <dir> as data directory"), true),
    schedulerSocketName(QSL("schedulerSocketName")),
    paused(QSL("paused"), false,
	QSL("Start with scheduled prober runs disabled"), true),
#if DEBUG
    // Debug
    useDevServer(QSL("useDevServer"), true,
	QSL("use development test server")),
    pretendMode(QSL("pretendMode"), false,
	QSL("pretend mode - don't send any probe packets")),
    standaloneMode(QSL("standaloneMode"), false,
	QSL("standalone debugging mode - run a test without server")),
#endif

    // General
    enableIPv4(QSL("enableIPv4"), true,
	QSL("Enable testing on IPv4 interfaces (if available)")),
    enableIPv6(QSL("enableIPv6"), true,
	QSL("Enable testing on IPv6 interfaces (if available)")),
    keepLogs(QSL("keepLogs"), 60, 0, INT_MAX,
	QSL("Number of prober log files to keep (0 means unlimited)")),
    sharePublic(QSL("sharePublic"), true,
	QSL(DESC_SHARE_PUBLIC)),
    shareRemedy(QSL("shareRemedy"), true,
	QSL(DESC_SHARE_REMEDY)),
    enableTLS(QSL("enableTLS"), true,
	QSL("Use SSL/TLS to connect to server (recommended unless blocked by your provider)")),
    // Probing
    netPollInterval(QSL("netPollInterval"), 2*60, 1, 86400,
	QSL("Wait to check for a network change (seconds)")),
    delayInterval(QSL("delayInterval"), 60, 1, 3600,
	QSL("Wait to run a test after detecting a network change (seconds)")),
    // odd proberInterval helps prevent many clients from synchronizing
    proberInterval(QSL("proberInterval"), 7*24*60*60 + 65*60, 1, INT_MAX,
	QSL("Wait to run a test after a successful run on the same network (seconds)")),
    proberRetryInterval(QSL("proberRetryInterval"), 10*60, 1, INT_MAX,
	QSL("Wait to retry after first incomplete run (seconds) (doubles each time)")),
    maxRetries(QSL("maxRetries"), 3, 0, INT_MAX,
	QSL("Maximum number of retries after an incomplete run")),
    // Permissions:  "Allow unprivileged users on this computer to..."
    unprivView(QSL("unprivView"), true,
	QSL("Observe a test in progress and view results of past tests")),
    unprivTest(QSL("unprivTest"), false,
	QSL("Run a test")),
    unprivPref(QSL("unprivPref"), false,
	QSL("Change preferences"))
{
    sharePublic.required = true;
    shareRemedy.required = true;
#ifdef Q_OS_UNIX
    // We don't want these user-desktop-specific environment variables
    // affecting our defaults for dataDir or settings file; we want the
    // same defaults for all users, including system daemon launchers.
    unsetenv("XDG_CONFIG_DIRS");
    unsetenv("XDG_DATA_DIRS");
#endif
}

void SpooferBase::Config::initSettings(bool _forWriting, bool debug)
{
    config->forWriting = _forWriting;
    if (!optSettings.isEmpty()) {
	settings = new QSettings(optSettings, QSettings::IniFormat);
    } else {
	settings = findDefaultSettings(debug);
	settings->setFallbacksEnabled(false);
    }
    sperr << "Config: " << settings->fileName() << endl;
}

QString SpooferBase::Config::lockFileName()
{
    // Note: QSettings may generate a temporary lock file by appending ".lock"
    // to the file name, so we must use a different name for our lock.
    if (isFile()) return settings->fileName() % QSL(".write-lock");

    QString path;
#ifdef Q_OS_WIN32
    // We want the system's %TEMP%, not the user's.
    LONG err;
    char buf[1024];
    DWORD size = sizeof(buf) - 1;
    const char *subkeyName =
	"System\\CurrentControlSet\\Control\\Session Manager\\Environment";
    err = RegGetValueA(HKEY_LOCAL_MACHINE, subkeyName, "TEMP", RRF_RT_REG_SZ,
	NULL, buf, &size);
    if (err != ERROR_SUCCESS) {
	wchar_t str[1024];
	FormatMessage(
	    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
	    nullptr, static_cast<DWORD>(err), 0, str, sizeof(str), nullptr);
	qDebug() << "RegGetValue:" << QString::fromWCharArray(str).trimmed();
	goto doneReg;
    }
    path = QString::fromLocal8Bit(buf).trimmed();
    qDebug() << "TEMP:" << qPrintable(path);
doneReg:
#endif
    if (path.isEmpty()) path = QDir::tempPath();
    return (path % QSL("/") % QCoreApplication::applicationName() % QSL(".lock"));
}

bool SpooferBase::Config::error(const char *label)
{
    if (settings->status() == QSettings::NoError)
	return false;

    logError(label,
	(settings->status() == QSettings::AccessError) ? QSL("AccessErrror") :
	(settings->status() == QSettings::FormatError) ? QSL("FormatError") :
	QSL("unknown error %1").arg(int(settings->status())));

    return true;
}

void SpooferBase::Config::logError(const char *label, QString msg, QString msg2)
{
    msg = QSL("%1 in \"%2\"").arg(msg,
	QDir::toNativeSeparators(settings->fileName()));

    if (isFile()) {
	// Use the standard library to get a more informative error message.
	FILE *f = fopen(qPrintable(settings->fileName()),
	    forWriting ? "r+" : "r");
	if (!f)
	    msg = QSL("%1 (%2)").arg(msg,
		QString::fromLocal8Bit(strerror(errno)));
	else
	    fclose(f);
    }
    qCritical().nospace().noquote() << label << ": " << msg << ". " << msg2;
}

void SpooferBase::Config::remove()
{
    if (!settings) return;
    QString name = isFile() ? settings->fileName() : QString();
    settings->clear();
    delete settings;
    settings = nullptr;
    if (!name.isEmpty()) {
	if (unlink(name.toStdString().c_str()) == 0)
	    sperr << name << " removed." << endl;
	else
	    sperr << "Error removing " << name << ": " << strerror(errno) << endl;
    }
}

SpooferBase::SpooferBase() :
    appDir(QCoreApplication::applicationDirPath()),
    appFile(QCoreApplication::applicationFilePath())
{
    setlocale(LC_NUMERIC, "C");

    // for QStandardPaths::standardLocations() and QSettings
    QCoreApplication::setOrganizationName(QSL(ORG_NAME));
    QCoreApplication::setOrganizationDomain(QSL(ORG_DOMAIN));
    QCoreApplication::setApplicationName(QSL("Spoofer")); // may change later

    qInstallMessageHandler(logHandler);

    config = new Config();
}

qint64 SpooferBase::OnDemandDevice::writeData(const char *data, qint64 maxSize)
{
    if (newdev) {
	QFile *file = dynamic_cast<QFile*>(dev);
	QFile *newfile = dynamic_cast<QFile*>(newdev);
	if (newfile) {
	    // Make sure filename is clean and absolute for comparison below.
	    QDir newpath(QDir::cleanPath(newfile->fileName()));
	    newfile->setFileName(newpath.absolutePath());
	}
	if (file && file->isOpen() && newfile && file->fileName() ==
	    newfile->fileName())
	{
	    // Old dev is open, and newdev is the same file; ignore newdev.
	} else {
	    char buf[2048];
	    if (dev && dev->isOpen() && !newname.isEmpty()) {
		snprintf(buf, sizeof(buf), "Redirecting output to %s\n",
		    qPrintable(newname));
		dev->write(buf);
	    }
	    if (!newdev->open(WriteOnly|Unbuffered|Append|Text)) {
		if (dev && dev->isOpen()) {
		    snprintf(buf, sizeof(buf), "Redirection failed: %s.\n",
			qPrintable(newdev->errorString()));
		    dev->write(buf);
		}
		delete newdev;
	    } else { // success
		if (dev) delete dev;
		dev = newdev;
	    }
	}
	newdev = nullptr;
    }

    if (!dev) {
	if (!fallback) {
	    setErrorString(QSL("output device is not set"));
	    return maxSize; // *dev failed, but *this can still work
	}
	// E.g., dev was nulled in a previous call, and fallback was set later.
	newdev = fallback;
	fallback = nullptr;
	return writeData(data, maxSize); // Try again with the fallback.
    }

    if (timestampEnabled) {
	char tbuf[40];
	time_t t = time(nullptr);
	struct tm *tm = gmtime(&t);
	strftime(tbuf, sizeof(tbuf), "[%Y-%m-%d %H:%M:%S] ", tm);
	dev->write(tbuf, safe_int<qint64>(strlen(tbuf)));
    }
    qint64 retval = dev->write(data, maxSize);
    if (retval < 0) {
	// E.g., stderr is closed when running as a Windows service.
	if (!fallback) { // There was no fallback.
	    delete dev; dev = nullptr;
	    return maxSize; // *dev failed, but *this can still work
	}
	newdev = fallback;
	fallback = nullptr;
	return writeData(data, maxSize); // Try again with the fallback.
    }
    fallback = nullptr; // Dev worked; we won't need the fallback.
    return retval;
}

void SpooferBase::logHandler(QtMsgType type, const QMessageLogContext &ctx,
    const QString &msg)
{
    Q_UNUSED(ctx);

    if (!(DEBUG-0) && type == QtDebugMsg)
	return;

    const char *prefix =
	(type == QtDebugMsg)    ? "Debug"    :
	(type == QtWarningMsg)  ? "Warning"  :
	(type == QtCriticalMsg) ? "Critical" :
	(type == QtFatalMsg)    ? "Fatal"    :
	"Info";

    static int depth = 0;
    if (++depth > 1) { // should not happen
	fprintf(stderr, "INTERNAL ERROR: logHandler recursion\n");
	fprintf(stderr, "%s: %s\n", prefix, qPrintable(msg));
	::fflush(stderr);
    } else {
	sperr << prefix << ": " << msg << endl;
    }
    depth--;
}

// Caller can add additional options before calling parseCommandLine(), and
// inspect them after.
bool SpooferBase::parseCommandLine(QCommandLineParser &clp, QString desc)
{
    clp.setApplicationDescription(desc);

    QSettings *ds = findDefaultSettings(false);
    QString format = QSL("");
#ifdef Q_OS_WIN32
    if (ds->format() == QSettings::NativeFormat) format = QSL("registry ");
#endif
    QCommandLineOption cloSettings(QSL("settings"),
	QSL("Use settings in <file> [%1\"%2\"].").arg(format).arg(ds->fileName()),
	QSL("file"));
    clp.addOption(cloSettings);
    delete ds;

    // clp.addHelpOption() wouldn't include "-?" on non-Windows.
    QCommandLineOption cloHelp(QStringList() << QSL("?") << QSL("h") << QSL("help"),
	QSL("Display this help."));
    clp.addOption(cloHelp);

    if (!clp.parse(QCoreApplication::arguments())) {
	qCritical() << qPrintable(clp.errorText()) << endl;
	return false;
    }

    if (clp.isSet(cloHelp)) {
#if QT_VERSION >= 0x050500 // qInfo() was added in Qt 5.5
	qInfo() << qPrintable(clp.helpText());
#else
	sperr << qPrintable(clp.helpText()) << endl;
#endif
	return false;
    }

    if (clp.isSet(cloSettings))
	optSettings = clp.value(cloSettings);

    return true;
}

// Format is like QDateTime::toString(), with the addition that '~' will be
// removed after formatting, allowing you to create adjacent non-separated
// fields in output by inserting '~' between them in the input format.
QString SpooferBase::ftime_zone(const QString &fmt, const time_t *tp, const Qt::TimeSpec &spec)
{
    time_t t;
    if (!tp) { time(&t); tp = &t; }
    // QDateTime::fromTime_t() is not available in Qt >= 5.8(?);
    // QDateTime::fromSecsSinceEpoch() is not available in Qt < 5.8.
    return QDateTime::fromMSecsSinceEpoch(qint64(*tp) * 1000, spec)
	.toString(!fmt.isEmpty() ? fmt : QSL("yyyy-MM-dd HH:mm:ss t"))
	.remove(QLatin1Char('~'));
}
