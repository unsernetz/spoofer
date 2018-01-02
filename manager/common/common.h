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

#ifndef SPOOFER_MANAGER_COMMON_COMMON_H
#define SPOOFER_MANAGER_COMMON_COMMON_H

#include "../../config.h"
#include <typeinfo>
#include <ctime>

#define QT_NO_CAST_FROM_ASCII
#include <QString>
#include <QStringBuilder> // efficient string concatenation with operator%
#define QSL(str) QStringLiteral(str)

#include <QDataStream>
#include <QCoreApplication>
#include <QFile>
#include <QHostAddress>
#include <QDateTime>
#include <QSettings>
#include <QList>

#include "port.h"

// forward declarations
QT_BEGIN_NAMESPACE
class QCommandLineParser;
QT_END_NAMESPACE

#define EVERYONE_IS_PRIVILEGED 1

// scheduler messages
enum sc_msg_type {
    SC_ERROR,
    SC_TEXT,
    SC_SCHEDULED,
    SC_PROBER_STARTED,
    SC_PROBER_FINISHED,
    SC_PROBER_ERROR,
    SC_PAUSED,
    SC_RESUMED,
    SC_DONE_CMD,
    SC_CONFIG_CHANGED,
    SC_NEED_CONFIG,
    SC_CONFIGED
};

struct sc_msg_text {
    QString text;
    sc_msg_text(const QString &_text = QString()) : text(_text) {}
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_text &msg) {
    return out << msg.text;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_text &msg) {
    return in >> msg.text;
}

struct sc_msg_scheduled {
    // QHostAddress addr;
    qint32 when;
    sc_msg_scheduled() : /*addr(),*/ when(0) {}
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_scheduled &msg) {
    return out /*<< msg.addr*/ << msg.when;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_scheduled &msg) {
    return in /*>> msg.addr*/ >> msg.when;
}

#if 0
struct sc_msg_started {
    QHostAddress addr;
    QString logfile;
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_started &msg) {
    return out << msg.addr << msg.logfile;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_started &msg) {
    return in >> msg.addr >> msg.logfile;
}

struct sc_msg_success {
    QHostAddress addr;
    QString logfile;
    QString url;
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_success &msg) {
    return out << msg.addr << msg.logfile << msg.url;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_success &msg) {
    return in >> msg.addr >> msg.logfile >> msg.url;
}

struct sc_msg_failed {
    QHostAddress addr;
    QString logfile;
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_failed &msg) {
    return out << msg.addr << msg.logfile;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_failed &msg) {
    return in >> msg.addr >> msg.logfile;
}

struct sc_msg_disabled {
    QHostAddress addr;
    QDateTime when;
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_disabled &msg) {
    return out << msg.addr << msg.when;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_disabled &msg) {
    return in >> msg.addr >> msg.when;
}

struct sc_msg_disconnected {
    QHostAddress addr;
};

inline QDataStream &operator<<(QDataStream &out, const sc_msg_disconnected &msg) {
    return out << msg.addr;
}

inline QDataStream &operator>>(QDataStream &in, sc_msg_disconnected &msg) {
    return in >> msg.addr;
}
#endif

// base class for Spoofer applications
class SpooferBase {
public:
    // A write-only QIODevice that wraps another but doesn't open it until
    // needed, and can be switched to a different device at any time.
    class OnDemandDevice : public QIODevice {
    private:
	QIODevice *dev, *newdev, *fallback;
	QString newname;
	bool timestampEnabled;
	OnDemandDevice(OnDemandDevice &) NO_METHOD; // no copy-ctor
	OnDemandDevice operator=(OnDemandDevice &) NO_METHOD; // no copy-assign
    public:
	OnDemandDevice(FILE *file) :
	    QIODevice(), dev(), newdev(), fallback(), newname(), timestampEnabled()
	{
	    QFile *qfile = new QFile();
	    if (qfile) qfile->open(file, WriteOnly|Unbuffered);
	    dev = qfile;
	    this->open(WriteOnly);
	}
	qint64 readData(char *data, qint64 maxSize)
	    { Q_UNUSED(data); Q_UNUSED(maxSize); return -1; }
	qint64 writeData(const char *data, qint64 maxSize);
	void setDevice(QIODevice *device, const QString &name) {
	    newname = name;
	    newdev = device;
	}
	void setDevice(QFileDevice *device) {
	    setDevice(device, device->fileName());
	}
	void setFallbackDevice(QFileDevice *device) {
	    fallback = device;
	}
	void close() {
	    QIODevice::close();
	    if (dev) { delete dev; dev = nullptr; }
	    if (newdev) { delete newdev; newdev = nullptr; }
	    if (fallback) { delete fallback; fallback = nullptr; }
	}
	const std::type_info& type() { return dev ? typeid(*dev) : typeid(0); }
	void setTimestampEnabled(bool flag) { timestampEnabled = flag; }
	bool getTimestampEnabled() const { return timestampEnabled; }
    };

    class Config {
	bool forWriting;
	ATR_UNUSED_MEMBER uint8_t unused_padding[3];
    public:
	struct MemberBase {
	    const QString key;
	    QVariant defaultVal;
	    bool required;
	    const QString desc;
	    MemberBase(QString _key, QVariant _defaultVal, QString _desc = QString(), bool _hidden = false) :
		key(_key), defaultVal(_defaultVal), required(false), desc(_desc)
	    {
		if (_hidden || desc.isNull()) return;
#ifdef EVERYONE_IS_PRIVILEGED
		if (_key.startsWith(QSL("unpriv"))) return;
#endif
		members.push_back(this);
	    }
	    virtual ~MemberBase() {}
	    virtual QVariant variant() const = 0;
	    virtual bool setFromString(QString value, QString &errmsg) = 0;
	    void remove()            // remove: config->foo.remove()
		{ if (settings) settings->remove(key); }
	    void setDefault(QVariant d) { defaultVal = d; }
	    bool isSet() const
		{ return settings && settings->contains(key); }
	    virtual QString optionHelpString() = 0;
	};
	template <class T> struct Member : public MemberBase {
	    Member(QString _key, T _defaultVal = T(), QString _desc = QString(), bool _hidden = false) :
		MemberBase(_key, QVariant(_defaultVal), _desc, _hidden) {}
	    ~Member() {}
	    T operator()() const // get: config->foo()
		{ return variant().template value<T>(); }
	    QVariant variant() const
		{ return settings ? settings->value(key, defaultVal) : defaultVal; }
	    void operator()(T value) // set: config->foo(value)
		{ if (settings) settings->setValue(key, QVariant(value)); }
	    bool setFromString(QString value, QString &errmsg) {
		if (!settings) return false;
		QVariant var(value);
		int qtypeid = qMetaTypeId<T>();
		if (!var.convert(qtypeid)) {
		    errmsg = QSL("%1: can not convert \"%2\" to %3.").
			arg(key).arg(value).
			arg(QString::fromLocal8Bit(QMetaType::typeName(qtypeid)));
		    qDebug() << errmsg;
		    return false;
		}
		if (!validate(var, errmsg)) return false;
		settings->setValue(key, var);
		return true;
	    }
	    QString optionHelpString() { return optionHelpString(*this); }
	private:
	    virtual bool validate(QVariant var, QString &errmsg)
		{ Q_UNUSED(var); Q_UNUSED(errmsg); return true; }
	    template <typename U> QString optionHelpString(const Member<U> &member) {
		Q_UNUSED(member);
		return QSL("%1 from now on [\"%2\" setting or \"%3\"].").
		    arg(desc).arg(key).arg(defaultVal.toString());
	    }
	    // C++ doesn't allow an explicit template specialization inside a
	    // class, but does allow an overload.  (The unused parameter is
	    // just for overload resolution.)
	    QString optionHelpString(const Member<bool> &member) {
		Q_UNUSED(member);
		return QSL("%1 from now on (yes/no) [\"%2\" setting or %3].").
		    arg(desc).arg(key).arg(defaultVal.toInt());
	    }
	};
	struct MemberInt : public Member<int> {
	    int minVal, maxVal;
	    MemberInt(QString _key, int _defaultVal, int _minVal, int _maxVal,
		QString _desc = QString(), bool _hidden = false) :
		Member(_key, _defaultVal, _desc, _hidden),
		minVal(_minVal), maxVal(_maxVal)
		{}
	private:
	    bool validate(QVariant var, QString &errmsg) {
		int val = var.value<int>();
		if (val >= minVal && val <= maxVal) return true;
		errmsg = QSL("%1: value %2 out of range [%3, %4]").
		    arg(key).arg(val).arg(minVal).arg(maxVal);
		qDebug() << errmsg;
		return false;
	    }
	};
	static QSettings *settings;
    public:
	static QList<MemberBase*> members;

	Member<QString> dataDir;
	Member<QString> schedulerSocketName;
	Member<bool> paused;
#if DEBUG
	Member<bool> useDevServer;
	Member<bool> pretendMode;
	Member<bool> standaloneMode;
#endif
	Member<bool> enableIPv4;
	Member<bool> enableIPv6;
	MemberInt keepLogs;
	Member<bool> sharePublic;
	Member<bool> shareRemedy;
	Member<bool> enableTLS;
	MemberInt netPollInterval;
	MemberInt delayInterval;
	MemberInt proberInterval;
	MemberInt proberRetryInterval;
	MemberInt maxRetries;
	Member<bool> unprivView;
	Member<bool> unprivTest;
	Member<bool> unprivPref;

	Config();
	void initSettings(bool forWriting = false, bool debug = false);
	~Config() { if (settings) delete settings; settings = nullptr; }

	bool error(const char *label);
	void logError(const char *label, QString msg, QString msg2 = QString());
	QString lockFileName();
	void remove();

	QString fileName() {
	    return settings ? settings->fileName() : QString();
	}

	bool isFile() {
	    if (!settings) return false;
#ifdef Q_OS_WIN32
	    if (settings->format() == QSettings::NativeFormat)
		return false; // windows registry
#endif
	    return true;
	}

	bool sync() {
	    if (!settings) return false;
	    settings->sync();
	    return !error("Config sync:");
	}

	MemberBase *find(const QString &key) {
	    for (int i = 0; i < members.size(); i++) {
		if (key.compare(members[i]->key, Qt::CaseInsensitive) == 0)
		    return members[i];
	    }
	    return nullptr;
	}

	bool hasRequiredSettings() {
	    for (int i = 0; i < members.size(); i++) {
		if (members[i]->required && !members[i]->isSet())
		    return false;
	    }
	    return true;
	}
    };

    QString appDir;
    QString appFile;
    static QString optSettings;
    static Config *config;
    static OnDemandDevice outdev;
    static OnDemandDevice errdev;
    static QTextStream spout;
    static QTextStream sperr;
    static const QString proberLogFtime;
    static const QString proberLogGlob;
    static const QString proberLogRegex;

    SpooferBase();

    virtual ~SpooferBase() {
	if (config) delete config;
    }

    static void logHandler(QtMsgType type,
	const QMessageLogContext &ctx, const QString &msg);
    static bool parseCommandLine(QCommandLineParser &clp, QString desc);
    static QString ftime_zone(const QString &fmt, const time_t *tp, const Qt::TimeSpec &spec);
    static QString ftime(const QString &fmt = QString(), const time_t *tp = nullptr)
	{ return ftime_zone(fmt, tp, Qt::LocalTime); }
    static QString ftime_utc(const QString &fmt = QString(), const time_t *tp = nullptr)
	{ return ftime_zone(fmt, tp, Qt::UTC); }

    static QSettings *findDefaultSettings(bool debug)
    {
	QSettings::Scope scope = debug ? QSettings::UserScope :
	    QSettings::SystemScope;
	// Mac expects a domain here where others expect a name.
	// QSettings() with no parameters would correctly auto-pick
	// the domain or name, but doesn't let us specify the scope.
	return new QSettings(scope,
#ifdef Q_OS_MAC
	    QCoreApplication::organizationDomain(),
#else
	    QCoreApplication::organizationName(),
#endif
	    QCoreApplication::applicationName(), nullptr);
    }

    bool initConfig(bool _forWriting = false) {
	config->initSettings(_forWriting);
	if (config->error("Config")) // XXX ???
	    return false;
	if (!_forWriting && config->dataDir().isEmpty()) {
	    // QSettings doesn't consider a missing file an error.  But if
	    // we want read-only and dataDir is missing, something is wrong.
	    config->logError("Config", QSL("Missing \"dataDir\""),
		QSL("Make sure the scheduler is running and using the same configuration."));
	    return false;
	}
	return true;
    }
};

#endif // SPOOFER_MANAGER_COMMON_COMMON_H
