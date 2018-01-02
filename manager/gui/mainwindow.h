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

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QTimer>
#include "SpooferUI.h"

// forward declarations
QT_BEGIN_NAMESPACE
class QFileSystemWatcher;
class QWidget;
class QLabel;
class QTableWidget;
class QFrame;
class QVBoxLayout;
QT_END_NAMESPACE
template<class T> class TableRow;
class ProgressRow;
class SessionResults;
class RunResults;
class ActionButton;
class PreferencesDialog;

class MainWindow : public QMainWindow, public SpooferUI {
    Q_OBJECT

    friend class RunResults;

    MainWindow(const MainWindow&) NO_METHOD; // no copy-ctor
    MainWindow operator=(const MainWindow&) NO_METHOD; // no copy-assign

    class WindowOutput : public QIODevice {
	QPlainTextEdit *_textedit;
	QTextCursor *_cursor;
	int overwritableStart; // position of beginning of overwritable text
	WindowOutput(const WindowOutput&) NO_METHOD; // no copy-ctor
	WindowOutput operator=(const WindowOutput&) NO_METHOD; // no copy-assign
    public:
	WindowOutput(QPlainTextEdit *textedit) :
	    QIODevice(), _textedit(textedit),
	    _cursor(new QTextCursor(textedit->textCursor())),
	    overwritableStart(-1)
	    {}
	QTextCharFormat setLogCharFmt(QtMsgType type) {
	    QTextCharFormat oldFmt = _cursor->charFormat();
	    QTextCharFormat newFmt = oldFmt;
	    newFmt.setForeground(QBrush(
		(type == QtDebugMsg)    ? Qt::darkBlue :
		(type == QtWarningMsg)  ? Qt::darkMagenta :
		(type == QtCriticalMsg) ? Qt::darkRed :
		(type == QtFatalMsg)    ? Qt::darkRed :
		Qt::darkBlue));
	    _cursor->setCharFormat(newFmt);
	    return oldFmt;
	}
	QTextCharFormat setProberCharFmt() {
	    QTextCharFormat oldFmt = _cursor->charFormat();
	    QTextCharFormat newFmt = oldFmt;
	    QFont font(QSL("mono"), oldFmt.font().pointSize());
	    font.setStyleHint(QFont::TypeWriter);
	    newFmt.setFont(font);
	    newFmt.setForeground(QBrush(Qt::darkGreen));
	    _cursor->setCharFormat(newFmt);
	    return oldFmt;
	}
	void setCharFmt(const QTextCharFormat &fmt) { _cursor->setCharFormat(fmt); }
    protected:
	qint64 readData(char *data, qint64 maxSize) Q_DECL_OVERRIDE
	    { Q_UNUSED(data); Q_UNUSED(maxSize); return -1; }
	qint64 writeData(const char *data, qint64 maxSize) Q_DECL_OVERRIDE;
    };

public:
    static void logHandler(QtMsgType type, const QMessageLogContext &ctx,
	const QString &msg);
    static MainWindow *instance() { return theInstance; }
    static QString mainTitle;

    MainWindow(QWidget *parent = nullptr);
    void init();
private slots:
    void initEvents();
    bool opAllowed(const Config::MemberBase &cfgItem);
    void openPreferences();
    void closePreferences();
    void help();
    void about();
    void runProber();
    void abortProber();
    void pauseScheduler();
    void resumeScheduler();
    void shutdownScheduler();
    void schedConnected();
    void schedError();
    void readScheduler() { SpooferUI::readScheduler(); showStatus(); }
    void schedDisconnected();
    void handleProberText(QString *text);
    bool finishProber() Q_DECL_OVERRIDE;
    void reconnectScheduler();
    void setCountdownLabel();
    void hideBlankTests(bool checked);
private:
    static MainWindow *theInstance;
    static WindowOutput *winout;
    QFileSystemWatcher *schedWatcher;
    QTimer countdownTimer;
    QVBoxLayout *centralLayout;
    QLabel *proberInfoLabel;
    QLabel *proberCountdownLabel;
    QLabel *schedulerStatusLabel;
    QVBoxLayout *proberBoxLayout;
    int firstProberMsgIdx;
    int nextProberMsgIdx;
    TableRow<QLabel> *proberTimeRow;
    ProgressRow *progRow4;
    ProgressRow *progRow6;
    RunResults *currentRun;
    QAction *aboutAct;
    QAction *exitAct;
    QAction *runAct;
    QAction *abortAct;
    QAction *pauseAct;
    QAction *resumeAct;
    QAction *shutdownAct;
    QAction *hideGuiAct;
    QAction *showGuiAct;
    ActionButton *runButton;
    ActionButton *pauseButton;
    static QPlainTextEdit *consoleWidget;
    static ActionButton *consoleButton;
    QTableWidget *historyWidget;
    PreferencesDialog *prefDialog;
    QString debugFlags;
    bool event(QEvent *ev) Q_DECL_OVERRIDE;
    void schedCleanup(bool isError);
    bool connectScheduler(bool privileged);
    void showStatus();
    void addHistoryCell(int row, int column, Qt::Alignment halign, QLabel *label);
    bool addHistoryReport(const RunResults *runResults);
    void initRunDisplay(const RunResults *runResults, const QString &timeTitle);
    void addHistorySession(SessionResults *results);
    void endHistorySession(SessionResults *results);
    void loadHistoricLogs();
    void startFileTail(QString logname) Q_DECL_OVERRIDE;
    void watchForSchedulerRestart();
    void printNextProberStart() Q_DECL_OVERRIDE;
    bool setCountdownUnit(time_t when, time_t now, int count, int size,
	QString unit, QString units);
    void configChanged() Q_DECL_OVERRIDE;
    void needConfig() Q_DECL_OVERRIDE;
};
