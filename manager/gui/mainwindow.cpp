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

// Disable some Qt features we don't need to speed up compilation and avoid
// some compiler warnings.
#define QT_NO_MATRIX4X4
#define QT_NO_VECTOR3D
#define QT_NO_VECTOR4D
#define QT_NO_QUATERNION

#include <time.h>
#include <errno.h>

#include "spoof_qt.h"
#include <QtGlobal>
#include <QAction>
#include <QtWidgets>
#include <QFile>
#include <QTextStream>
#include <QFileSystemWatcher>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QUrl>

#include "../../config.h"
#include "port.h"
#include "mainwindow.h"
#include "FileTailThread.h"
#include "ActionButton.h"
#include "PreferencesDialog.h"
#include "ColoredLabel.h"
static const char cvsid[] ATR_USED = "$Id: mainwindow.cpp,v 1.198 2017/12/06 01:25:29 kkeys Exp $";

MainWindow::WindowOutput *MainWindow::winout = nullptr;
MainWindow *MainWindow::theInstance = nullptr;
QPlainTextEdit *MainWindow::consoleWidget = nullptr;
ActionButton *MainWindow::consoleButton = nullptr;
QString MainWindow::mainTitle(QSL("Spoofer Manager GUI"));

class SessionResults {
public:
    int row;
    int ipv;
    uint32_t asn;
    QString ipaddr;
    QString routable;
    QString privaddr;
    QString ininternal;
    QString inprivaddr;
    SessionResults(int _ipv) : row(-1), ipv(_ipv), asn(0), ipaddr(),
	routable(), privaddr(), ininternal(), inprivaddr()
	{ }
};

class RunResults {
    RunResults(const RunResults&) NO_METHOD; // no copy-ctor
    RunResults operator=(const RunResults&) NO_METHOD; // no copy-assign
public:
    bool live;
    time_t started;
    QString logname;
    QString report;
    bool proberVersionMatch;
    SessionResults *results4;
    SessionResults *results6;
    RunResults(bool _live, const QString &_logname) :
	live(_live), started(_live ? time(nullptr) : 0), logname(_logname),
	report(), proberVersionMatch(false), results4(0), results6(0)
	{
	    static QRegularExpression re(SpooferBase::proberLogRegex);
	    QRegularExpressionMatch match = re.match(logname);
	    if (match.hasMatch()) {
		int year = match.captured(1).toInt();
		int mon = match.captured(2).toInt();
		int day = match.captured(3).toInt();
		int hour = match.captured(4).toInt();
		int min = match.captured(5).toInt();
		int sec = match.captured(6).toInt();
		QDateTime datetime(QDate(year, mon, day), QTime(hour, min, sec), Qt::UTC);
		started = static_cast<time_t>(datetime.toTime_t());
	    }
	}
    ~RunResults() {
	if (results4) delete results4;
	if (results6) delete results6;
    }
    void parseProberText(const QString &text, bool showMessages = true);
    void findResults(const QString &ipv, ProgressRow **progRow, SessionResults **results);
};

class LinkWidget : public ColoredLabel {
public:
    LinkWidget(const QUrl &_url, const QString &_text, QWidget *_parent = 0) :
	ColoredLabel(QSL("<a href='") % _url.toString(QUrl::FullyEncoded) % QSL("'>") %
	    _text.toHtmlEscaped() % QSL("</a>"), _parent)
    {
	this->setTextInteractionFlags(Qt::LinksAccessibleByMouse |
	    Qt::LinksAccessibleByKeyboard);
	this->setOpenExternalLinks(true);
	this->setStatusTip(_url.toString());
    }
};

template<class T>
class TableRow {
public:
    QLabel *title;
    T *content;
    TableRow(QGridLayout *grid, int rownum, const QString &_title, T *_content) :
	title(new QLabel(_title)), content(_content)
    {
	grid->addWidget(title, rownum, 0, Qt::AlignTop);
	grid->addWidget(content, rownum, 1, Qt::AlignTop);
    }
    void show() {
	title->show();
	content->show();
    }
};

static void retainSizeWhenHidden(QWidget *w)
{
    QSizePolicy sp;
    sp = w->sizePolicy();
    sp.setRetainSizeWhenHidden(true);
    w->setSizePolicy(sp);
}

class ProgressRow : public TableRow<QWidget> {
    // +---------+-------------------+
    // | title   | content---------+ |
    // |         | | text          | |
    // |         | | progbar       | |
    // |         | +---------------+ |
    // +---------+-------------------+
    ProgressRow(const ProgressRow&) NO_METHOD; // no copy-ctor
    ProgressRow operator=(const ProgressRow&) NO_METHOD; // no copy-assign
public:
    QString name;
    QLabel *text;
    QProgressBar *bar;
    SessionResults *results;
    ProgressRow(QGridLayout *grid, int rownum, QString _name) :
	TableRow(grid, rownum, _name, new QWidget()),
	name(_name), text(), bar(), results()
    {
	QVBoxLayout *vbox = new QVBoxLayout();
	content->setLayout(vbox);
	vbox->setContentsMargins(0,0,0,0);
	vbox->addWidget(text = new QLabel(QSL("no results yet")));
	vbox->addWidget(bar = new QProgressBar());
	bar->setFormat(QSL("%v/%m"));
	retainSizeWhenHidden(bar);
	retainSizeWhenHidden(text);
	retainSizeWhenHidden(title);
	bar->hide();
	text->hide();
	title->hide();
    }
    void start() {
	text->setText(QSL("untested"));
	bar->reset();
	bar->setMaximum(0);
	bar->setValue(0);
	bar->hide();
	text->show();
	title->show();
	show();
    }
    void stage(const QString &_text) {
	text->setText(_text);
	bar->show();
	text->show();
	title->show();
    }
    void tick(int progress, int goal) {
	bar->setMaximum(goal);
	bar->setValue(progress);
    }
    void endSession() {
	text->setText(!results ? QSL("incomplete") : QSL("done"));
    }
    void endProber() {
	bar->hide();
	text->hide();
	title->hide();
	results = nullptr;
    }
};

qint64 MainWindow::WindowOutput::writeData(const char *data, qint64 maxSize)
{
    // Note: on Windows, this is called twice for each line of text: first with
    // the visible text, and then with "\r\n".
    QScrollBar *sb = _textedit->verticalScrollBar();
    bool wasNearBottom = (sb->value() >= sb->maximum() - 5); // exact equality doesn't work

    // If sequential lines start with PROGRESS_PREFIX, 2nd will overwrite 1st.
    int chunklen = 0;
    int len = safe_int<int>(maxSize);
    const char *chunk = data;
    while (chunklen < len) {
	if (chunk[chunklen++] != '\n' && chunklen < len)
	    continue;
	if (_cursor->atBlockStart()) { // beginning of line?
	    if (strncmp(chunk, PROGRESS_PREFIX, sizeof(PROGRESS_PREFIX)-1) == 0) {
		if (overwritableStart >= 0)
		    _cursor->setPosition(overwritableStart, QTextCursor::KeepAnchor);
		overwritableStart = _cursor->position();
	    } else {
		overwritableStart = -1;
	    }
	    _cursor->insertText(QSL(" ")); // indent
	}
	_cursor->insertText(QString(QString::fromLocal8Bit(chunk, chunklen)));
	chunk += chunklen;
	len -= chunklen;
	chunklen = 0;
    }

    if (wasNearBottom)
	sb->setValue(sb->maximum());
    return maxSize;
}

void MainWindow::logHandler(QtMsgType type, const QMessageLogContext &ctx,
    const QString &msg)
{
    if (type == QtCriticalMsg || type == QtFatalMsg)
	if (!consoleWidget->isVisible())
	    consoleButton->click();
    QTextCharFormat oldfmt = winout->setLogCharFmt(type);
    SpooferBase::logHandler(type, ctx, msg);
    winout->setCharFmt(oldfmt);
}

static void setActionTip(QAction *action, QString tip)
{
    action->setStatusTip(tip);
    action->setToolTip(tip);
}

MainWindow::MainWindow(QWidget *_parent) :
    QMainWindow(_parent), SpooferUI(),
    schedWatcher(), countdownTimer(this), centralLayout(),
    proberInfoLabel(), proberCountdownLabel(), schedulerStatusLabel(),
    proberBoxLayout(), firstProberMsgIdx(), nextProberMsgIdx(),
    proberTimeRow(), progRow4(), progRow6(), currentRun(),
    aboutAct(), exitAct(), runAct(), abortAct(),
    pauseAct(), resumeAct(), shutdownAct(), hideGuiAct(), showGuiAct(),
    runButton(), pauseButton(), historyWidget(), prefDialog(), debugFlags()
{
    theInstance = this;
}

enum historyColumnId { HIST_date, HIST_ipv, HIST_ipaddr, HIST_asn,
    HIST_privaddr, HIST_routable, HIST_inprivaddr, HIST_ininternal,
    HIST_log, HIST_report, HIST_N };

static const struct {
    QString name;
    QString tip;
} historyHeader[HIST_N] = {
    { QSL("date"),           QSL("date and time of prober run") },
    { QSL("IPv"),            QSL("Internet Protocol version") },
    { QSL("client address"), QSL("IP address of spoofer client") },
    { QSL("ASN"),            QSL("Autonomous System number") },
    { QSL("egress\nprivate"),   QSL("result of sending spoofed private addresses") },
    { QSL("egress\nroutable"),  QSL("result of sending spoofed routable addresses") },
    { QSL("ingress\nprivate"),  QSL("result of receiving spoofed private addresses") },
    { QSL("ingress\ninternal"), QSL("result of receiving spoofed internal addresses") },
    { QSL("log"),            QSL("prober log file (technical)") },
    { QSL("report"),         QSL("summary report at website") }
};

static QLabel *resultWidget(const QString &raw)
{
    static QChar checkMark(0x2714);
    static QChar xMark(0x2718);
    QString text;
    QLabel *widget = new ColoredLabel();
    QPalette palette = widget->palette();
    if (raw.compare(QSL("BLOCKED"), Qt::CaseInsensitive) == 0) {
	text.append(checkMark).append(QSL(" "));
	palette.setColor(QPalette::Text, Qt::darkGreen);
    } else if (raw.compare(QSL("RECEIVED"), Qt::CaseInsensitive) == 0) {
	text.append(xMark).append(QSL(" "));
	palette.setColor(QPalette::Text, Qt::darkRed);
    } else if (raw.compare(QSL("REWRITTEN"), Qt::CaseInsensitive) == 0) {
	text.append(xMark).append(QSL(" "));
	palette.setColor(QPalette::Text, Qt::darkYellow);
    } else {
	text.append(QSL("? "));
    }
    widget->setText(text.append(raw));
    widget->setPalette(palette);
    return widget;
}

// Do extra initialization before QMainWindow::show().
void MainWindow::init() 
{
    QIcon spooferIcon;
    spooferIcon.addFile(QSL(":/icons/spoofer16.png"), QSize(16,16));
    spooferIcon.addFile(QSL(":/icons/spoofer32.png"), QSize(32,32));
    spooferIcon.addFile(QSL(":/icons/spoofer48.png"), QSize(48,48));
    spooferIcon.addFile(QSL(":/icons/spoofer64.png"), QSize(64,64));
    spooferIcon.addFile(QSL(":/icons/spoofer128.png"), QSize(128,128));
    spooferIcon.addFile(QSL(":/icons/spoofer256.png"), QSize(256,256));
    setWindowIcon(spooferIcon);

    scheduler = new QLocalSocket(this);

    //========= result history table
    historyWidget = new QTableWidget(this);

    //========= text output console
    consoleWidget = new QPlainTextEdit(this);

    //========= Actions
    QAction *prefAct = new QAction(QSL("&Preferences"), this);
    setActionTip(prefAct, QSL("Open preferences dialog"));
    connect(prefAct, &QAction::triggered, this, &MainWindow::openPreferences);

#if 0 // not used
    helpAct = new QAction(QSL("&Help"), this);
    setActionTip(helpAct, QSL("View documentation"));
    helpAct->setShortcut(QKeySequence::HelpContents);
    connect(helpAct, &QAction::triggered, this, &MainWindow::help);
#endif

    aboutAct = new QAction(QSL("&About Spoofer"), this);
    setActionTip(aboutAct, QSL("About Spoofer"));
    connect(aboutAct, &QAction::triggered, this, &MainWindow::about);

    exitAct = new QAction(QSL("&Exit GUI"), this);
    setActionTip(exitAct, QSL("Exit this GUI (does not affect Scheduler or Prober)"));
    exitAct->setShortcut(QKeySequence::Quit);
    connect(exitAct, &QAction::triggered, this, &MainWindow::close);

    hideGuiAct = new QAction(QSL("&Hide GUI"), this);
    setActionTip(hideGuiAct, QSL("Hide GUI"));
    hideGuiAct->setEnabled(true);
    connect(hideGuiAct, &QAction::triggered, this, &MainWindow::hide);

    showGuiAct = new QAction(QSL("&Show GUI"), this);
    setActionTip(showGuiAct, QSL("Show GUI"));
    showGuiAct->setEnabled(true);
    connect(showGuiAct, &QAction::triggered, this, &MainWindow::show);

    QAction *hideConsoleAct = new QAction(QSL("Hide &Console"), this);
    setActionTip(hideConsoleAct, QSL("Hide console"));
    connect(hideConsoleAct, &QAction::triggered, consoleWidget, &QPlainTextEdit::hide);

    QAction *showConsoleAct = new QAction(QSL("Show &Console"), this);
    setActionTip(showConsoleAct, QSL("Show console"));
    connect(showConsoleAct, &QAction::triggered, consoleWidget, &QPlainTextEdit::show);

    QAction *clearConsoleAct = new QAction(QSL("Clear Console"), this);
    setActionTip(clearConsoleAct, QSL("Erase contents of console window"));
    connect(clearConsoleAct, &QAction::triggered, consoleWidget, &QPlainTextEdit::clear);

#ifdef HIDABLE_HISTORY
    QAction *hideHistoryAct = new QAction(QSL("Hide Result &History"), this);
    setActionTip(hideHistoryAct, QSL("Hide results of previous tests"));
    connect(hideHistoryAct, &QAction::triggered, historyWidget, &QTableWidget::hide);

    QAction *showHistoryAct = new QAction(QSL("Show Result &History"), this);
    setActionTip(showHistoryAct, QSL("Show results of previous tests"));
    connect(showHistoryAct, &QAction::triggered, historyWidget, &QTableWidget::show);
#endif

    runAct = new QAction(QSL("Start Tests"), this);
    setActionTip(runAct, QSL("Start a Prober test run now"));
    runAct->setShortcut(QKeySequence::New);
    runAct->setEnabled(false);
    connect(runAct, &QAction::triggered, this, &MainWindow::runProber);

    abortAct = new QAction(QSL("Stop Tests"), this);
    setActionTip(abortAct, QSL("Stop the current Prober test run"));
    abortAct->setEnabled(false);
    connect(abortAct, &QAction::triggered, this, &MainWindow::abortProber);

    pauseAct = new QAction(QSL("&Pause Scheduler"), this);
    setActionTip(pauseAct, QSL("Disable automatic scheduled Prober runs"));
    pauseAct->setEnabled(false);
    connect(pauseAct, &QAction::triggered,
	this, &MainWindow::pauseScheduler);

    resumeAct = new QAction(QSL("&Resume Scheduler"), this);
    setActionTip(resumeAct, QSL("Enable automatic scheduled Prober runs"));
    resumeAct->setEnabled(false);
    connect(resumeAct, &QAction::triggered,
	this, &MainWindow::resumeScheduler);

    shutdownAct = new QAction(QSL("&Shutdown Scheduler"), this);
    setActionTip(shutdownAct, QSL("Shut down Scheduler (not recommended)"));
    shutdownAct->setEnabled(false);
    connect(shutdownAct, &QAction::triggered,
	this, &MainWindow::shutdownScheduler);

    //========= menubar
    // Note: menubar->addAction() may work on some platforms, but does not
    // work at all on OSX; only QMenus can be added to menubar.
    // (Toolbars, OTOH, can contain actions and widgets but not menus.)
    QMenuBar *menubar = this->menuBar();

    // Note: on OSX, Qt will move the special entries "about", "exit", and
    // "preferences" out to the OS menu unless their role is changed.
#ifdef Q_OS_MAC
    QMenu *spooferMenu = new QMenu(QSL("Preferences"));
    spooferMenu->menuAction()->setMenuRole(QAction::NoRole);
#else
    QMenu *spooferMenu = new QMenu(QSL("Spoo&fer"));
#endif
    spooferMenu->addAction(prefAct);
    spooferMenu->addAction(aboutAct);
    spooferMenu->addAction(exitAct);
    menubar->addMenu(spooferMenu);

    QMenu *schedulerMenu = new QMenu(QSL("&Scheduler"));
    schedulerMenu->addAction(pauseAct);
    schedulerMenu->addAction(resumeAct);
    schedulerMenu->addAction(shutdownAct);
    menubar->addMenu(schedulerMenu);

    QMenu *proberMenu = new QMenu(QSL("&Prober"));
    proberMenu->addAction(runAct);
    proberMenu->addAction(abortAct);
    menubar->addMenu(proberMenu);

    //========= status bar (for action tips)
    statusBar()->setSizeGripEnabled(false);

    //========= central widget
    QWidget *widget = new QWidget();
    setCentralWidget(widget);
    centralLayout = new QVBoxLayout;
    // centralLayout->addStrut(600); // minimum width
    widget->setLayout(centralLayout);

    //========= scheduler information
    QFrame *siBox = new QFrame();
    centralLayout->addWidget(siBox);
    siBox->setFrameStyle(QFrame::Panel | QFrame::Sunken);
    QHBoxLayout *siLayout = new QHBoxLayout();
    siBox->setLayout(siLayout);
    siLayout->addWidget(new QLabel(QSL("Scheduler:"), this));
    siLayout->addWidget(schedulerStatusLabel = new QLabel(QSL("unknown"), this), 1);
    siLayout->addWidget(pauseButton = new ActionButton(pauseAct, resumeAct, this));

    //========= prober information
    QFrame *proberBox = new QFrame();
    proberBox->setFrameStyle(QFrame::Panel | QFrame::Sunken);
    proberBoxLayout = new QVBoxLayout();
    proberBox->setLayout(proberBoxLayout);
    centralLayout->addWidget(proberBox);

    // prober grid
    QGridLayout *proberGrid = new QGridLayout;
    proberGrid->setColumnStretch(1, 1);
    proberBoxLayout->addLayout(proberGrid);
    int rownum = -1;

    // prober grid first line
    proberGrid->addWidget(new QLabel(QSL("Prober:"), this), ++rownum, 0, Qt::AlignVCenter);
    QHBoxLayout *p0 = new QHBoxLayout();
    proberGrid->addLayout(p0, rownum, 1, Qt::AlignVCenter);
    p0->addWidget(proberInfoLabel = new QLabel(QSL("schedule unknown"), this), 0);
    p0->addWidget(proberCountdownLabel = new QLabel(QSL(""), this), 1);
    p0->addWidget(runButton = new ActionButton(runAct, nullptr, this));
    connect(&countdownTimer, &QTimer::timeout, this, &MainWindow::setCountdownLabel);

    // prober time and progress bars
    proberTimeRow = new TableRow<QLabel>(proberGrid, ++rownum, QSL(""), new QLabel());
    progRow4 = new ProgressRow(proberGrid, ++rownum, QSL("IPv4 progress:"));
    progRow6 = new ProgressRow(proberGrid, ++rownum, QSL("IPv6 progress:"));

    // index for future prober messages
    nextProberMsgIdx = firstProberMsgIdx = proberBoxLayout->count();

    //========= history buttons
    QHBoxLayout *historyButtons = new QHBoxLayout();
    centralLayout->addLayout(historyButtons);

#ifdef HIDABLE_HISTORY
    //========= show/hide history button
    historyWidget->hide();
    ActionButton *historyButton = historyWidget->isVisible() ?
	new ActionButton(hideHistoryAct, showHistoryAct, this) :
	new ActionButton(showHistoryAct, hideHistoryAct, this);
    historyButtons->addWidget(historyButton, 0, Qt::AlignLeft);
#else
    historyButtons->addWidget(new QLabel(QSL("Result history:")), 0, Qt::AlignLeft);
#endif

    //========= show/hide blank history checkbox
    QCheckBox *hideBlankTestsButton = new QCheckBox(QSL("Hide old blank tests"), this);
    hideBlankTestsButton->setChecked(true);
    connect(hideBlankTestsButton, &QCheckBox::toggled, this, &MainWindow::hideBlankTests);
    historyButtons->addWidget(hideBlankTestsButton, 0, Qt::AlignRight);

    //========= result history table
    centralLayout->addWidget(historyWidget, 2);
    historyWidget->setSelectionMode(QAbstractItemView::NoSelection);
    historyWidget->setColumnCount(HIST_N);
    for (int i = 0; i < HIST_N; i++) {
	QTableWidgetItem *item = new QTableWidgetItem(historyHeader[i].name);
	if (!historyHeader[i].tip.isEmpty())
	    item->setToolTip(historyHeader[i].tip);
	historyWidget->setHorizontalHeaderItem(i, item);
    }
    int hsize = QFontInfo(historyWidget->font()).pixelSize();
    historyWidget->setMinimumHeight(12*hsize);
    historyWidget->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    historyWidget->verticalHeader()->setVisible(false);
    historyWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    historyWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    {
	// There ought to be a better way to do this...
	historyWidget->insertRow(0); // add dummy row to calculate width
	addHistoryCell(0, HIST_date, Qt::AlignLeft, new QLabel(QSL("0000-00-00 00:00:00")));
	addHistoryCell(0, HIST_ipv, Qt::AlignHCenter, new QLabel(QSL("0")));
	addHistoryCell(0, HIST_ipaddr, Qt::AlignLeft, new QLabel(QSL("000:000:000:000:000:000:000:000")));
	addHistoryCell(0, HIST_asn, Qt::AlignRight, new QLabel(QSL("00000")));
	addHistoryCell(0, HIST_privaddr, Qt::AlignHCenter, resultWidget(QSL("rewritten")));
	addHistoryCell(0, HIST_routable, Qt::AlignHCenter, resultWidget(QSL("rewritten")));
	addHistoryCell(0, HIST_inprivaddr, Qt::AlignHCenter, resultWidget(QSL("rewritten")));
	addHistoryCell(0, HIST_ininternal, Qt::AlignHCenter, resultWidget(QSL("rewritten")));
	addHistoryCell(0, HIST_log, Qt::AlignHCenter, new QLabel(QSL("log")));
	addHistoryCell(0, HIST_report, Qt::AlignHCenter, new QLabel(QSL("report")));
	historyWidget->resizeColumnsToContents();
	int histWidth = 0;
	for (int i = 0; i < HIST_N; i++)
	    histWidth += historyWidget->columnWidth(i);
	histWidth += historyWidget->verticalScrollBar()->sizeHint().width();
	historyWidget->setMinimumWidth(histWidth);
	historyWidget->removeRow(0); // remove dummy row
    }

    //========= console buttons
    QHBoxLayout *consoleButtons = new QHBoxLayout();
    centralLayout->addLayout(consoleButtons);

    //========= show/hide console button
    consoleWidget->hide();
    consoleButton = new ActionButton(showConsoleAct, hideConsoleAct, this);
    // If console visibility could be changed by something other than the
    // button, we'd have to detect that using a custom class Foo with an
    // eventFilter() that catches Show and Hide events, and then
    // consoleWidget->installEventFilter(Foo).
    consoleButtons->addWidget(consoleButton, 0, Qt::AlignLeft);

    //========= clear console button
    ActionButton *clearConsoleButton = new ActionButton(clearConsoleAct, nullptr, this);
    clearConsoleButton->hide();
    consoleButtons->addWidget(clearConsoleButton, 1, Qt::AlignLeft);
    connect(hideConsoleAct, &QAction::triggered, clearConsoleButton, &QPushButton::hide);
    connect(showConsoleAct, &QAction::triggered, clearConsoleButton, &QPushButton::show);

    //========= text output console
    centralLayout->addWidget(consoleWidget, 5);
    consoleWidget->setReadOnly(true);
    int csize = QFontInfo(consoleWidget->font()).pixelSize();
    consoleWidget->setMinimumHeight(15*csize);
    consoleWidget->setMaximumBlockCount(10000);
    // Create a cursor for appending, independent of the default cursor which
    // can be moved by the user (e.g., to copy a selection).
    winout = new WindowOutput(consoleWidget);
    outdev.setDevice(winout, QSL(""));
    errdev.setDevice(winout, QSL(""));
    qInstallMessageHandler(MainWindow::logHandler);

    //========= stretch
    // keep other stuff from stretching when history and console are hidden
    centralLayout->addStretch(0);




    qDebug() << "### cwd: " << qPrintable(QDir::toNativeSeparators(QDir::currentPath()));

    //========= other
    this->setWindowTitle(mainTitle);
    this->setEnabled(false); // until event loop is started

    loadHistoricLogs();
    showStatus();

#if 0
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
	qDebug() << "### System tray is available";
	QIcon *icon = new QIcon(QSL("/home/kkeys/WIP/spoofer/cropped/spoofer32.png")); // XXX
	QSystemTrayIcon *trayicon = new QSystemTrayIcon(*icon, 0);
	QMenu *traymenu = new QMenu(this);
	traymenu->addAction(aboutAct);
	traymenu->addAction(pauseAct);
	traymenu->addAction(resumeAct);
	traymenu->addAction(showGuiAct);
	traymenu->addAction(hideGuiAct);
	traymenu->addAction(exitAct);
	trayicon->setContextMenu(traymenu);
	trayicon->show();
    } else {
	qDebug() << "### System tray is NOT available";
    }
#endif

    this->setEnabled(true);
}

// Before doing anything that might alter the main window (e.g., by calling
// logHandler()) or trigger QApplication::exit(), wait until the MainWindow is
// visible (the Show event) and the event loop has started, plus a delay
// for mysterious other stuff that can cause display glitches if we didn't
// wait for it.
bool MainWindow::event(QEvent *ev)
{
    if (ev->type() == QEvent::Show) {
	static bool started = false;
	if (!started)
	    QTimer::singleShot(500, this, SLOT(initEvents()));
	started = true;
    }
    return QMainWindow::event(ev);
}

void MainWindow::initEvents()
{
    this->setEnabled(true);
    if (!connectScheduler(true))
	watchForSchedulerRestart();
}

bool MainWindow::connectScheduler(bool privileged)
{
    connect(scheduler, &QLocalSocket::connected,
	this, &MainWindow::schedConnected);
    connect(scheduler, &QLocalSocket::disconnected,
	this, &MainWindow::schedDisconnected);
    connect(scheduler, SIGCAST(QLocalSocket, error, (QLocalSocket::LocalSocketError)),
	this, &MainWindow::schedError);
    connect(scheduler, &QLocalSocket::readyRead,
	this, &MainWindow::readScheduler);
    return connectToScheduler(privileged);
}

bool MainWindow::opAllowed(const Config::MemberBase &cfgItem)
{
    return (scheduler && scheduler->state() == QLocalSocket::ConnectedState) &&
	(connectionIsPrivileged || cfgItem.variant().toBool());
}

void MainWindow::openPreferences()
{
    if (!prefDialog) {
	prefDialog = new PreferencesDialog(this, this->scheduler,
	    opAllowed(config->unprivPref));
	connect(prefDialog, &QDialog::finished, this, &MainWindow::closePreferences);
    }
    prefDialog->show();
    prefDialog->raise();
    prefDialog->activateWindow();
}

void MainWindow::closePreferences()
{
    if (prefDialog) {
	disconnect(prefDialog, nullptr, nullptr, nullptr);
	prefDialog->deleteLater();
	prefDialog = nullptr;
    }
}

void MainWindow::help() {
    qDebug() << "### signal: help";
}

void MainWindow::about() {
    static QString text;
    if (text.isNull()) { 
	text +=
	    QSL("<h1>" PACKAGE_NAME "</h1>") %
	    QSL("<span style='white-space: nowrap;'>") %
	    QSL(PACKAGE_DESC ", version " PACKAGE_VERSION "<br />") %
	    QSL("</span>") %
	    QSL(PACKAGE_LONGDESC "<br /><br />") %
	    QSL("<span style='white-space: nowrap;'>") %
	    QSL(COPYRIGHT).replace(QSL("; "), QSL("<br />")) %
	    QSL("</span>") %
	    QSL("<br /><br />") %
	    QSL("<a href='" PACKAGE_URL "'>" PACKAGE_URL "</a>" "<br />");
	    // QSL("contact: " PACKAGE_BUGREPORT "<br />");
    }
    QMessageBox::about(this, QSL("About Spoofer"), text);
}

void MainWindow::configChanged()
{
    if (prefDialog)
	prefDialog->warn(QSL("Warning: settings have changed since this window opened."));
}

void MainWindow::needConfig()
{
    openPreferences();
}

void MainWindow::schedConnected()
{   
    spout << "Connected to scheduler." << endl;
    connect(qApp, &QApplication::aboutToQuit, scheduler, &QLocalSocket::close);
    schedulerPaused = false; // until told otherwise
    schedulerNeedsConfig = false; // until told otherwise
    if (fileTail) // stale
	fileTail->requestInterruption();
    showStatus();
    if (schedWatcher) delete schedWatcher;
    schedWatcher = nullptr;
}

void MainWindow::schedCleanup(bool isError)
{
    if (prefDialog) {
	prefDialog->warn(QSL("Disconnected from Scheduler.  Settings can not be changed."));
	prefDialog->disable();
    }
    disconnect(qApp, nullptr, scheduler, nullptr);
    disconnect(scheduler, nullptr, nullptr, nullptr);
    if (isError) scheduler->abort();
    scheduler->close();
    scheduler->deleteLater();
    scheduler = new QLocalSocket(this);
    if (fileTail) {
	// Without the scheduler to tell us SC_PROBER_FINISHED, we'll assume
	// prober is done after a period of inactivity in the log.
	fileTail->setTimeout(10000);
    }
    showStatus();
#ifndef EVERYONE_IS_PRIVILEGED
    if (isError && connectionIsPrivileged)
	if (connectScheduler(false)) return;
#endif
    watchForSchedulerRestart();
}

void MainWindow::schedError()
{
    qCritical() << "Scheduler error:" << qPrintable(scheduler->errorString());
    schedCleanup(true);
}

void MainWindow::showStatus()
{
    statusBar()->clearMessage();
    if (fileTail) {
	runAct->setEnabled(false);
	abortAct->setEnabled(opAllowed(config->unprivTest));
    } else {
	runAct->setEnabled(opAllowed(config->unprivTest));
	abortAct->setEnabled(false);
    }
    runButton->setAction(fileTail ? abortAct : runAct);
    schedulerStatusLabel->setText(
	!scheduler || (scheduler->state() != QLocalSocket::ConnectedState) ?
	    QSL("not connected") :
	schedulerNeedsConfig ? QSL("pending configuration") :
	schedulerPaused ? QSL("paused") :
	QSL("ready"));
    proberInfoLabel->setEnabled(scheduler && scheduler->isOpen());
    proberCountdownLabel->setEnabled(scheduler && scheduler->isOpen());
    shutdownAct->setEnabled(scheduler && scheduler->isOpen());
    pauseAct->setEnabled(opAllowed(config->unprivPref) && !schedulerPaused);
    resumeAct->setEnabled(opAllowed(config->unprivPref) && schedulerPaused);
    if (schedulerPaused)
	pauseButton->setAction(resumeAct, pauseAct);
    else
	pauseButton->setAction(pauseAct, resumeAct);
}

bool MainWindow::finishProber()
{
    if (!SpooferUI::finishProber())
	return false;
    showStatus();
    // show results even if prober didn't exit properly
    proberTimeRow->title->setText(QSL("Last run:"));
    progRow4->endProber();
    progRow6->endProber();

    bool complete = false;
    if (currentRun) {
	complete = addHistoryReport(currentRun);
	delete currentRun;
	currentRun = nullptr;
    }
    if (!complete)
	proberTimeRow->content->setText(
	    proberTimeRow->content->text() % QSL(" (incomplete)"));
    return true;
}

bool MainWindow::setCountdownUnit(time_t when, time_t now, int count, int secs,
    QString unit, QString units)
{
    if ((when - now) > count * secs) {
	time_t n = (when - now + secs/2 - 1) / secs;
	proberCountdownLabel->setText(
	    QSL("(in about %1 %2)").arg(n).arg(n == 1 ? unit : units));
	time_t timeout = std::min(
	    (when - now + secs/2) % secs + 1, // the nearest X.5 units before when
	    (when - now) - count * secs);     // count units before when
	// qDebug() << "countdown: " << ftime(nullptr, &now) << ftime(nullptr, &when);
	// qDebug() << "countdown: label" << proberCountdownLabel->text() << ", diff" << when-now << ", new timeout" << timeout;
	countdownTimer.start(1000 * static_cast<int>(timeout));
	return true;
    } else {
	return false;
    }
}

void MainWindow::setCountdownLabel()
{
    time_t when = nextProberStart.when;
    if (!when) {
	countdownTimer.stop();
	proberCountdownLabel->setText(QString());
	return;
    }
    time_t now;
    time(&now);
    if (!setCountdownUnit(when, now, 2, 86400, QSL("day"), QSL("days")) &&
	!setCountdownUnit(when, now, 2, 3600, QSL("hour"), QSL("hours")) &&
	!setCountdownUnit(when, now, 1, 60, QSL("minute"), QSL("minutes")))
    {
	proberCountdownLabel->setText(QSL("(in less than 1 minute)"));
	countdownTimer.stop();
    }
}

void MainWindow::printNextProberStart()
{
    time_t when = nextProberStart.when;
    proberInfoLabel->setText(!when ? QSL("none scheduled") :
	QSL("next scheduled for ") % ftime(QString(), &when));
    setCountdownLabel();
    SpooferUI::printNextProberStart();
}

void MainWindow::startFileTail(QString logname)
{
    // clear old prober messages
    while (nextProberMsgIdx > firstProberMsgIdx) {
	QLayoutItem *item = proberBoxLayout->takeAt(--nextProberMsgIdx);
	if (!item || !item->widget()) continue; // impossible
	item->widget()->hide();
	delete item;
    }
    proberInfoLabel->setText(QSL("in progress"));
    proberCountdownLabel->setText(QSL(""));

    fileTail = new FileTailThread(logname);
    connect(fileTail, &FileTailThread::dataReady,
	this, &MainWindow::handleProberText,
	Qt::BlockingQueuedConnection);
	// Blocking avoids races between dataReady and finished
    connect(fileTail, &FileTailThread::finished,
	this, &MainWindow::finishProber);
    fileTail->start();
    currentRun = new RunResults(true, logname);
    showStatus();
    // hide any old results
    progRow4->start();
    progRow6->start();
    initRunDisplay(currentRun, QSL("Started:"));
    historyWidget->setRowHidden(0, false); // "live" row is visible by default
}

void MainWindow::hideBlankTests(bool checked)
{
    if (!historyWidget->rowCount()) return;
    bool liveSpan = fileTail ? historyWidget->rowSpan(0, HIST_date) : 0;
    for (int i = 0; i < historyWidget->rowCount(); i++) {
	if (!historyWidget->cellWidget(i, HIST_asn))
	    historyWidget->setRowHidden(i, checked && i >= liveSpan);
    }
    historyWidget->resizeColumnsToContents();
}

void MainWindow::loadHistoricLogs()
{
    QDir dir(config->dataDir());

    QStringList lognames = dir.entryList(QStringList() << proberLogGlob,
	QDir::Files | QDir::Readable, QDir::Name);

    for (int i = 0; i < lognames.size(); i++) {
	bool showMessages = (i == lognames.size() - 1);
	QString logname = dir.filePath(lognames.at(i));
	QFile file(logname);
	errno = 0;
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
	    qWarning() << "Failed to open" << qPrintable(logname) << ":" <<
		strerror(errno);
	    continue;
	}
	RunResults historicRun(false, logname);
	initRunDisplay(&historicRun, QSL("Last run:"));
	historyWidget->setRowHidden(0, true); // hide until endHistorySession()
	QTextStream in(&file);
	while (!in.atEnd()) {
	    historicRun.parseProberText(in.read(4096), showMessages);
	}
	addHistoryReport(&historicRun);
    }
}

void RunResults::findResults(const QString &ipv, ProgressRow **progRow, SessionResults **results)
{
    *progRow = nullptr;
    if (results) *results = nullptr;
    if (ipv.at(0) == QChar::fromLatin1('6')) {
	if (!this->results6)
	    this->results6 = new SessionResults(6);
	if (results)
	    *results = this->results6;
	if (this->live) {
	    *progRow = MainWindow::instance()->progRow6;
	    (*progRow)->results = this->results6;
	}
    } else {
	if (!this->results4)
	    this->results4 = new SessionResults(4);
	if (results)
	    *results = this->results4;
	if (this->live) {
	    *progRow = MainWindow::instance()->progRow4;
	    (*progRow)->results = this->results4;
	}
    }
}

void MainWindow::addHistoryCell(int row, int column, Qt::Alignment halign, QLabel *label)
{
    ColoredLabel *cl = dynamic_cast<ColoredLabel*>(label);
    if (cl && currentRun && currentRun->live) {
	// Fade from yellow to transparent in 10s
	QPropertyAnimation *anim = new QPropertyAnimation(cl, "bgcolor");
	anim->setDuration(10000);
	anim->setStartValue(QColor(255,255,0,255)); // opaque yellow
	anim->setEndValue(QColor(255,255,0,0)); // transparent yellow
	anim->start(QAbstractAnimation::DeleteWhenStopped);
    }
    label->setAlignment(halign | Qt::AlignVCenter);
    label->setContentsMargins(2,2,2,2);
    historyWidget->setCellWidget(row, column, label);
}

bool MainWindow::addHistoryReport(const RunResults *runResults)
{
    if (runResults->report.isEmpty()) return false;
    addHistoryCell(0, HIST_report, Qt::AlignHCenter, new LinkWidget(QUrl(runResults->report), QSL("report")));
    return true;
}

void MainWindow::initRunDisplay(const RunResults *runResults, const QString &timeTitle)
{
    debugFlags.clear();

    proberTimeRow->title->setText(timeTitle);
    proberTimeRow->content->setText(ftime(QString(), &runResults->started));
    proberTimeRow->show();

    historyWidget->insertRow(0);

    QLabel *timeLabel =
	new ColoredLabel(ftime(QSL("yyyy-MM-dd HH:mm:ss"), &runResults->started));
    // Time zone would be a waste of column space (especially on Windows where
    // it's not abbreviated), so we put it in a tool tip instead.
    timeLabel->setToolTip(ftime(QSL("t"), &runResults->started));
    addHistoryCell(0, HIST_date, Qt::AlignLeft, timeLabel);

    LinkWidget *link = new LinkWidget(QUrl::fromLocalFile(runResults->logname), QSL("log"));
    addHistoryCell(0, HIST_log, Qt::AlignHCenter, link);
    QFont linkFont = link->font();
    linkFont.setPointSizeF(linkFont.pointSizeF() * 0.8); // de-emphasize log link
    linkFont.setWeight(QFont::Light);
    link->setFont(linkFont);

    historyWidget->resizeColumnsToContents();
}

void MainWindow::addHistorySession(SessionResults *results)
{
    if (!results) return;
    if (results->row >= 0) return; // already added

    if (!historyWidget->cellWidget(0, HIST_ipv)) {
	// first session of the run; we will fill in the base row
	results->row = 0;
    } else {
	// Nth session of the run; we will insert a new row
	results->row = historyWidget->rowSpan(0, HIST_log);
	historyWidget->insertRow(results->row);

	// make some columns of row 0 span down into the new row
	historyWidget->setSpan(0, HIST_date, results->row + 1, 1);
	historyWidget->setSpan(0, HIST_log, results->row + 1, 1);
	historyWidget->setSpan(0, HIST_report, results->row + 1, 1);
    }

    QString ipv = QString::number(results->ipv);
    ipv.append(debugFlags);
    addHistoryCell(results->row, HIST_ipv, Qt::AlignHCenter, new ColoredLabel(ipv));

    historyWidget->setRowHidden(results->row, !fileTail);
    if (fileTail)
	historyWidget->resizeColumnsToContents();
}

void MainWindow::endHistorySession(SessionResults *results)
{
    if (!results) return;

    addHistoryCell(results->row, HIST_asn, Qt::AlignRight,
	new ColoredLabel(results->asn ? QString::number(results->asn) : QString()));
    addHistoryCell(results->row, HIST_privaddr, Qt::AlignHCenter,
	resultWidget(results->privaddr));
    addHistoryCell(results->row, HIST_routable, Qt::AlignHCenter,
	resultWidget(results->routable));
    if (!results->inprivaddr.isNull())
	addHistoryCell(results->row, HIST_inprivaddr, Qt::AlignHCenter,
	    resultWidget(results->inprivaddr));
    if (!results->ininternal.isNull())
	addHistoryCell(results->row, HIST_ininternal, Qt::AlignHCenter,
	    resultWidget(results->ininternal));

    historyWidget->setRowHidden(results->row, false); // row with results should always be visible
    historyWidget->resizeColumnsToContents();
    results->row = -1;
}

void RunResults::parseProberText(const QString &text, bool showMessages)
{
    static QString oldtext;
    static int offset = 0;
    static QRegularExpression re(QSL(
	// prober version, if it exactly matches ours
	">> \\Q" PACKAGE_DESC "\\E version (?<proberversion>\\Q" PACKAGE_VERSION "\\E)\n|"
	// debugging flags
	">>   (?<debugflag>standaloneMode|pretendMode|useDevServer)\n|"
	// start session
	"# ServerMessage \\(IPv(?<startv>[46])\\):\n"
	"(#  (?!hello:)\\S.*\n)*" // e.g. "textmsg"
	"#  hello:\n"
	"(#   (?!clientip:)\\S.*\n)*"
	"(?:#   clientip: (?<addr>[0-9a-fA-F.:]+)\n)?|"
	// start stage
	">> Running IPv(?<stagev>[46]) (?<stagetext>test \\d+:.*)\n|"
	// stage progress
	"\\Q" PROGRESS_PREFIX "\\E  (?<progresstext>.*)\n|"
	// result summary (note: versions < 1.2.0 did not have ingress lines
	// or ", egress" substrings.)
	">> IPv(?<endv>[46]) Result Summary:\n"
	">> +ASN: (?<asn>\\d+)\n"
	">> +Spoofed private addresses(, egress)?: (?<privaddr>\\w+)\n"
	">> +Spoofed routable addresses(, egress)?: (?<routable>\\w+)\n"
	"(?:>> +Spoofed private addresses, ingress: (?<inprivaddr>\\w+)\n)?"
	"(?:>> +Spoofed internal addresses, ingress: (?<ininternal>\\w+)\n)?|"
	// report url
	"Your test results:\\s+(?<report>\\S+)\n|"
	// server or scheduler message
	"(?<msg>[*][*][*] (?<msgpfx>(?:IPv[46] server )?"
	    "(?<msgtype>[Ee]rror|[Ww]arning|[Nn]otice)): (?<msgtxt>.*))\n"
	));

    const QString *subject = &text;
    if (!oldtext.isNull()) {
	// append new text to old partially-matched text
	oldtext += text;
	subject = &oldtext;
    }

    QRegularExpressionMatchIterator it = re.globalMatch(*subject, offset,
	QRegularExpression::PartialPreferFirstMatch);
    while (it.hasNext()) {
	QRegularExpressionMatch match = it.next();
	if (match.hasPartialMatch()) {
	    // save partially matched text and offset to try again later
	    offset = match.capturedStart(0);
	    if (oldtext.isNull())
		oldtext = text;
	    return;
	}
	ProgressRow *progRow = nullptr;
	SessionResults *results = nullptr;
	if (!match.captured(QSL("proberversion")).isNull()) {
	    this->proberVersionMatch = true;
	} else if (!match.captured(QSL("debugflag")).isNull()) {
	    if (match.captured(QSL("debugflag")).compare(QSL("standaloneMode")) == 0)
		MainWindow::instance()->debugFlags.append(QSL("S"));
	    if (match.captured(QSL("debugflag")).compare(QSL("pretendMode")) == 0)
		MainWindow::instance()->debugFlags.append(QSL("P"));
	    if (match.captured(QSL("debugflag")).compare(QSL("useDevServer")) == 0)
		MainWindow::instance()->debugFlags.append(QSL("T"));
	} else if (!match.captured(QSL("startv")).isNull()) {
	    this->findResults(match.captured(QSL("startv")), &progRow, &results);
	    MainWindow::instance()->addHistorySession(results);
	    if (!match.captured(QSL("addr")).isNull()) {
		results->ipaddr = match.captured(QSL("addr"));
		QLabel *label = new ColoredLabel(results->ipaddr);
		MainWindow::instance()->addHistoryCell(results->row, HIST_ipaddr,
		    Qt::AlignLeft, label);
		if (results->ipaddr.length() > 16) {
		    // smaller font so v6 addr doesn't use so much space
		    QFont labelFont = label->font();
		    labelFont.setPointSizeF(labelFont.pointSizeF() * 0.8);
		    label->setFont(labelFont);
		}
	    }
	} else if (!match.captured(QSL("endv")).isNull()) {
	    this->findResults(match.captured(QSL("endv")), &progRow, &results);
	    results->asn = match.captured(QSL("asn")).toUInt();
	    results->privaddr = match.captured(QSL("privaddr"));
	    results->routable = match.captured(QSL("routable"));
	    results->inprivaddr = match.captured(QSL("inprivaddr"));
	    results->ininternal = match.captured(QSL("ininternal"));
	    if (this->live) progRow->endSession();
	    MainWindow::instance()->endHistorySession(results);
	} else if (!match.captured(QSL("report")).isNull()) {
	    this->report = match.captured(QSL("report"));
	} else if ((this->live || (showMessages && this->proberVersionMatch)) &&
	    !match.captured(QSL("msgtype")).isNull())
	{
	    // The proberVersionMatch requirement prevents us from displaying
	    // a misleading out-of-date message like "new version available"
	    // when the client has been upgraded since the logged prober run.
	    QString msgtype = match.captured(QSL("msgtype")).toLower();
	    QLabel *label = new QLabel(match.captured(QSL("msg")));
	    label->setTextFormat(Qt::PlainText);
	    label->setWordWrap(true);
	    QPalette palette = label->palette();
	    if (msgtype.compare(QSL("error"), Qt::CaseInsensitive) == 0)
		palette.setColor(QPalette::Active, QPalette::WindowText, Qt::darkRed);
	    else if (msgtype.compare(QSL("warning"), Qt::CaseInsensitive) == 0)
		palette.setColor(QPalette::Active, QPalette::WindowText, Qt::darkMagenta);
	    label->setPalette(palette);
	    label->setEnabled(this->live);
	    label->setContentsMargins(20,0,0,0);
	    MainWindow *mw = MainWindow::instance();
	    while (mw->nextProberMsgIdx >= mw->firstProberMsgIdx + 5) {
		// too many messages; delete the oldest.
		QLayoutItem *item =
		    mw->proberBoxLayout->takeAt(mw->firstProberMsgIdx);
		if (item && item->widget()) { // should never be false
		    item->widget()->hide();
		    delete item;
		}
		mw->nextProberMsgIdx--;
	    }
	    mw->proberBoxLayout->insertWidget(mw->nextProberMsgIdx++, label);
	} else if (!this->live) {
	    // Do nothing.  Remaining matches are only for live runs.
	} else if (!match.captured(QSL("stagev")).isNull()) {
	    this->findResults(match.captured(QSL("stagev")), &progRow, nullptr);
	    progRow->stage(match.captured(QSL("stagetext")));
	} else if (!match.captured(QSL("progresstext")).isNull()) {
	    QString progText = match.captured(QSL("progresstext"));
	    QRegularExpression progRe(QSL("IPv(?<v>[46]): (\\d+\\+\\d+/)?(?<tries>\\d+)/(?<goal>\\d+)"));
	    QRegularExpressionMatchIterator progIt = progRe.globalMatch(progText);
	    while (progIt.hasNext()) {
		QRegularExpressionMatch progMatch = progIt.next();
		int tries = progMatch.captured(QSL("tries")).toInt();
		int goal = progMatch.captured(QSL("goal")).toInt();
		this->findResults(progMatch.captured(QSL("v")), &progRow, nullptr);
		progRow->tick(tries, goal);
	    }
	}
    }
    oldtext.clear();
    offset = 0;
}

void MainWindow::handleProberText(QString *text)
{
    currentRun->parseProberText(*text);
    QTextCharFormat oldfmt = winout->setProberCharFmt();
    SpooferUI::handleProberText(text);
    winout->setCharFmt(oldfmt);
}

void MainWindow::schedDisconnected()
{
    qWarning() << "Scheduler disconnected";
    schedCleanup(false);
}

void MainWindow::watchForSchedulerRestart()
{
    // When scheduler starts, it will update the settings and create a lock
    // file in dataDir.  So we watch for changes in one of those.
    QString file = config->isFile() ? config->fileName() : QString();
    QString dir = config->dataDir();
    if (!schedWatcher) {
	schedWatcher = new QFileSystemWatcher();
	connect(schedWatcher, &QFileSystemWatcher::fileChanged,
	    this, &MainWindow::reconnectScheduler);
	connect(schedWatcher, &QFileSystemWatcher::directoryChanged,
	    this, &MainWindow::reconnectScheduler);
    }

    // Note: after a change is signaled for a watched path, that path may or
    // may not still be in the watch list.
    if (!file.isNull())
	schedWatcher->addPath(file);

    if (schedWatcher->files().isEmpty() && !dir.isNull())
	schedWatcher->addPath(dir);

    if (schedWatcher->files().isEmpty() && schedWatcher->directories().isEmpty()) {
	delete schedWatcher;
	schedWatcher = nullptr;
	qDebug() << "watching failed!";
	return;
    }
    spout << "Waiting for scheduler to start..." << endl;
    qDebug() << "watching: " << schedWatcher->files() << " " << schedWatcher->directories();
}

void MainWindow::reconnectScheduler()
{
    qDebug() << "reconnectScheduler";
    QThread::msleep(1000); // give scheduler a chance to get going
    if (!connectScheduler(true))
	watchForSchedulerRestart();
}

void MainWindow::runProber() {
    qDebug() << "### signal: run";
    if (!fileTail) {
	scheduler->write("run\n");
    } else {
	qDebug() << "### prober is already running";
    }
}

void MainWindow::abortProber() {
    qDebug() << "### signal: abort";
    if (fileTail) {
	scheduler->write("abort\n");
    } else {
	qDebug() << "### prober is not running";
    }
}

void MainWindow::pauseScheduler() {
    qDebug() << "### signal: pause";
    scheduler->write("pause\n");
}

void MainWindow::resumeScheduler() {
    qDebug() << "### signal: resume";
    scheduler->write("resume\n");
}

void MainWindow::shutdownScheduler() {
    QMessageBox mb;
    mb.setIcon(QMessageBox::Warning);
    mb.setText(QSL("<b>Shut down Spoofer scheduler?</b>"));
    mb.setInformativeText(QSL("Once the scheduler is shut down, this GUI will "
	"not be able to restart it or do anything else; and it may restart "
	"automatically at next reboot depending on its configuration.  Use "
	"\"Pause Scheduler\" instead to disable scheduled tests in a way that "
	"can be easily re-enabled and will persist across reboots."));
    mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
    if (mb.exec() == QMessageBox::Yes)
	scheduler->write("shutdown\n");
}

