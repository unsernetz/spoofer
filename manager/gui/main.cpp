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
#include "spoof_qt.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QMessageBox>
#include <QtDebug>
#include <QSpacerItem>
#include <QGridLayout>
#include <mainwindow.h>
#include "../../config.h"
#include "port.h"
static const char cvsid[] ATR_USED = "$Id: main.cpp,v 1.21 2017/03/09 23:42:03 kkeys Exp $";

static void msgboxLogHandler(QtMsgType type, const QMessageLogContext &ctx,
    const QString &msg)
{
    SpooferBase::logHandler(type, ctx, msg);
    if (type != QtDebugMsg) {
	QMessageBox mb;
	QString label;
	switch (type) {
	case QtWarningMsg:
	    mb.setIcon(QMessageBox::Warning);
	    label = QSL("Warning");
	    break;
	case QtCriticalMsg:
	case QtFatalMsg:
	    mb.setIcon(QMessageBox::Critical);
	    label = QSL("Error");
	    break;
	default: // note: QtInfoMsg was added in Qt 5.5
	    mb.setIcon(QMessageBox::Information);
	    label = QSL("Information");
	    break;
	}
	// note: setWindowTitle() would be ignored on OSX
	mb.setText(MainWindow::mainTitle % QSL(": ") % label);
	mb.setInformativeText(msg);
	mb.setStandardButtons(QMessageBox::Ok);

	// QMessageBox::setMinimumWidth() does not work because the box has a
	// grid layout.  Instead, we add a spacer row that spans all columns.
	QSpacerItem *spacer = new QSpacerItem(500, 0, QSizePolicy::Minimum,
	    QSizePolicy::Expanding);
	QGridLayout *layout = static_cast<QGridLayout*>(mb.layout());
	if (layout && spacer)
	    layout->addItem(spacer, layout->rowCount(), 0, 1, layout->columnCount());

	mb.exec();
    }
}

int qMain(int, char**); // silences warning about missing declaration

int main(int argc, char *argv[])
{
    int retval = -1;
    QApplication app(argc, argv);
    MainWindow window;

    qInstallMessageHandler(::msgboxLogHandler);

    QCommandLineParser clp;
    if (!SpooferBase::parseCommandLine(clp,
	QSL("Spoofer scheduler graphical user interface")))
    {
	retval = 1;
	goto done;
    }

    if (!window.initConfig()) {
	retval = 1;
	goto done;
    }

    window.init();
    window.show();

    retval = app.exec();
done:
    qDebug() << "exit " << retval;
    return retval;
}
