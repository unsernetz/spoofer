
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

#include <QDialog>
#include "SpooferUI.h"

// forward declarations
class MainWindow;
class QLocalSocket;
class QLabel;
class QAbstractButton;
class QDialogButtonBox;
class SettingWidget;

class PreferencesDialog : public QDialog {
    Q_OBJECT

    QLocalSocket *&socket; // ref because pointer could change in other thread
    QDialogButtonBox *buttonbox;
    QLabel *warningBanner;

public:
    QList<SettingWidget*> settingWidgets;
    PreferencesDialog(QWidget *parent, QLocalSocket *&socket, bool editable);
    void warn(const QString &s);
    void disable();

private slots:
    void clicked(QAbstractButton *button);
    //void restoreDefaults();

private:
    PreferencesDialog(const PreferencesDialog&) NO_METHOD; // no copy-ctor
    PreferencesDialog operator=(const PreferencesDialog&) NO_METHOD; // no copy-assign
};
