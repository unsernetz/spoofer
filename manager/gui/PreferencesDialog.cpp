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

#include "spoof_qt.h"
#include <QDialog>
#include <QVBoxLayout>
#include <QDialogButtonBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QLabel>
#include <QGroupBox>
#include <QPushButton>
#include <QLineEdit>
#include <QLocalSocket>
#include "../../config.h"
#include "port.h"
#include "PreferencesDialog.h"
#include "SpooferUI.h"
static const char cvsid[] ATR_USED = "$Id: PreferencesDialog.cpp,v 1.35 2017/10/19 21:42:20 kkeys Exp $";

// a pointer to a Config::Member, and a widget used to edit it
class SettingWidget {
    SettingWidget(const SettingWidget&) NO_METHOD; // no copy-ctor
    void operator=(const SettingWidget&) NO_METHOD; // no copy-assign
protected:
    SpooferBase::Config::MemberBase *setting;
    SettingWidget(SpooferBase::Config::MemberBase *_setting, PreferencesDialog *prefDialog) :
	setting(_setting)
    {
	prefDialog->settingWidgets.push_back(this);
    }
public:
    virtual ~SettingWidget() {}
    virtual void reset() = 0;
    virtual void restoreDefault() = 0;
    virtual void setEnabled(bool flag) = 0;
    virtual QWidget *widget() = 0;
    virtual QVariant variant() = 0;
    void write(QLocalSocket *socket) {
	if (variant() != setting->variant() || (setting->required && !setting->isSet())) {
	    QString msg = QSL("set %1 %2\n").arg(setting->key, variant().toString());
	    socket->write(qPrintable(msg));
	}
    }
};


class BoolSettingWidget : public SettingWidget {
    QCheckBox *checkbox;
    BoolSettingWidget(const BoolSettingWidget&) NO_METHOD; // no copy-ctor
    BoolSettingWidget operator=(const BoolSettingWidget&) NO_METHOD; // no copy-assign
public:
    BoolSettingWidget(SpooferBase::Config::Member<bool> *_setting, PreferencesDialog *prefDialog) :
	SettingWidget(_setting, prefDialog),
	checkbox(new QCheckBox(setting->desc, prefDialog))
    {
	checkbox->setChecked(setting->variant().toBool());
    }
    ~BoolSettingWidget() {}
    void reset() { checkbox->setChecked(setting->variant().toBool()); }
    void restoreDefault() { checkbox->setChecked(setting->defaultVal.toBool()); }
    void setEnabled(bool flag) { checkbox->setEnabled(flag); }
    QWidget *widget() { return checkbox; }
    QVariant variant() { return QVariant(!!checkbox->checkState()); }
};

#if 0 // not used
class StringSettingWidget : public SettingWidget {
    QWidget *box;
    QLabel *label;
    QLineEdit *lineedit;
    StringSettingWidget(const StringSettingWidget&) NO_METHOD; // no copy-ctor
    StringSettingWidget operator=(const StringSettingWidget&) NO_METHOD; // no copy-assign
public:
    StringSettingWidget(SpooferBase::Config::Member<QString> *_setting, PreferencesDialog *prefDialog) :
	SettingWidget(_setting, prefDialog),
	box(new QWidget(prefDialog)),
	label(new QLabel(setting->desc)),
	lineedit(new QLineEdit(setting->variant().toString()))
    {
	QHBoxLayout *hbox = new QHBoxLayout;
	hbox->addWidget(label, 0);
	hbox->addWidget(lineedit, 1);
	hbox->setContentsMargins(0,0,0,0);
	box->setLayout(hbox);
    }
    ~StringSettingWidget() {}
    void reset() { lineedit->setText(setting->variant().toString()); }
    void restoreDefault() { lineedit->setText(setting->defaultVal.toString()); }
    void setEnabled(bool flag) { lineedit->setEnabled(flag); }
    QWidget *widget() { return box; }
    QVariant variant() { return QVariant(lineedit->text()); }
};
#endif

class IntSettingWidget : public SettingWidget {
    QSpinBox *spinbox;
    QWidget *w;
    IntSettingWidget(const IntSettingWidget&) NO_METHOD; // no copy-ctor
    IntSettingWidget operator=(const IntSettingWidget&) NO_METHOD; // no copy-assign
public:
    IntSettingWidget(SpooferBase::Config::MemberInt *_setting, PreferencesDialog *prefDialog) :
	SettingWidget(_setting, prefDialog),
	spinbox(new QSpinBox(prefDialog)),
	w(new QWidget())
    {
	QBoxLayout *layout = new QHBoxLayout();
	w->setLayout(layout);
	layout->setContentsMargins(0,0,0,0);

	layout->addWidget(new QLabel(setting->desc), 1);

	spinbox->setRange(_setting->minVal, _setting->maxVal);
	spinbox->setValue(setting->variant().toInt());
	spinbox->setAlignment(Qt::AlignRight);
	spinbox->setKeyboardTracking(false);
	spinbox->setAccelerated(true);
	// spinbox->setFrame(false);
	layout->addWidget(spinbox);
    }
    ~IntSettingWidget() {}
    void reset() { spinbox->setValue(setting->variant().toInt()); }
    void restoreDefault() { spinbox->setValue(setting->defaultVal.toInt()); }
    void setEnabled(bool flag) { spinbox->setEnabled(flag); }
    QWidget *widget() { return w; }
    QVariant variant() { return QVariant(spinbox->value()); }
};


PreferencesDialog::PreferencesDialog(QWidget *_parent, QLocalSocket *&_socket, bool editable) :
    QDialog(_parent), socket(_socket), buttonbox(), warningBanner(), settingWidgets()
{
    SettingWidget *w;
    this->setWindowTitle(QSL("Spoofer preferences"));

    QBoxLayout *topLayout = new QVBoxLayout;
    setLayout(topLayout);
    topLayout->setSizeConstraint(QLayout::SetFixedSize); // resize after hiding moreBox

    warningBanner = new QLabel();
    warningBanner->setFrameShape(QFrame::Box);
    QPalette pal = warningBanner->palette();
    pal.setColor(QPalette::WindowText, Qt::darkRed);
    pal.setColor(QPalette::Window, Qt::yellow);
    warningBanner->setAutoFillBackground(true);
    warningBanner->setPalette(pal);
    warningBanner->hide();
    topLayout->addWidget(warningBanner);

#if DEBUG
    QGroupBox *debugBox = new QGroupBox(QSL("Debug preferences"));
    topLayout->addWidget(debugBox);
    QBoxLayout *debugLayout = new QVBoxLayout;
    debugBox->setLayout(debugLayout);

    w = new BoolSettingWidget(&SpooferBase::config->useDevServer, this);
    debugLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->pretendMode, this);
    debugLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->standaloneMode, this);
    debugLayout->addWidget(w->widget());
#endif 

    QGroupBox *generalBox = new QGroupBox(QSL("General preferences"));
    topLayout->addWidget(generalBox);
    QBoxLayout *generalLayout = new QVBoxLayout;
    generalBox->setLayout(generalLayout);

    w = new BoolSettingWidget(&SpooferBase::config->enableIPv4, this);
    generalLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->enableIPv6, this);
    generalLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->sharePublic, this);
    generalLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->shareRemedy, this);
    generalLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->enableTLS, this);
    generalLayout->addWidget(w->widget());

    w = new IntSettingWidget(&SpooferBase::config->keepLogs, this);
    generalLayout->addWidget(w->widget());

    QWidget *moreBox = new QWidget();
    QBoxLayout *moreLayout = new QVBoxLayout;
    moreLayout->setMargin(0);
    topLayout->addWidget(moreBox);
    moreBox->setLayout(moreLayout);

    QGroupBox *probingBox = new QGroupBox(QSL("Scheduling details"));
    moreLayout->addWidget(probingBox);
    QBoxLayout *probingLayout = new QVBoxLayout;
    probingBox->setLayout(probingLayout);
    probingBox->hide();

    w = new IntSettingWidget(&SpooferBase::config->netPollInterval, this);
    probingLayout->addWidget(w->widget());

    w = new IntSettingWidget(&SpooferBase::config->delayInterval, this);
    probingLayout->addWidget(w->widget());

    w = new IntSettingWidget(&SpooferBase::config->proberInterval, this);
    probingLayout->addWidget(w->widget());

    w = new IntSettingWidget(&SpooferBase::config->proberRetryInterval, this);
    probingLayout->addWidget(w->widget());

    w = new IntSettingWidget(&SpooferBase::config->maxRetries, this);
    probingLayout->addWidget(w->widget());


#ifndef EVERYONE_IS_PRIVILEGED
    QGroupBox *permissionBox = new QGroupBox("Permissions");
    moreLayout->addWidget(permissionBox);
    QBoxLayout *permissionLayout = new QVBoxLayout;
    permissionBox->setLayout(permissionLayout);

    permissionLayout->addWidget(new QLabel("Allow unprivileged users on this computer to..."));

    w = new BoolSettingWidget(&SpooferBase::config->unprivView, this);
    permissionLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->unprivTest, this);
    permissionLayout->addWidget(w->widget());

    w = new BoolSettingWidget(&SpooferBase::config->unprivPref, this);
    permissionLayout->addWidget(w->widget());
#endif


    buttonbox = new QDialogButtonBox(
	QDialogButtonBox::Ok |
	QDialogButtonBox::Reset |
	QDialogButtonBox::RestoreDefaults |
	QDialogButtonBox::Cancel);
    QPushButton *moreButton = new QPushButton(QSL("More"));
    moreButton->setCheckable(true);
    buttonbox->addButton(moreButton, QDialogButtonBox::ActionRole);
    topLayout->addWidget(buttonbox);

    connect(buttonbox, &QDialogButtonBox::clicked, this, &PreferencesDialog::clicked);
    connect(moreButton, &QAbstractButton::toggled, probingBox, &QWidget::setVisible);

    if (!socket || socket->state() != QLocalSocket::ConnectedState) {
	editable = false;
	this->warn(QSL("Settings can not be changed without a connection to the scheduler."));
    }

    if (!editable) disable();
}

void PreferencesDialog::disable()
{
    foreach (SettingWidget *sw, settingWidgets)
	sw->setEnabled(false);
    buttonbox->button(QDialogButtonBox::Ok)->setEnabled(false);
    buttonbox->button(QDialogButtonBox::Reset)->setEnabled(false);
    buttonbox->button(QDialogButtonBox::RestoreDefaults)->setEnabled(false);
}

void PreferencesDialog::clicked(QAbstractButton *button)
{
    switch (buttonbox->standardButton(button)) {
    case QDialogButtonBox::Ok:
	if (socket && socket->state() == QLocalSocket::ConnectedState) {
	    accept();
	    // Note: Input widgets may not have the correct values before
	    // accept(), e.g. if the user typed some text into a widget and
	    // clicked "Ok" without first changing focus.
	    foreach (SettingWidget *sw, settingWidgets)
		sw->write(socket);
	}
	break;
    case QDialogButtonBox::Reset:
	foreach (SettingWidget *sw, settingWidgets)
	    sw->reset();
	warningBanner->hide();
	break;
    case QDialogButtonBox::RestoreDefaults:
	foreach (SettingWidget *sw, settingWidgets)
	    sw->restoreDefault();
	break;
    case QDialogButtonBox::Cancel:
	reject();
	break;
    default:
	break;
    }
}

void PreferencesDialog::warn(const QString &s)
{
    warningBanner->setText(s);
    warningBanner->show();
}

