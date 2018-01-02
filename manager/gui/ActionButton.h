#ifndef ACTIONBUTTON_H
#define ACTIONBUTTON_H

#include <QPushButton>
#include <QAction>
#include "port.h"

// Simple extension of QPushButton that allows a QAction to be attached such
// that clicking the button triggers the action, and the button's status is
// updated when the action's status changes.
// If an alternate action is set, the current and alternate actions will be
// swapped when the button is clicked.
class ActionButton : public QPushButton
{
    Q_OBJECT

private:
    QAction* action;
    QAction* alt;

    ActionButton(const ActionButton&) NO_METHOD; // no copy-ctor
    ActionButton operator=(const ActionButton&) NO_METHOD; // no copy-assign

public:
    explicit ActionButton(QAction *_action = 0, QAction *_alt = 0, QWidget *_parent = 0) :
	QPushButton(_parent), action(0), alt(0)
	{ setAction(_action, _alt); }
    void setAction(QAction* action, QAction *alt = 0);
    void swap();

private slots:
    void updateStatus();
};

#endif // ACTIONBUTTON_H
