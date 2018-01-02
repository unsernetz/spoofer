#include "../../config.h"
#include "spoof_qt.h"
#include "ActionButton.h"

void ActionButton::setAction(QAction *_action, QAction *_alt)
{
    if (action) {
	disconnect(action, nullptr, this, nullptr);
	disconnect(this, nullptr, action, nullptr);
	disconnect(this, nullptr, this, nullptr);
    }

    action = _action;
    alt = _alt;
    updateStatus();

    // When action status changes, so does button status.
    connect(action, &QAction::changed, this, &ActionButton::updateStatus);
    connect(action, &QAction::toggled, this, &ActionButton::setChecked);
    // Clicking the button triggers the action...
    connect(this, &ActionButton::clicked, action, &QAction::trigger);
    // ...and THEN swaps the current and alternate actions.
    connect(this, &ActionButton::clicked, this, &ActionButton::swap);
}

void ActionButton::swap()
{
    if (alt) setAction(alt, action);
}

void ActionButton::updateStatus()
{
    setCheckable(action->isCheckable());
    setEnabled(action->isEnabled());
    setIcon(action->icon());
    setText(action->text());
    setToolTip(action->toolTip());
    setStatusTip(action->statusTip());
    setWhatsThis(action->whatsThis());
    setFont(action->font());
    setVisible(action->isVisible());
}
