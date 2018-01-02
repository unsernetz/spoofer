#ifndef COLOREDLABEL_H
#define COLOREDLABEL_H

#include <QLabel>
#include "spoof_qt.h"

class ColoredLabel : public QLabel
{
    Q_OBJECT
    Q_PROPERTY(QColor bgcolor READ bgcolor WRITE setBgcolor)

public:
    ColoredLabel(QWidget *_parent = 0) : QLabel(_parent) {}
    ColoredLabel(const QString &_text, QWidget *_parent = 0) : QLabel(_text, _parent) {}
    void setBgcolor(QColor c) {
	// Note: an alpha value of "1" in rgba() is interpreted in the float
	// 0-1 scale where it means fully opaque, not the int 0-255 scale
	// where it would mean almost transparent.
	setStyleSheet(QSL("background-color: rgba(%1,%2,%3,%4);")
	    .arg(c.red()).arg(c.green()).arg(c.blue()).arg(c.alphaF()));
    }
    QColor bgcolor() {
	return Qt::black; // dummy
    }
};

#endif // COLOREDLABEL_H
