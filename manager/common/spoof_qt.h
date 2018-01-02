/* 
 * Copyright 2016-2017 The Regents of the University of California
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

#ifndef SPOOFER_MANAGER_COMMON_SPOOF_QT_H
#define SPOOFER_MANAGER_COMMON_SPOOF_QT_H

#define QT_NO_CAST_FROM_ASCII
#include <QString>
#include <QStringBuilder> // efficient QString concatenation with operator%

#define QSL(str) QStringLiteral(str) // efficient ctor for QString literal

// disambiguate a QT signal that is implemented by an overloaded member
#define SIGCAST(type, func, args)  static_cast<void(type::*)args>(&type::func)

#endif // SPOOFER_MANAGER_COMMON_SPOOF_QT_H
