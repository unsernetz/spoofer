## 
## Copyright 2015-2017 The Regents of the University of California
## All rights reserved.
## 
## This file is part of Spoofer.
## 
## Spoofer is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## 
## Spoofer is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
## 
## You should have received a copy of the GNU General Public License
## along with Spoofer.  If not, see <http://www.gnu.org/licenses/>.
## 

MAKEFILE = manager.mak
TEMPLATE = subdirs
SUBDIRS = common scheduler cli gui

CONFIG -= debug_and_release
CONFIG += release

scheduler.depends = common
cli.depends = common
gui.depends = common

