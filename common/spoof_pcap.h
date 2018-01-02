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

#ifndef COMMON_SPOOF_PCAP_H
#define COMMON_SPOOF_PCAP_H

#include "config.h"

#if defined(PCAP_H) && defined(HAVE_PCAP_CLOSE)
 #define HAVE_PCAP 1
 #ifdef _WIN32
  #define NOGDI // prevents <wingdi.h> from polluting our namespace
 #endif
 #pragma GCC system_header // suppress compiler warnings in pcap.h
 #include PCAP_H
 #ifndef PCAP_ERROR
  #define PCAP_ERROR -1
 #endif
#endif

#endif // COMMON_SPOOF_PCAP_H
