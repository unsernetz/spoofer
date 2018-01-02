/* 
 * Copyright 2004-2009 Rob Beverly
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

/****************************************************************************
   Program:     $Id: messages.h,v 1.11 2017/10/02 22:06:09 kkeys Exp $
   Author:      Rob Beverly <rbeverly at csail.mit.edu>
                Ken Keys, CAIDA
   Date:        $Date: 2017/10/02 22:06:09 $
   Description: Define control message types
****************************************************************************/

/* Test probe format */
#pragma pack(push,2)
#define PAYLOAD_VERSION 8
#define IPV4ADDRLEN 4
#define IPV6ADDRLEN 16
#define SEQNOSIZE 14
#define HMACSIZE  16
typedef struct test {
    uint32_t ts;
    unsigned char src_addr[IPV6ADDRLEN];
    unsigned char dst_addr[IPV6ADDRLEN];
    unsigned char seqno[SEQNOSIZE];
    unsigned char hmac[HMACSIZE];
} test_t;

typedef struct probe_hdr {
    uint16_t ver; // PAYLOAD_VERSION
    uint16_t spoofed; // 0=spoofed, 1=unspoofed [sic]
} probe_hdr_t;

typedef struct probe {
    probe_hdr_t hdr;
    test_t tst;
} probe_t;
#define PROBESIZE sizeof(probe_t)
#define PAYLOADSIZE (sizeof(probe_t) - HMACSIZE)

STATIC_ASSERT(sizeof(probe_t) ==
    (sizeof(uint16_t) + sizeof(uint16_t)) +
    (sizeof(uint32_t) + IPV6ADDRLEN + IPV6ADDRLEN + SEQNOSIZE + HMACSIZE),
    probe_t_is_not_correctly_packed);

#pragma pack(pop)
