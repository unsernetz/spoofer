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

#ifndef _PROBER_PROBER_H_
#define _PROBER_PROBER_H_ 1

#define DUPLICATES 5	/* dups for each probe */
#define TRACEROUTE_ITEM_COST 30
#define TRACEROUTE_GAP_LIMIT 5 // give up after this many unresponsive hops
#define TRACEROUTE_MAX_WAIT 60 // give up after this many seconds

extern unsigned int traceroute_delay;

struct Tracker {
    Tracker() {}
    virtual ~Tracker() {}
    virtual void incSuccess(int inc = 1) = 0;
    virtual void incFail(int inc = 1) = 0;
    virtual void incTries(int inc = 1) = 0;
    virtual void incGoal(int inc) = 0;
};

int runTraceroute(Tracker *tracker, struct in_addr *dest, char *result, int num);
int initTraceroute();

#endif /* _PROBER_PROBER_H_ */
