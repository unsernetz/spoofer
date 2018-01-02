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

/****************************************************************************
   Author:      Ken Keys, CAIDA
   Date:        $Date: 2017/12/05 20:39:38 $
   Description: Traceroute wrapper
****************************************************************************/

#include "spoof.h"
#include "prober.h"
#include "AppInfo.h"
#include "routetracer.h"

static const char cvsid[] ATR_USED = "$Id: routetracer.cc,v 1.12 2017/12/05 20:39:38 kkeys Exp $";

// per-IPv RouteTracer configuration
bool RouteTracer::initializing[7] =
    { true, true, true, true, true, true, true };
RouteTracer::Type RouteTracer::type[7] =
    { UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN };
std::vector<const char *> RouteTracer::trace_args[7]; // program + arguments

// Split up scamper output by destination
void RouteTracer::splitScamperOutput(const std::vector<const char *> &dests)
{
    family_t family = ipvtofamily(ipv);
    text[result[0].length] = '\0';
    result[0].text = nullptr;
    result[0].length = 0;
    char *start, *next;
    char addrstr[INET6_ADDRSTRLEN+1];
    char addr[IPV6ADDRLEN];
    for (start = text; *start; start = next) {
	next = strstr(start+1, "traceroute from");
	if (!next)
	    for (next = start; *next; next++);
#define STRINGIFY(X) STRINGIFY2(X)
#define STRINGIFY2(X) #X
#define WIDTH STRINGIFY(INET6_ADDRSTRLEN)
	if (sscanf(start, "traceroute from %*" WIDTH "[0-9a-fA-F.:] "
	    "to %" WIDTH "[0-9a-fA-F.:]s\n",
	    addrstr) < 1)
		continue;
	if (inet_pton(family, addrstr, &addr) != 1)
	    continue;
	for (unsigned i = 0; i < result.size(); i++) {
	    if (memcmp(dests[i], &addr, addrlen(family)) == 0) {
		result[i].text = start;
		result[i].length = safe_int<size_t>(next - start);
		break;
	    }
	}
    }
}

bool RouteTracer::checkProg(IPv ipv, Type checktype)
{
    const char *addrstr = ipv == IPv6 ? "::1" : "127.0.0.1";
    char addr[IPV6ADDRLEN];
    family_t family = ipvtofamily(ipv);
    char pattern[32];
    sprintf(pattern, " to %s", addrstr);
    std::vector<const char *> addrs(1);
    addrs[0] = addr;
    inet_pton(family, addrstr, addr);
    type[ipv] = checktype;
    RouteTracer *rt = RouteTracer::make(ipv);
    bool works = rt->run(nullptr, addrs) == 0 && strstr(rt->text, pattern);
    delete rt;
    return works;
}

bool RouteTracer::finishInit(IPv ipv, Type foundtype)
{
    type[ipv] = foundtype;
    initializing[ipv] = false;
    if (type[ipv] == MISSING) {
        warn("Could not find a working IPv%d trace program", ipv);
        return false;
    }
    info("IPv%d trace program: %s", ipv, trace_args[ipv][0]);
#if DEBUG
    if (type[ipv] < SCAMPER)
        warn("(DEBUG) IPv%d trace program is not scamper", ipv);
#endif
    return true;
}

bool RouteTracer::initScamper(IPv ipv, const char *name, const char *alternate)
{
#ifndef SCAMPER_DISABLED
    // Use scamper if possible
    std::vector<const char *> scamper_candidate;
#ifdef SCAMPER_PATH
    if (*SCAMPER_PATH)
	scamper_candidate.push_back(SCAMPER_PATH);
#endif
    if (AppInfo::path()) {
        static char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s/%s", AppInfo::dir(), name);
        scamper_candidate.push_back(buf);
    }
    if (alternate)
	scamper_candidate.push_back(alternate);
    for (unsigned i = 0; i < scamper_candidate.size(); i++) {
	trace_args[ipv].clear();
	trace_args[ipv].push_back(scamper_candidate[i]);
	trace_args[ipv].push_back("-c");
	// MacOS: High Sierra 10.13.1 has a networking bug that freezes all
	//   networking upon receipt of a ICMP6 Address Unreachable response to
	//   a ICMP6 Echo Request, so we must not use icmp-paris.  The problem
	//   does not occur with UDP probes.
	// Other UNIX-like systems: ICMP and UDP should both work; we prefer
	//   icmp-paris because that's what we've always used, so it's better
	//   tested.
	// Windows: scamper does not recieve the responses to UDP probes,
	//   even with the firewall disabled (but the responses are visible to
	//   tcpdump).  Scamper does receive responses to ICMP probes.
#ifdef _OSX
	trace_args[ipv].push_back("trace -P udp-paris -q 1 -w 1");
#else
	trace_args[ipv].push_back("trace -P icmp-paris -q 1 -w 1");
#endif
	trace_args[ipv].push_back("-i");
        if (checkProg(ipv, SCAMPER))
            return finishInit(ipv, SCAMPER);
    }
#endif // !SCAMPER_DISABLED
    trace_args[ipv].clear();
    return false;
}

bool RouteTracer::initRun(const std::vector<const char *> &dests)
{
    if (type[ipv] <= MISSING) return false;
    text = new char[BIGBUF*dests.size()];
    maxlen = safe_int<size_t>((type[ipv] == SCAMPER) ? BIGBUF*dests.size() : BIGBUF);
    size_t childCount = (type[ipv] == SCAMPER) ? 1 : dests.size();
    result.resize(dests.size());

    for (unsigned i = 0; i < result.size(); i++) {
        result[i].length = 0;
        result[i].text = (type[ipv] == SCAMPER && i>0) ? nullptr : &text[i*BIGBUF];
    }

    for (unsigned i = 0; i < childCount; i++) {
	children.push_back(RouteTracer::Child::make(i, this, dests));
    }

    start_time = time(nullptr);
    too_long = start_time + TRACEROUTE_MAX_WAIT +
	safe_int<time_t>((childCount - 1) * traceroute_delay/1000);
    return true;
}

void RouteTracer::Child::adjustScamperGoal(Tracker *tracker)
{
    if (type[rt->ipv] == SCAMPER && latest_hop != current_goal) {
	if (tracker) tracker->incGoal(latest_hop - current_goal);
	goal += latest_hop - current_goal;
	current_goal = latest_hop;
    }
}

void RouteTracer::Child::parse(Tracker *tracker)
{
    for ( ; scanned < result->length + this->done; scanned++) {
	if (scanned < result->length && result->text[scanned] == '\n') {
	    // normal end of line
	} else if (this->done && scanned == result->length) {
	    scanned++; // end of unterminated final line
	} else
	    continue; // middle of a line

	const char *line = result->text + parsed;

	size_t len = scanned - parsed;

	if (type[rt->ipv] == SCAMPER && strncmp(line, "traceroute from", sizeof("traceroute from") - 1) == 0) {
	    // Beginning of new scamper target output
	    adjustScamperGoal(tracker); // update goal of previous target
	    latest_hop = 0;
	    current_goal = TRACEROUTE_ITEM_COST;
	} else {
	    char *t;
	    long hop = strtol(line, &t, 10);
	    if (hop >= 1 && hop <= TRACEROUTE_ITEM_COST && isspace(*t)) {
		// found a line starting with a hop number
		latest_hop = static_cast<int>(hop);
		bool gotResponse = false;
		for (len -= (unsigned)(t - line); len >= 3; t++, len--) {
		    if ((gotResponse = (strncmp(t, " ms", 3) == 0)))
			break;
		}
		if (type[rt->ipv] == SCAMPER && latest_hop > current_goal) {
		    // Oops, we adjusted goal before target was done.  Fix it.
		    adjustScamperGoal(tracker);
		}
		if (tracker) tracker->incTries();
		this->tries++;
		if (gotResponse) {
		    if (tracker) tracker->incSuccess();
		    this->gap = 0;
		} else {
		    if (tracker) tracker->incFail();
		    this->gap++;
		}
	    }
	}

	parsed = scanned + 1;
    }
    if (!this->done && type[rt->ipv] == NATIVE && this->gap >= TRACEROUTE_GAP_LIMIT) {
#if DEBUG
	printf("gap limit reached [child: %d]\n", this->id);
#endif
	this->abort = true;
    }
    if (type[rt->ipv] == SCAMPER) {
	// Assuming the scamper output for the target is not split across
	// multiple parse() calls, the target is done.  Update its goal.
	adjustScamperGoal(tracker);
    }
}
