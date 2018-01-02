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

/****************************************************************************
   Program:     $Id: messages.cc,v 1.48 2017/12/06 00:18:04 kkeys Exp $
   Author:      Ken Keys, CAIDA
   Date:        $Date: 2017/12/06 00:18:04 $
   Description: Spoofer control channel message routines
****************************************************************************/
#include "spoof.h"

/**
 * Like inet_ntop() for an address stored in a std::string (as in a spoofer
 * protobuf).
 *
 * If the address size is incorrect for the family, the address will be dumped
 * in hex, making this function safe to use even when the source of the
 * message is untrusted.
 **/
const char *pb_ntop(family_t family, const std::string &addr, char *buf, size_t buflen)
{
    if (addr.size() == addrlen(family))
	return inet_ntop(family, addr.data(), buf, safe_int<unsigned>(buflen));
    unsigned off = unsigned(snprintf(buf, buflen, "(bad addr/%ld: ", long(addr.size())));
    for (unsigned i = 0; i < addr.size(); i++) {
	if (off + 5 > buflen && i < addr.size() - 2) {
	    off += unsigned(snprintf(buf+off, buflen-off, "..."));
	    break;
	}
	off += unsigned(snprintf(buf+off, buflen-off, "%02x", addr.data()[i]));
    }
    snprintf(buf+off, buflen-off, ")");
    return buf;
}

/**
 * Convenience variant of pb_ntop() that writes to a static buffer.
 **/
const char *pb_ntop(family_t family, const std::string &addr)
{
    static char buf[INET6_ADDRSTRLEN+1];
    return pb_ntop(family, addr, buf, sizeof(buf));
}

// Not necessarily the absolute maximum, but a typical maximum.
static inline int addrStrWidth(family_t family) {
    switch (family) {
	case AF_INET: return 15;
	case AF_INET6: return 32;
	default: return 0;
    }
}

static void printSpoofSchedule(int indent, const SpooferSpoofSchedule &sched,
    family_t family, bool verboseFlag)
{
    printf("#%*s Spoof schedule (targets: %d)\n", indent, "", sched.item_size());
    if (verboseFlag) {
        for (int i = 0; i < sched.item_size(); i++) {
	    const SpooferSpoofSchedule::Item &item = sched.item(i);
	    time_t ts = safe_int<time_t>(item.timestamp());
	    printf("#%*s [%d] %s  ", indent+1, "", i,
		gmTimeStr(&ts)());
	    if (family == AF_INET6)
		printf("\n#%*s   ", indent+1, "");
	    printf("%-*s ", addrStrWidth(family), pb_ntop(family, item.srcip()));
	    printf("-> %-*s\n", addrStrWidth(family), pb_ntop(family, item.dstip()));
	    {
		printf("#%*s   seq: %s", indent+1, "", item.seqno().c_str());
		if (item.has_hmac() && item.hmac().size() > 0) {
		    printf("  HMAC: ");
		    binDump(item.hmac().data(), item.hmac().size(), FALSE);
		}
		printf("\n");
	    }
        }
    }
}

static void printTracefilterSchedule(int indent,
    const SpooferTracefilterSchedule &sched, family_t family)
{
    printf("#%*s Tracefilter schedule (targets: %d)\n", indent, "", sched.item_size());
    for (int i = 0; i < sched.item_size(); i++) {
	const SpooferTracefilterSchedule::Item &item = sched.item(i);
        printf("#%*s  [%d] dist: %d  ", indent, "", i, item.dist());
	if (family == AF_INET6)
	    printf("\n#%*s    ", indent, "");
	printf("%-*s ", addrStrWidth(family), pb_ntop(family, item.srcip()));
	printf("-> %-*s\n", addrStrWidth(family), pb_ntop(family, item.dstip()));
    }
}

static void printTracerouteSchedule(int indent,
    const SpooferTracerouteSchedule &sched, family_t family)
{
    printf("#%*s Traceroute schedule (targets: %d)\n", indent, "", sched.item_size());
    for (int i = 0; i < sched.item_size(); i++) {
	const SpooferTracerouteSchedule::Item &item = sched.item(i);
        printf("#%*s  [%d] %s\n", indent, "", i, pb_ntop(family, item.dstip()));
    }
}

static void printSpoofIngressSchedule(int indent,
    const SpooferSpoofIngressSchedule &sched, family_t family)
{
    printf("#%*s SpoofIngress schedule (sources: %d)\n", indent, "", sched.srcip_size());
    printf("#%*s  timeout: %u\n", indent, "", sched.timeout());
    printf("#%*s  dstip: %s\n", indent, "", pb_ntop(family, sched.dstip()));
    for (int i = 0; i < sched.srcip_size(); i++) {
	printf("#%*s  srcip[%d]: %s\n", indent, "", i, pb_ntop(family, sched.srcip(i)));
    }
}

void printServerMsg(const SpooferServerMsg &msg, IPv ipv, time_t ts)
{
    FileGuard fileguard(stdout);
    family_t family = ipvtofamily(ipv);

    if (ts)
	printf("# %s\n", gmTimeStr(&ts)());

    printf("# ServerMessage (IPv%d):\n", ipv);
    if (msg.has_txtmsg()) {
	printf("#  txtmsg: level %d: \"%s\"\n", msg.txtmsg().level(),
	    msg.txtmsg().body().c_str());
    }
    if (msg.has_hello()) {
	const SpooferServerHello &hello = msg.hello();
	printf("#  hello:\n");
	printf("#   sessionid: %d\n", hello.sessionid());
	printf("#   sessionkey: %s\n", hello.sessionkey().c_str());
	printf("#   clientip: %s\n", pb_ntop(family, hello.clientip()));
	for (int i = 0; i < hello.work_est_size(); i++) {
	    printf("#   work_est[%d]: %s, %d\n", i,
		names_TestType.fromId(msg.hello().work_est(i).type()),
		hello.work_est(i).count());
	}
    }
    for (int i = 0; i < msg.schedule_size(); i++) {
	printf("#  schedule[%d]:\n", i);
	// schedule holds a oneof, but we avoid oneof API for 2.4 compatibility
	int n_sched = 0;
	if (msg.schedule(i).has_spoof()) {
	    printSpoofSchedule(2, msg.schedule(i).spoof(), family, true);
	    n_sched++;
	}
	if (msg.schedule(i).has_tracefilter()) {
	    printTracefilterSchedule(2, msg.schedule(i).tracefilter(), family);
	    n_sched++;
	}
	if (msg.schedule(i).has_traceroute()) {
	    printTracerouteSchedule(2, msg.schedule(i).traceroute(), family);
	    n_sched++;
	}
	if (msg.schedule(i).has_spoofingress()) {
	    printSpoofIngressSchedule(2, msg.schedule(i).spoofingress(), family);
	    n_sched++;
	}
	if (n_sched != 1)
	    printf("#   WARNING: sub-schedule count %d != 1\n", n_sched);
    }
    if (msg.has_summary()) {
	printf("#  summary:\n");
	printf("#   AS: %d\n", msg.summary().clientasn());
	printf("#   privaddr: %d\n", msg.summary().privaddr());
	printf("#   routable: %d\n", msg.summary().routable());
	if (msg.summary().has_ingress_privaddr())
	    printf("#   ingress_privaddr: %d\n", msg.summary().ingress_privaddr());
	if (msg.summary().has_ingress_internal())
	    printf("#   ingress_internal: %d\n", msg.summary().ingress_internal());
    }
}

static void printSpoofReport(int indent,
    const SpooferSpoofReport &report, family_t family)
{
    printf("#%*s Spoof report (targets: %d):\n", indent, "", report.item_size());
    printf("#%*s  status: %s\n", indent, "", names_ReportStatus.fromId(report.status()));
    for (int i = 0; i < report.item_size(); i++) {
	const SpooferSpoofReport::Item &item = report.item(i);
	printf("#%*s  [%d] ", indent, "", i);
	printf("%-*s -> ", addrStrWidth(family), pb_ntop(family, item.srcip()));
	if (family == AF_INET6) {
	    printf("%s\n#%*s    ", pb_ntop(family, item.dstip()), indent, "");
	} else {
	    printf("%-*s", addrStrWidth(family), pb_ntop(family, item.dstip()));
	}
	printf("  seq: %s  status: %s\n", item.seqno().c_str(),
	    names_SpoofReport_Item_Status.fromId(item.status()));
    }
}

static void printTracefilterReport(int indent,
    const SpooferTracefilterReport &report, family_t family ATR_UNUSED)
{
    printf("#%*s Tracefilter report:\n", indent, "");
    printf("#%*s  status: %s\n", indent, "", names_ReportStatus.fromId(report.status()));
}

static void printTracerouteReport(int indent, const SpooferTracerouteReport &report, family_t family)
{
    printf("#%*s Traceroute report (targets: %d):\n", indent, "", report.item_size());
    printf("#%*s  status: %s\n", indent, "", names_ReportStatus.fromId(report.status()));
    for (int i = 0; i < report.item_size(); i++) {
	const SpooferTracerouteReport::Item &item = report.item(i);
	printf("#%*s  [%d] %s\n", indent, "", i, pb_ntop(family, item.dstip()));
	if (item.has_text()) {
	    // preprend the prefix to every line of text
	    const char *p = item.text().c_str();
	    while (*p) {
		int len = safe_int<int>(strcspn(p, "\n"));
		printf("#%*s  %.*s\n", indent+2, "", len, p);
		if (!p[len]) break; // no newline at end
		p += len + 1;
	    }
	}
    }
}

static void printSpoofIngressReport(int indent,
    const SpooferSpoofIngressReport &report, family_t family)
{
    printf("#%*s SpoofIngress report (sources: %d):\n", indent, "", report.item_size());
    printf("#%*s  status: %s\n", indent, "", names_ReportStatus.fromId(report.status()));
    if (report.port())
	printf("#%*s  port: %d\n", indent, "", report.port());
    char prefix[80];
    char tbuf[32];
    sprintf(prefix, "#%*s", indent+5, "");
    for (int i = 0; i < report.item_size(); i++) {
	const SpooferSpoofIngressReport::Item &item = report.item(i);
	time_t ts = safe_int<time_t>(item.timestamp());
	struct tm *tm = gmtime(&ts);
	strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
	printf("#%*s  [%d]", indent, "", i);
	if (item.has_timestamp())
	    printf(" %s", tbuf);
	if (item.has_rcvd_srcip())
	    printf(" %s", pb_ntop(family, item.rcvd_srcip()));
	printf("\n");
	if (item.has_count())
	    printf("#%*s    count: %d\n", indent, "", item.count());
	if (item.has_payload())
	    printf("#%*s    payload:\n", indent, "");
	binDump(item.payload().data(), item.payload().size(), true, prefix);
    }
}

void printClientMsg(const SpooferClientMsg &msg, IPv ipv, time_t ts)
{
    FileGuard fileguard(stdout);
    family_t family = ipvtofamily(ipv);

    if (ts)
	printf("# %s\n", gmTimeStr(&ts)());

    printf("# ClientMessage (IPv%d):\n", ipv);
    printf("#  ready: %s\n", msg.ready() ? "true" : "false");
    if (msg.has_hello()) {
	printf("#  hello:\n");
	printf("#   version: %d\n", msg.hello().version());
	printf("#   os: %s\n", msg.hello().os().c_str());
	printf("#   clientip: %s\n", pb_ntop(family, msg.hello().clientip()));
	printf("#   share_public: %d\n", msg.hello().share_public());
	printf("#   share_remedy: %d\n", msg.hello().share_remedy());
	printf("#   sessionkey: %s\n", msg.hello().sessionkey().c_str());
	printf("#   types: ");
	for (int i = 0; i < msg.hello().type_size(); i++) {
	    printf(" %s", names_TestType.fromId(msg.hello().type(i)));
	}
	printf("\n");
    }
    for (int i = 0; i < msg.report_size(); i++) {
	printf("#  report[%d]:\n", i);
	// report holds a oneof, but we avoid oneof API for 2.4 compatibility
	int n_report = 0;
	if (msg.report(i).has_spoof()) {
	    printSpoofReport(2, msg.report(i).spoof(), family);
	    n_report++;
	}
	if (msg.report(i).has_tracefilter()) {
	    printTracefilterReport(2, msg.report(i).tracefilter(), family);
	    n_report++;
	}
	if (msg.report(i).has_traceroute()) {
	    printTracerouteReport(2, msg.report(i).traceroute(), family);
	    n_report++;
	}
	if (msg.report(i).has_spoofingress()) {
	    printSpoofIngressReport(2, msg.report(i).spoofingress(), family);
	    n_report++;
	}
	if (n_report != 1)
	    printf("#   WARNING: sub-report count %d != 1\n", n_report);
    }
}

