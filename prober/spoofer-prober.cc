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
   Author:      Rob Beverly <rbeverly at csail.mit.edu>
                Ken Keys, CAIDA
   Date:        $Date: 2017/11/29 23:00:35 $
   Description: Spoofer - generate spoofed packets
****************************************************************************/

#include <ctype.h>
#include <string>
#include <sstream>
#include <vector>
#include <list>
#include "spoof_pcap.h"
#include "spoof.h"
#include "prober.h"
#include "PBStreamer.h"
#include "AppInfo.h"
#include "routetracer.h"
#ifdef HAVE_LIBSSL
 #include <openssl/x509v3.h>
 #ifdef _WIN32
  #include <wincrypt.h>
 #endif
#endif

#ifdef HAVE_GETOPT_LONG
 #include <getopt.h>
#else
 #define getopt_long spoofer_getopt_long
 struct option {
     const char *name;
     int         has_arg;
     int        *flag;
     int         val;
 };
#endif

#ifdef HAVE_UNORDERED_MAP
 #include <unordered_map>
#else
 #include <map>
#endif

#ifdef HAVE_PTHREAD
static bool multiThreaded = true;
#else
static bool multiThreaded = false;
#endif

static const char cvsid[] ATR_USED = "$Id: spoofer-prober.cc,v 1.209 2017/11/29 23:00:35 kkeys Exp $";

static int sharePublic = -1; // initially unknown
static int shareRemedy = -1; // initially unknown
static bool useDevServer = false;
static bool pretendMode = false;
static bool standaloneMode = false;
static const char *standaloneTraceSrc4 = nullptr;
static const char *standaloneTraceSrc6 = nullptr;
static std::string sessionkey("");
static OptMutex sessionkey_mutex;

static const char *server4;
static const char *server6;
static const char *report_host;
static uint32_t spoofer_protocol_version = VERSION;
#ifdef HAVE_LIBSSL
static SSL_CTX *ssl_ctx = nullptr;
static int enableTLS = 1;
static int enableTLSverify = 1;
static int default_ca = 1;
static const char *ca_file = nullptr;
#else
static const int enableTLS = 0;
#endif

static const unsigned int DEFAULT_TRACEROUTE_DELAY = 600; // ms
unsigned int traceroute_delay = DEFAULT_TRACEROUTE_DELAY;

enum SessionStatus { SS_FAIL, SS_UNTESTED, SS_SUCCESS };

static bool enabledTests[SpooferTestType_ARRAYSIZE];

#if 0
#define to_str(val) \
    (static_cast<std::ostringstream&>(std::ostringstream() << val).str())
#endif

static inline uint8_t saneTracefilterDist(uint32_t dist)
{
    return (dist >= 1 && dist <= TTL_OUT) ? static_cast<uint8_t>(dist) : 5u;
}

class SpooferThreadable {
public:
#ifdef HAVE_PTHREAD
    pthread_t thread;
    bool thread_ok;
    SpooferThreadable() : thread(), thread_ok(false) {}
#else
    SpooferThreadable() {}
#endif
    ~SpooferThreadable() {}
};

class Session; // forward declaration

struct CostEstimate {
    SpooferTestType type;
    int count;
    int cost;
    CostEstimate(SpooferTestType _type, int _count, int _cost) :
	type(_type), count(_count), cost(_cost) {}
};

class Sessions : public std::vector<Session*> {
public:
    Sessions() : std::vector<Session*>() {}
    void printProgress() const;
} sessions;

class SessionTracker : public Tracker {
    OptMutex mutex;

    SessionTracker(const SessionTracker&) NO_METHOD; // copy-ctor
    SessionTracker &operator=(const SessionTracker&) NO_METHOD; // copy-assign

public:
    int success, fail, tries, goal;

    SessionTracker() :
	mutex(), success(), fail(), tries(), goal() {}

    void incTries(int inc = 1) {
	mutex.lock();
	if (tries + inc > goal)
	    inc = goal - tries;
	tries += inc;
	sessions.printProgress();
	mutex.unlock();
    }

    void incSuccess(int inc = 1) {
	mutex.lock();
	if (success + fail + inc > tries)
	    inc = tries - success - fail;
	success += inc;
	sessions.printProgress();
	mutex.unlock();
    }

    void incFail(int inc = 1) {
	mutex.lock();
	if (success + fail + inc > tries)
	    inc = tries - success - fail;
	fail += inc;
	sessions.printProgress();
	mutex.unlock();
    }

    void incGoal(int inc) {
	mutex.lock();
	goal += inc;
	sessions.printProgress();
	mutex.unlock();
    }
};

class Session : public SpooferThreadable {
public:
    const IPv ipv;
    const family_t family;
    uint32_t sessionid;
    std::string int_clientip; // what I think my address is
    std::string ext_clientip; // what server thinks my address is
    socket_t ctrlsock;
#ifdef HAVE_LIBSSL
    SSL *ctrl_ssl;
#endif
    PBStreamer *pbs;
    SpooferClientMsg req; // The request being prepared to send to server
    SpooferServerMsg resp; // The most recent response from server
    bool rcvdHello;
    unsigned short schedulesDone;
    SessionStatus status;
    std::list<CostEstimate> costEstimates;
    SessionTracker *tracker;
    bool sessionTests[SpooferTestType_ARRAYSIZE];

    Session(IPv _ipv) :
	SpooferThreadable(), ipv(_ipv), family(ipvtofamily(_ipv)),
	sessionid(0), int_clientip(), ext_clientip(), ctrlsock(INVALID_SOCKET),
#ifdef HAVE_LIBSSL
	ctrl_ssl(),
#endif
	pbs(), req(), resp(), rcvdHello(),
	schedulesDone(0), status(SS_UNTESTED), costEstimates(), tracker()
	{ memcpy(sessionTests, enabledTests, sizeof(enabledTests)); }
    ~Session() {
	if (pbs) delete pbs;
#ifdef HAVE_LIBSSL
	if (ctrl_ssl) {
	    SSL_shutdown(ctrl_ssl);
	    SSL_free(ctrl_ssl);
	}
#endif
	if (ctrlsock != INVALID_SOCKET) closesocket(ctrlsock);
	if (tracker) delete tracker;
    }

    int calcCost(const SpooferSpoofSchedule &sched) {
	return sched.item_size() * DUPLICATES;
    }

    int calcCost(const SpooferTracefilterSchedule &sched) {
	int c = 0;
	for (int i = 0; i < sched.item_size(); i++)
	    c += saneTracefilterDist(sched.item(i).dist()) * DUPLICATES;
	return c;
    }

    int calcCost(const SpooferTracerouteSchedule &sched) {
	return sched.item_size() * TRACEROUTE_ITEM_COST;
    }

    int calcCost(const SpooferSpoofIngressSchedule &sched) {
	return sched.srcip_size() * DUPLICATES;
    }

    void printHeader(const char *label, int count, const char *itemdesc) {
	// NB: GUI depends on this output format
	printf(">> Running IPv%d test %d:  %s (%d %s%s)\n",
	    ipv, schedulesDone+1, label, count, itemdesc, count > 1 ? "s" : "");
    }
    unsigned int addrlen() const { return ::addrlen(family); }
    bool init();
    bool serverConnect();
    void generateFakeHello();
    bool handleTextMessage(const SpooferTextMessage &txtmsg);
    bool validateServerMsg();
    void makeCostEstimate(SpooferTestType type, int count);
    void runTracerouteTests(const SpooferTracerouteSchedule &sched);
    void runSpoofIngressTests(const SpooferSpoofIngressSchedule &sched);
    void *run();
#ifdef HAVE_PTHREAD
    static void *run(void *arg) {
	Session *session = static_cast<Session*>(arg);
	// Only one session at a time should try to get a sessionkey.
	debug(HIGH, "IPv%d starting; locking sessionkey...\n", session->ipv);
	sessionkey_mutex.lock();
	debug(HIGH, "IPv%d starting; locked sessionkey (\"%s\")\n",
	    session->ipv, sessionkey.c_str());
	void *result = session->run();
	if (sessionkey.empty()) {
	    // This session failed to get a sessionkey; let another one try.
	    debug(HIGH, "IPv%d done; unlocking sessionkey (empty: \"%s\")\n",
		session->ipv, sessionkey.c_str());
	    sessionkey_mutex.unlock();
	} else {
	    // This session got a sessionkey and already unlocked the mutex.
	}
	return result;
    }
#endif
    bool pretend(int pcost, int speed = 1) const;

    class Tester; // forward declaration

    class TestItem {
    public:
	const Session &sess;
	Tester * const tester;
	struct sockaddr_storage src_ss, dst_ss;
	struct sockaddr * const src;
	struct sockaddr * const dst;
	socket_t udpsock;
	socket_t spoofsock;
	TestItem(Session &_sess, Tester *_tester = nullptr,
	    const void *saddr = nullptr, const void *daddr = nullptr,
	    unsigned short sport = 0, unsigned short dport = 0)
	:
	    sess(_sess), tester(_tester), src_ss(), dst_ss(),
	    src(saddr ? (struct sockaddr *)&src_ss : nullptr),
	    dst(daddr ? (struct sockaddr *)&dst_ss : nullptr),
	    udpsock(INVALID_SOCKET), spoofsock(INVALID_SOCKET)
	{
	    if (src) {
		memset(src, 0, sizeof(src_ss));
		src->sa_family = sess.family;
		memcpy(sa_ipaddr(src), saddr, sess.addrlen());
		sa_port(src) = htons(sport);
	    }
	    if (dst) {
		memset(dst, 0, sizeof(dst_ss));
		dst->sa_family = sess.family;
		memcpy(sa_ipaddr(dst), daddr, sess.addrlen());
		sa_port(dst) = htons(dport);
	    }
	}
	virtual ~TestItem() {
	    if (udpsock != INVALID_SOCKET) ::closesocket(udpsock);
	    if (spoofsock != INVALID_SOCKET) ::closesocket(spoofsock);
	}
	virtual void runTest() {}
	bool initSockets(bool spoof) {
	    // We don't bind src because we want to use the default (also, the
	    // schedule's value for src is wrong if we're behind a NAT).
	    return ::initSockets(spoof, sess.ipv, spoofsock, udpsock,
		nullptr, dst);
	}
	bool closeSocket(socket_t &sock) { return ::closeSocket(sock, sess.ipv); }
    private:
	TestItem(const TestItem &) NO_METHOD; // no copy-ctor
	TestItem operator=(const TestItem &) NO_METHOD; // no copy-assign
    };

    struct SpoofTestItem : public TestItem {
	const SpooferSpoofSchedule::Item *schedItem;
	SpooferSpoofReport::Item *reportItem;
	SpoofTestItem(Tester *_tester,
	    const SpooferSpoofSchedule::Item *_schedItem,
	    SpooferSpoofReport::Item *_reportItem,
	    unsigned short sport, unsigned short dport) /*ATR_NONNULL*/
	:
	    TestItem(_tester->sess, _tester, _schedItem->srcip().data(), _schedItem->dstip().data(), sport, dport),
	    schedItem(_schedItem), reportItem(_reportItem)
	    { }
	void runTest();
    private:
	SpoofTestItem(const SpoofTestItem &) NO_METHOD; // no copy-ctor
	SpoofTestItem operator=(const SpoofTestItem &) NO_METHOD; // no copy-assign
    };

    struct TracefilterTestItem : public TestItem {
	const SpooferTracefilterSchedule::Item *schedItem;
	uint8_t pathdist;
	TracefilterTestItem(Tester *_tester,
	    const SpooferTracefilterSchedule::Item *_schedItem,
	    unsigned short sport, unsigned short dport, uint8_t _pathdist) /*ATR_NONNULL*/
	:
	    TestItem(_tester->sess, _tester, _schedItem->srcip().data(), _schedItem->dstip().data(), sport, dport),
	    schedItem(_schedItem), pathdist(_pathdist)
	    { }
	void runTest();
    private:
	TracefilterTestItem(const TracefilterTestItem &) NO_METHOD; // no copy-ctor
	TracefilterTestItem operator=(const TracefilterTestItem &) NO_METHOD; // no copy-assign
    };

    class TestThread : public SpooferThreadable {
    public:
	std::vector<Session::TestItem*> testItems;
	TestThread() : SpooferThreadable(), testItems() {}
	~TestThread() {
	    for (unsigned i = 0; i < testItems.size(); i++)
		delete testItems[i];
	}
	void *run();
	static void *run(void *arg) { return static_cast<TestThread*>(arg)->run(); }
    };

    class Tester {
    public:
	Session &sess;
	bool errors;
    protected:
#ifdef HAVE_UNORDERED_MAP
typedef std::unordered_map<std::string, TestThread*> ThreadMap;
#else
typedef std::map<std::string, TestThread*> ThreadMap;
#endif
	ThreadMap threadMap;
	TestThread primaryThread;
	std::vector<TestThread*> secondaryThreads;

    private:
	Tester(const Tester &) NO_METHOD;
	Tester &operator=(const Tester &) NO_METHOD;
    public:
	Tester(Session &_sess) :
	    sess(_sess), errors(false), threadMap(), primaryThread(), secondaryThreads()
	    {}
	virtual ~Tester() {}
	void runTests();
	virtual void set_report_status() = 0;
	TestThread *getThread(std::string dst);
    };

    class SpoofTester : public Tester {
	const SpooferSpoofSchedule &sched;
	SpooferSpoofReport *report;

	SpoofTester(const SpoofTester &) NO_METHOD;
	SpoofTester &operator=(const SpoofTester &) NO_METHOD;
    public:
	SpoofTester(Session &_sess, const SpooferSpoofSchedule &_sched, SpooferSpoofReport *_report);
	void set_report_status() { report->set_status(errors ? ERROR : DONE); }
    };

    class TracefilterTester : public Tester {
	const SpooferTracefilterSchedule &sched;
	SpooferTracefilterReport *report;

	TracefilterTester(const TracefilterTester &) NO_METHOD;
	TracefilterTester &operator=(const TracefilterTester &) NO_METHOD;
    public:
	TracefilterTester(Session &_sess, const SpooferTracefilterSchedule &_sched,
	    SpooferTracefilterReport *_report);
	void set_report_status() { report->set_status(errors ? ERROR : DONE); }
    };

private:
    Session(const Session &) NO_METHOD; // no copy-ctor
    Session operator=(const Session &) NO_METHOD; // no copy-assign
};

// NB: GUI depends on this output format
void Sessions::printProgress() const {
    char buf[256];
    char *p = buf;
    p += sprintf(p, "%s", PROGRESS_PREFIX);
    for (unsigned i = 0; i < this->size(); i++) {
	SessionTracker *tracker = (*this)[i]->tracker;
	if (!tracker || tracker->goal <= 0) continue;
	p += sprintf(p, "  IPv%d: %d+%d/%d/%d", (*this)[i]->ipv,
	    tracker->success, tracker->fail, tracker->tries, tracker->goal);
    }
    if (is_interactive()) {
	// Add some spaces to erase an old line in case it was longer, but try
	// not to go all the way to edge of screen, because some terminals
	// will wrap there.
	int len = safe_int<int>(p - buf);
	int pad = len >= 77 ? 2 : 79 - len; // not quite to edge, we hope
	p += sprintf(p, "%*s", pad, "");
	overwritable_puts(buf);
    } else {
	puts(buf);
    }
}

bool Session::handleTextMessage(const SpooferTextMessage &txtmsg)
{
    const char *type;
    bool result = true;
    switch (txtmsg.level()) {
	case SpooferTextMessage::ERROR:
	    type = "error";
	    result = false;
	    break;
	case SpooferTextMessage::WARNING:
	    type = "warning";
	    break;
	case SpooferTextMessage::NOTICE:
	default:
	    type = "notice";
	    break;
    }
    printf("*** IPv%d server %s: %s\n", ipv, type, txtmsg.body().c_str());
    return result;
}

bool Session::pretend(int pcost, int speed) const {
    if (!pretendMode) return false;
    for (int i = 0; i < pcost; i++) {
	msleep(400 / safe_int<unsigned>(speed));
	tracker->incTries();
	tracker->incSuccess();
    }   
    return true;
}       

// Each destination gets its own thread.  Thus,
// - Per-destination data does not need to be threadsafe.
// - A single dest (or path to it) does not receive multiple probes too
//   quickly.
Session::TestThread *Session::Tester::getThread(std::string dst)
{
    if (multiThreaded) {
	TestThread *tt;
	if (threadMap.empty()) {
	    tt = threadMap[dst.data()] = &primaryThread;
	} else {
	    if (!(tt = threadMap[dst.data()])) {
		tt = threadMap[dst.data()] = new TestThread();
		secondaryThreads.push_back(tt);
	    }
	}
	return tt;
    }
    return &primaryThread;
}

Session::SpoofTester::SpoofTester(Session &_sess, const SpooferSpoofSchedule &_sched,
    SpooferSpoofReport *_report)
:
    Tester(_sess), sched(_sched), report(_report)
{
    sess.printHeader("spoof", sched.item_size(), "source/destination pair");

    for (int i = 0; i < sched.item_size(); i++) {
	const SpooferSpoofSchedule::Item &schedItem = sched.item(i);
	SpooferSpoofReport::Item *reportItem = report->add_item();
	reportItem->set_srcip(schedItem.srcip());
	reportItem->set_dstip(schedItem.dstip());
	reportItem->set_seqno(schedItem.seqno());
	reportItem->set_status(SpooferSpoofReport::Item::SENDFAIL); // until proven otherwise

	if (schedItem.dstip().size() != sess.addrlen()) {
	    sess.tracker->incGoal(-DUPLICATES);
	    continue; // family disagrees with dst address (shouldn't happen)
	}

	TestThread *tt = getThread(schedItem.dstip());
	tt->testItems.push_back(new Session::SpoofTestItem(this,
	    &schedItem, reportItem, SRC_PORT, SERV_PORT));
    }
}

void Session::Tester::runTests()
{
#ifdef HAVE_PTHREAD
    if (multiThreaded) {
	for (unsigned i = 0; i < secondaryThreads.size(); i++) {
	    TestThread *tt = secondaryThreads[i];
	    int rc = pthread_create(&tt->thread, nullptr, &TestThread::run, tt);
	    if (!(tt->thread_ok = (rc == 0)))
		severe("IPv%d pthread_create: %s", sess.ipv, strerror(rc));
	}
    }
#endif
    primaryThread.run(); // run in main thread

#ifdef HAVE_PTHREAD
    if (multiThreaded) {
	for (unsigned i = 0; i < secondaryThreads.size(); i++) {
	    TestThread *tt = secondaryThreads[i];
	    if (tt->thread_ok) {
		int rc = pthread_join(tt->thread, nullptr);
		if (rc != 0)
		    severe("IPv%d pthread_join: %s", sess.ipv, strerror(rc));
	    }
	    delete tt;
	}
    }
#endif

    set_report_status();
}

void *Session::TestThread::run()
{
    for (unsigned i = 0; i < testItems.size(); i++) {
	testItems[i]->runTest();
    }
    return nullptr;
}

void Session::SpoofTestItem::runTest()
{
    struct probe_info *pinfo = nullptr;
    size_t pktlen = 0;
#pragma pack(push,1)
    struct {
	probe_t probe;
	// Possible padding was accidently introduced here in v106
	uint32_t sessionid;
    } payload;
#pragma pack(pop)
    STATIC_ASSERT(sizeof(payload) == sizeof(payload.probe) + sizeof(payload.sessionid),
        payload_is_not_correctly_packed);

    int n_sent = 0, n_send_errors = 0;
    bool spoof =
	(memcmp(sess.ext_clientip.data(), sa_ipaddr(src), sess.addrlen()) != 0);
    bool skipSniffing = true;

    if (sess.pretend(DUPLICATES)) return;

    if (!initSockets(spoof))
	goto enditem;

    if (verbosity >= HIGH) {
	char buf[256];
	char *p = buf;
	p += sprintf(p, ">> Send %d %s packets", DUPLICATES,
	    spoof ? "spoofed" : "non-spoofed");
	if (spoof)
	    p += sprintf(p, " from %s", ntopBuf(src)());
	p += sprintf(p, " to target %s...\n", ntopBuf(dst)());
	fputs(buf, stdout);
    }

    pinfo = new_probe_info(IPPROTO_UDP, spoof, udpsock, src, dst);
    if (!pinfo) {
	sess.tracker->incGoal(-DUPLICATES);
	goto enditem;
    }

    /* send probe packets */
    craftProbe(&payload.probe, spoof, schedItem);

    if (spoof) {
	union {
	    unsigned char pkt[sizeof(ip6_hdr) + sizeof(udphdr) + sizeof(payload)];
	    uint32_t aligned_pkt;
	};
	pktlen = craftPacket(&aligned_pkt, &payload.probe, PROBESIZE, src, dst, TTL_OUT, 0);
	for (int j = 0; j < DUPLICATES; j++) {
	    sess.tracker->incTries();
	    n_sent++;
	    if (socketSendSpoof(spoofsock, udpsock, pkt, pktlen, pinfo) < 0) {
		n_send_errors++;
		sess.tracker->incFail();
	    } else {
		sess.tracker->incSuccess();
		spoofSleep();
	    }
	}

    } else { // non-spoof
	char ebuf[4096] = "";
	unsigned int probesize = sizeof(payload.probe);
	if (sess.ipv == IPv4) {
	    htonpl(&payload.sessionid, sess.sessionid);
	    probesize = sizeof(payload);
	}
	for (int j = 0; j < DUPLICATES; j++) {
	    sess.tracker->incTries();
	    n_sent++;
	    if (socketSend(udpsock, &payload, probesize, pinfo) < 0) {
		// In rare cases (ICMP response arrives between SO_ERROR and
		// send() in socketSend() on FreeBSD) we can get an error that
		// indicates a network error, not an error in send().
		n_send_errors++;
		SockLastErrmsg msg;
		if (verbosity >= LOW) {
		    info("send to IPv%d target %s: %s",
			sess.ipv, ntopBuf(dst)(), msg());
		} else if (strcmp(msg(), ebuf) != 0) { // not a repeat
		    if (*ebuf)
			strncat(ebuf, "; ", sizeof(ebuf) - strlen(ebuf) - 1);
		    strncat(ebuf, msg(), sizeof(ebuf) - strlen(ebuf) - 1);
		}
		sess.tracker->incFail();
	    } else {
		sess.tracker->incSuccess();
		spoofSleep();
	    }
	}

	if (n_send_errors) {
	    info("send to IPv%d target %s: %d of %d sends failed%s%s",
		sess.ipv, ntopBuf(dst)(), n_send_errors, n_sent,
		(*ebuf ? ": " : "."), ebuf);
	}
    }
    skipSniffing = (n_send_errors >= n_sent);

enditem:
    closeSocket(spoofsock);
    closeSocket(udpsock);
    if (pinfo) {
	ProbeStatus pstatus = free_probe_info(pinfo, skipSniffing);
	switch (pstatus) {
	    case UNTRIED:
	    case SENDFAIL:
		reportItem->set_status(SpooferSpoofReport::Item::SENDFAIL);
		break;
	    case UNCONFIRMED:
		reportItem->set_status(SpooferSpoofReport::Item::UNCONFIRMED);
		break;
	    case REWRITTEN:
		reportItem->set_status(SpooferSpoofReport::Item::REWRITTEN);
		break;
	    case CONFIRMED:
		reportItem->set_status(SpooferSpoofReport::Item::CONFIRMED);
		break;
	    default:
		warn("internal error: bad pinfo->status %d", pstatus);
		reportItem->set_status(SpooferSpoofReport::Item::SENDFAIL);
		break;
	}
    }
}

// IPv4 only
Session::TracefilterTester::TracefilterTester(Session &_sess,
    const SpooferTracefilterSchedule &_sched, SpooferTracefilterReport *_report)
:
    Tester(_sess), sched(_sched), report(_report)
{
    // Encode low 2B of session ID into UDP src port and high 2B into IPID
    uint16_t sid_lo = static_cast<uint16_t>(sess.sessionid & 0x0000ffff);

    sess.printHeader("tracefilter", sched.item_size(), "source/destination pair");

    if (sched.item_size() > 100) {
	warn("Bogus IPv%d test list.", sess.ipv);
	errors = true;
	return;
    }

    for (int i = 0; i < sched.item_size(); i++) {
	const SpooferTracefilterSchedule::Item &schedItem = sched.item(i);
	TestThread *tt = getThread(schedItem.dstip());
	tt->testItems.push_back(new Session::TracefilterTestItem(this,
	    &schedItem, sid_lo, SERV_PORT, saneTracefilterDist(schedItem.dist())));
    }
}

void Session::TracefilterTestItem::runTest()
{
    struct Hop {
	union {
	    unsigned char pkt[sizeof(ip6_hdr) + sizeof(udphdr) + 30];
	    uint32_t aligned_pkt;
	};
	size_t pktlen;
	int sent;
	int failed;
    };
    struct probe_info *pinfo = nullptr;
    unsigned char *payload = new unsigned char[pathdist+1]();
    Hop *hops = new Hop[pathdist];

    if (sess.pretend(DUPLICATES * pathdist)) return;

    // Encode low 2B of session ID into UDP src port and high 2B into IPID
    uint16_t sid_hi = static_cast<uint16_t>((sess.sessionid >> 16) & 0x0000ffff);
    if (!initSockets(true))
	goto end;

    pinfo = new_probe_info(IPPROTO_UDP, true, udpsock, src, dst);
    if (!pinfo) goto end;

    for (uint8_t ttl = 1; ttl <= pathdist; ttl++) {
	// Encode initial TTL as UDP payload size
	int i = ttl - 1;
	hops[i].pktlen = craftPacket(&hops[i].aligned_pkt, payload, ttl, src, dst, ttl, sid_hi);
	hops[i].sent = 0;
	hops[i].failed = 0;
    }

    // Send 1st duplicate to every hop; pause; send 2nd dup to every hop; etc.
    for (int j = 0; j < DUPLICATES; j++) {
	int sent = 0;
	for (uint8_t i = 0; i < pathdist; i++) {
	    sess.tracker->incTries();
	    if (hops[i].failed) {
		// do nothing;
	    } else if (socketSendSpoof(spoofsock, udpsock, hops[i].pkt, hops[i].pktlen, pinfo) < 0) {
		hops[i].failed++;
		sess.tracker->incFail();
		sess.tracker->incGoal(j+1 - DUPLICATES);
	    } else {
		hops[i].sent++;
		sent++;
		sess.tracker->incSuccess();
	    }
	}
	if (!sent) break;
	spoofSleep();
    }
end:
    closeSocket(spoofsock);
    closeSocket(udpsock);
    for (uint8_t i = 0; i < pathdist; i++) {
	// TODO: Report item errors in a SpooferTracefilterReport::Item, not
	// the SpooferTracefilterReport.
	if (!hops[i].sent)
	    tester->errors = true;
    }
    if (hops) delete[] hops;
    if (payload) delete[] payload;
    if (pinfo) free_probe_info(pinfo);
}

void Session::runTracerouteTests(const SpooferTracerouteSchedule &sched)
{
    std::vector<const char *> dests;
    SpooferTracerouteReport *report = req.add_report()->mutable_traceroute();
    report->set_status(ERROR); // until proven otherwise

    printHeader("traceroute", sched.item_size(), "destination");
    if (pretend(calcCost(sched), multiThreaded ? sched.item_size() : 1)) return;
    RouteTracer *rt = RouteTracer::make(ipv);

    // create destination list
    dests.reserve(safe_int<size_t>(sched.item_size()));
    for (unsigned short i = 0; i < sched.item_size(); i++) {
	dests.push_back(sched.item(i).dstip().data());
    }

    // run traceroute
    if (rt->run(tracker, dests) == 0) {
	for (unsigned short i = 0; i < sched.item_size() && i < rt->resultCount(); i++) {
	    // copy the dstip and trace output into the report
	    SpooferTracerouteReport::Item *reportItem = report->add_item();
	    reportItem->set_dstip(sched.item(i).dstip());
	    reportItem->set_text(rt->getText(i), rt->getLength(i));
	}
	report->set_status(DONE);
    }
    delete rt;
}

void Session::runSpoofIngressTests(const SpooferSpoofIngressSchedule &sched)
{
struct IngressResult {
    uint32_t timestamp;
    std::string rcvd_srcip; // from IP header
    std::string payload;
    uint32_t count;
    IngressResult(const char *srcip, size_t srcip_len, const char *buf, size_t len) :
	timestamp(static_cast<uint32_t>(time(nullptr))), rcvd_srcip(srcip, srcip_len),
	payload(buf, len), count(1) {}
};
#ifdef HAVE_UNORDERED_MAP
typedef std::unordered_map<std::string, std::vector<IngressResult>> ResultMap;
#else
typedef std::map<std::string, std::vector<IngressResult>> ResultMap;
#endif

    ResultMap resultmap;
    int pending = 0;
    time_t endtime = 0;
    sockaddr_storage dst_ss;
    struct sockaddr *dst_sa = (struct sockaddr *)&dst_ss;
    sockaddr_storage src_ss;
    struct sockaddr *src_sa = (struct sockaddr *)&src_ss;
    socklen_t socklen = 0;
    uint16_t dport = 0;

    printHeader("ingress", sched.srcip_size(), "source");

    // Prepare a SpoofIngressReport (note: req may already contain reports
    // from previous schedules in same batch)
    SpooferSpoofIngressReport *report = req.add_report()->mutable_spoofingress();

    // create socket
    socket_t sock = newSocket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) goto error;

    // Listen for probes, and let the system choose a port number
    memset(dst_sa, 0, sizeof(dst_ss));
    dst_sa->sa_family = family;
    memcpy(sa_ipaddr(dst_sa), sched.dstip().data(), addrlen());
    sa_port(dst_sa) = 0;
    if (bind(sock, dst_sa, sa_len(dst_sa)) != 0) {
	severe("binding to IPv%d %s port %hu: %s", ipv, ntopBuf(dst_sa)(), dport, SockLastErrmsg()());
	goto error;
    }
    socklen = sizeof(dst_ss);
    // Find out what port the system chose
    if (getsockname(sock, dst_sa, &socklen) < 0) {
        severe("couldn't get local IPv%d address: %s", ipv, SockLastErrmsg()());
	goto error;
    } 
    dport = ntohs(sa_port(dst_sa));
    info("Listening for incoming probes on IPv%d %s port %hu", ipv, ntopBuf(dst_sa)(), dport);

    // Tell server we're ready to receive probes on chosen port.
    req.set_ready(false); // NOT ready for another set of schedules
    report->set_status(READY); // ready to receive spoofingress probes
    report->set_port(dport);
    printClientMsg(req, ipv, time(nullptr));
    if (!standaloneMode) {
	PBStreamer::Result pbsresult;
	if ((pbsresult = pbs->writeMessage(&req)) != PBStreamer::OK) {
	    severe("sending IPv%d ClientMsg: %s", ipv, pbs->last_errmsg());
	    goto error;
	}
    }

    // Prepare a new ClientRequest with SpoofIngressReport
    req.Clear();
    req.set_ready(true);
    report = req.add_report()->mutable_spoofingress();

    // Receive probes
    for (int i = 0; i < sched.srcip_size(); i++) {
	resultmap[sched.srcip(i)];
    }
    endtime = time(nullptr) + safe_int<time_t>(sched.timeout()) + 1;
    pending = sched.srcip_size() * DUPLICATES;

    while (pending > 0) {
	int nfds;
	fd_set readable;
	struct timeval timeout;
	time_t now = time(nullptr);
	if (now > endtime) break; // timeout
	timeout.tv_sec = endtime - now;
	timeout.tv_usec = 0;
	nfds = static_cast<int>(sock) + 1;
	FD_ZERO(&readable);
	FD_SET(sock, &readable);
	debug(HIGH, "IPv%d select for %ld.%06ld s...\n", ipv,
	    (long)timeout.tv_sec, (long)timeout.tv_usec);
	nfds = select(nfds, &readable, nullptr, nullptr, &timeout);
	if (nfds < 0) { // error
	    severe("IPv%d select: %s", ipv, SockLastErrmsg()());
	    break;
	} else if (nfds == 0) { // timeout
	    break;
	}
	char buf[9000];
	ssize_t rcvd;
	socklen = sizeof(src_ss);
	rcvd = recvfrom(sock, buf, sizeof(buf), 0, src_sa, &socklen);
	if (rcvd < 0) {
	    severe("IPv%d recvfrom: %s", ipv, SockLastErrmsg()());
	    break;
	}
	debug(HIGH, "received v%d ingress pkt: %zd bytes from %s port %u\n",
	    ipv, rcvd, ntopBuf(src_sa)(), ntohs(sa_port(src_sa)));
	if (verbosity >= HIGH) {
	    printf("payload: ");
	    binDump(buf, static_cast<size_t>(rcvd), FALSE);
	    printf("\n");
	}

	if (rcvd != sizeof(probe_t)) {
	    debug(HIGH, "rejecting v%d ingress pkt with size %zd != %zd\n",
		ipv, rcvd, sizeof(probe_t));
	    continue;
	}

	const uint8_t *probe_src =
	    ua_field(probe_t, buf, tst.src_addr) + IPV6ADDRLEN - addrlen();
	std::string probe_srcstr((const char*)probe_src, addrlen());

	ResultMap::iterator it = resultmap.find(probe_srcstr);
	if (it == resultmap.end()) continue; // pkt was from unexpected source

	uint16_t probe_version = nptohs(ua_field(probe_t, buf, hdr.ver));
	if (probe_version != PAYLOAD_VERSION) {
	    debug(HIGH, "rejecting v%d ingress pkt with hdr.ver %hu\n",
		ipv, probe_version);
	    continue;
	}

	const uint8_t *probe_dst =
	    ua_field(probe_t, buf, tst.dst_addr) + IPV6ADDRLEN - addrlen();
	if (memcmp(probe_dst, ext_clientip.data(), addrlen()) != 0) {
	    char pbuf[INET6_ADDRSTRLEN+1];
	    debug(HIGH, "rejecting v%d ingress pkt with tst.dst_addr %s\n",
		ipv, inet_ntop(family, probe_dst, pbuf, sizeof(pbuf)));
	    continue;
	}

	if (it->second.size() < DUPLICATES) {
	    pending--;
	    tracker->incTries();
	    tracker->incSuccess();
	}
	it->second.push_back(IngressResult(sa_ipaddr(src_sa), addrlen(), buf,
	    static_cast<size_t>(rcvd)));
    }
    if (pending > 0) {
	tracker->incTries(pending);
	tracker->incFail(pending);
    }

    closesocket(sock);
    report->set_status(DONE);

    for (int i = 0; i < sched.srcip_size(); i++) {
	ResultMap::iterator it = resultmap.find(sched.srcip(i));
	if (it == resultmap.end()) continue; // impossible
	// collapse duplicates
	// (note: if we ever implement ingress probing from multiple nodes
	// that use the same orig_srcip, we'll need a more unique grouping key
	// here so that duplicate collapsing still works)
	for (size_t j = it->second.size(); j > 1; ) {
	    j--; // after condition because j is unsigned
	    std::vector<IngressResult> &v = it->second;
	    if (v[j].payload.compare(v[j-1].payload) == 0 &&
		v[j].rcvd_srcip.compare(v[j-1].rcvd_srcip) == 0)
	    {
		v[j-1].count += v[j].count;
		v[j].count = 0;
	    }
	}
	// fill in report
	for (size_t j = 0; j < it->second.size(); j++) {
	    if (it->second[j].count == 0) continue; // skip collapsed item
	    SpooferSpoofIngressReport::Item *reportItem = report->add_item();
	    // possible TODO: omit rcvd_srcip if same as sched.srcip(i)
	    reportItem->set_rcvd_srcip(it->second[j].rcvd_srcip);
	    reportItem->set_timestamp(it->second[j].timestamp);
	    // possible TODO: omit payload if same as previous item's payload
	    reportItem->set_payload(it->second[j].payload);
	    // possible TODO: omit count if == 1
	    reportItem->set_count(it->second[j].count);
	}
    }

    return;

error:
    req.set_ready(true);
    report->set_status(ERROR);

    if (sock != INVALID_SOCKET)
	closesocket(sock);
}

static bool validateAddr(const std::string &addr, IPv ipv, const char *where, int index = -1)
{
    if (addr.size() != addrlen(ipvtofamily(ipv))) {
	if (index < 0)
	    severe("Protocol error: invalid IPv%d address size %zd in %s",
		ipv, addr.size(), where);
	else
	    severe("Protocol error: invalid IPv%d address size %zd in %s[%d]",
		ipv, addr.size(), where, index);
	return false;
    }
    return true;
}

// like strncpy(), but also converts to lower case
static char *strlower(char *dst, const char *src, size_t n)
{
    if (n < 1) return dst;
    size_t i;
    for (i = 0; i < n-1 && src[i]; i++)
	dst[i] = static_cast<char>(::tolower(src[i]));
    dst[i] = '\0';
    return dst;
}

static void printResult(const char *addrtype, const char *direction,
    SpooferResultSummary::Result result)
{
    char buf[16];
    printf(">>    Spoofed %s addresses, %s: %s\n", addrtype, direction,
	strlower(buf, names_ResultSummary_Result.fromId(result), sizeof(buf)));
}

void *Session::run()
{
    status = SS_FAIL; // until proven otherwise
    PBStreamer::Result pbsresult;
    tracker = new SessionTracker();

    // generate ClientHello message
    req.Clear();
    req.set_ready(true);

    req.mutable_hello()->set_version(spoofer_protocol_version);
    req.mutable_hello()->set_os(OS);
    req.mutable_hello()->set_share_public(sharePublic == 1);
    req.mutable_hello()->set_share_remedy(shareRemedy == 1);
    req.mutable_hello()->set_sessionkey(sessionkey);

    for (auto entry : names_TestType) {
	if (!sessionTests[entry.id])
	    continue; // skip disabled type
	req.mutable_hello()->add_type(entry.id);
    }

    if (!serverConnect()) return nullptr;
    req.Clear();

    while (true) {
	// get server response
	if (standaloneMode) {
	    resp.Clear();
	    msleep(1000); // simulated RTT
	    if (!rcvdHello) {
		generateFakeHello();
	    } else {
		// generate fake ResultSummary
		resp.mutable_summary()->set_clientasn(ipv==IPv4 ? 444 : 66666);
		resp.mutable_summary()->set_privaddr(ipv==IPv4 ?
		    SpooferResultSummary::BLOCKED : SpooferResultSummary::REWRITTEN);
		resp.mutable_summary()->set_routable(ipv==IPv4 ?
		    SpooferResultSummary::RECEIVED : SpooferResultSummary::UNKNOWN);
		resp.mutable_summary()->set_ingress_privaddr(ipv==IPv4 ?
		    SpooferResultSummary::BLOCKED : SpooferResultSummary::REWRITTEN);
		resp.mutable_summary()->set_ingress_internal(ipv==IPv4 ?
		    SpooferResultSummary::RECEIVED : SpooferResultSummary::UNKNOWN);
	    }
	} else {
	    if ((pbsresult = pbs->readFullMessage(&resp)) != PBStreamer::OK) {
		const char *msg = pbs->last_errmsg();
		if (strncmp(msg, "bad magic: \"", 12) == 0) {
		    severe("Connection to IPv%d Spoofer server seems to have "
			"been intercepted by an HTTP proxy or other server.  "
			"Response: %s", ipv, msg+11);
		} else {
		    severe("receiving IPv%d ServerMsg: %s", ipv, msg);
		}
		return nullptr;
	    }
	}
	printServerMsg(resp, ipv, time(nullptr));
	if (!validateServerMsg())
	    return nullptr;
	if (resp.has_summary()) // end of session
	    break;

	// If server omitted work_est from ServerHello, and this looks like
	// the start of a typical IPv4 session, make our own estimate.
	// (A typical IPv6 session puts all the work in the first message, so
	// we don't need an estimate.)
	if (tracker->goal == 0 && ipv == IPv4 && resp.schedule_size() == 2 &&
	    resp.schedule(0).has_spoof() && resp.schedule(1).has_spoof())
	{
	    debug(LOW, "Missing work estimate from IPv%d server.\n", ipv);
	    makeCostEstimate(SPOOF, resp.schedule(0).spoof().item_size());
	    makeCostEstimate(SPOOF, resp.schedule(1).spoof().item_size());
	    makeCostEstimate(TRACEFILTER, 1);
	    makeCostEstimate(SPOOF, resp.schedule(0).spoof().item_size());
	    makeCostEstimate(TRACEROUTE, resp.schedule(0).spoof().item_size());
	}

	// prepare the scheduled tests
	for (int i = 0; i < resp.schedule_size(); i++) {
	    const SpooferServerSchedule &sched = resp.schedule(i);
	    int actual = 0, est = 0;
	    SpooferTestType type;
	    // note: we avoid the oneof API for 2.4 compatibility
	    if (sched.has_spoof()) {
		actual = calcCost(sched.spoof());
		type = SPOOF;
	    } else if (sched.has_tracefilter()) {
		actual = calcCost(sched.tracefilter());
		type = TRACEFILTER;
	    } else if (sched.has_traceroute()) {
		actual = calcCost(sched.traceroute());
		type = TRACEROUTE;
	    } else if (sched.has_spoofingress()) {
		actual = calcCost(sched.spoofingress());
		type = SPOOFINGRESS;
	    } else {
		severe("impossible: Unknown or missing IPv%d schedule", ipv);
		continue;
	    }
	    if (!sessionTests[type]) // ignore disabled test
		continue;
	    for (std::list<CostEstimate>::iterator it = costEstimates.begin();
		it != costEstimates.end(); ++it)
	    {
		if (it->type == type) {
		    est = it->cost;
		    costEstimates.erase(it);
		    break;
		}
	    }
	    if (est != actual) {
		debug(HIGH, "adjusting IPv%d schedule cost from %d to %d (%+d)\n",
		    ipv, est, actual, actual - est);
		tracker->incGoal(actual - est);
	    }
	}

	// run the scheduled tests
	for (int i = 0; i < resp.schedule_size(); i++) {
	    const SpooferServerSchedule &sched = resp.schedule(i);
	    time_t started = time(nullptr);
	    // note: we avoid the oneof API for 2.4 compatibility
	    if (sessionTests[SPOOF] && sched.has_spoof()) {
		Session::SpoofTester(*this, sched.spoof(), req.add_report()->mutable_spoof()).runTests();
	    } else if (sessionTests[TRACEFILTER] && sched.has_tracefilter()) {
		Session::TracefilterTester(*this, sched.tracefilter(), req.add_report()->mutable_tracefilter()).runTests();
	    } else if (sessionTests[TRACEROUTE] && sched.has_traceroute()) {
		runTracerouteTests(sched.traceroute());
	    } else if (sessionTests[SPOOFINGRESS] && sched.has_spoofingress()) {
		runSpoofIngressTests(sched.spoofingress());
	    }
	    schedulesDone++;
	    printf(">> IPv%d test %d done in %lus\n", ipv, schedulesDone, 
		static_cast<unsigned long>(time(nullptr) - started));
	}

	// send reports and request more work
	req.set_ready(true);
	printClientMsg(req, ipv, time(nullptr));
	if (!standaloneMode) {
	    if ((pbsresult = pbs->writeMessage(&req)) != PBStreamer::OK) {
		severe("sending IPv%d ClientMsg: %s", ipv, pbs->last_errmsg());
		return nullptr;
	    }
	}
	req.Clear();
    }

    printf(">> IPv%d Result Summary:\n", ipv);
    printf(">>   ASN: %d\n", resp.summary().clientasn());
    printResult("private", "egress", resp.summary().privaddr());
    printResult("routable", "egress", resp.summary().routable());
    if (resp.summary().has_ingress_privaddr())
	printResult("private", "ingress", resp.summary().ingress_privaddr());
    if (resp.summary().has_ingress_internal())
	printResult("internal", "ingress", resp.summary().ingress_internal());


    status = SS_SUCCESS;
    return nullptr;
}

void Session::generateFakeHello()
{
    resp.Clear();

    std::vector<const char *> spoof_dests;
    char dst_in[IPV6ADDRLEN], src_in[IPV6ADDRLEN];

#if 0
    if (ipv == IPv4) {
	resp.mutable_txtmsg()->set_level(SpooferTextMessage::WARNING);
	resp.mutable_txtmsg()->set_body("This is a test of a SpooferTextMessage warning.  This is only a test.");
    } else {
	resp.mutable_txtmsg()->set_level(SpooferTextMessage::NOTICE);
	resp.mutable_txtmsg()->set_body("This is a test of a SpooferTextMessage notice.  This is only a test.");
    }
#endif

    if (ipv == IPv4) {
	// spoof_dests.push_back("132.249.65.60"); // ingress
	spoof_dests.push_back("139.91.90.6");
	spoof_dests.push_back("78.41.116.2");
	// spoof_dests.push_back("137.164.84.50");
    } else {
	spoof_dests.push_back("2a02:60:1:1::49"); // vie-at.ark
	spoof_dests.push_back("2001:770:18:7:225:90ff:fe0c:acb4"); // dub-ie.ark
    }
    resp.mutable_hello()->set_sessionid(0xFFFFFFFF); // higher than any real id
    resp.mutable_hello()->set_sessionkey("FakeSessionKey"); // no caps in real keys
    resp.mutable_hello()->set_clientip(int_clientip);
    SpooferServerHello::WorkEstimate *work_est;

    // initialize fake Spoof tests
    // (with separate Schedules for non-spoofed and spoofed phases)
    if (sessionTests[SPOOF]) {
	inet_pton(family, ipv==IPv4 ? "10.68.68.68" : "2001::1", &src_in);
	for (int spoof = 0; spoof <= 1; spoof++) {
	    char seqno[SEQNOSIZE];
	    SpooferSpoofSchedule *sched = resp.add_schedule()->mutable_spoof();
	    SpooferSpoofSchedule::Item *item;
	    for (unsigned i = 0; i < spoof_dests.size(); i++) {
		item = sched->add_item();
		if (spoof)
		    item->set_srcip(&src_in, addrlen());
		else
		    item->set_srcip(resp.hello().clientip());
		inet_pton(family, spoof_dests[i], &dst_in);
		item->set_dstip(&dst_in, addrlen());
		genSequence(seqno, SEQNOSIZE);
		memcpy(seqno, "TEST", 4); // real seqno's never contain capitals
		item->set_seqno(seqno, SEQNOSIZE);
	    }
	    work_est = resp.mutable_hello()->add_work_est();
	    work_est->set_type(SPOOF);
	    work_est->set_count(safe_int<uint32_t>(spoof_dests.size()));
	}
    }

    // initialize fake Tracefilter tests
    if (sessionTests[TRACEFILTER]) {
	SpooferTracefilterSchedule *sched = resp.add_schedule()->mutable_tracefilter();
	SpooferTracefilterSchedule::Item *item = sched->add_item();
	uint8_t addr[IPV6ADDRLEN];
	const char *src = spoof_dests[0];
	if (ipv == IPv4 && standaloneTraceSrc4)
	    src = standaloneTraceSrc4;
	if (ipv == IPv6 && standaloneTraceSrc6)
	    src = standaloneTraceSrc6;
	inet_pton(family, src, addr);
	item->set_srcip(addr, addrlen());
	addr[addrlen()-1] ^= 1; // toggle last bit
	item->set_dstip((char*)&addr, addrlen());
	item->set_dist(5);
	work_est = resp.mutable_hello()->add_work_est();
	work_est->set_type(TRACEFILTER);
	work_est->set_count(1);
    }

    // initialize fake Traceroute tests
    if (sessionTests[TRACEROUTE]) {
	SpooferTracerouteSchedule *sched = resp.add_schedule()->mutable_traceroute();
	SpooferTracerouteSchedule::Item *item;
	for (unsigned i = 0; i < spoof_dests.size(); i++) {
	    item = sched->add_item();
	    inet_pton(family, spoof_dests[i], &dst_in);
	    item->set_dstip(&dst_in, addrlen());
	}
	work_est = resp.mutable_hello()->add_work_est();
	work_est->set_type(TRACEROUTE);
	work_est->set_count(safe_int<uint32_t>(spoof_dests.size()));
    }

    // initialize fake SpoofIngress tests
    if (sessionTests[SPOOFINGRESS]) {
	SpooferSpoofIngressSchedule *sched = resp.add_schedule()->mutable_spoofingress();
	sched->set_timeout(30);
	sched->set_dstip(int_clientip);
	for (int spoof = 0; spoof <= 1; spoof++) {
	    if (spoof) {
		uint8_t addr[IPV6ADDRLEN];
		memcpy(addr, int_clientip.data(), addrlen());
		addr[addrlen()-1] ^= 1; // toggle last bit
		sched->add_srcip(addr, addrlen());
	    } else {
		inet_pton(family, spoof_dests[0], &dst_in);
		sched->add_srcip(&dst_in, addrlen());
	    }
	}
	work_est = resp.mutable_hello()->add_work_est();
	work_est->set_type(SPOOFINGRESS);
	work_est->set_count(safe_int<uint32_t>(sched->srcip_size()));
    }
}

void Session::makeCostEstimate(SpooferTestType type, int count)
{
    if (!sessionTests[type]) return;
    int est =
	type == SPOOF        ? count * DUPLICATES :
	type == TRACEFILTER  ? count * DUPLICATES * 10 : // dist=10 in 1.1.0 server
	type == TRACEROUTE   ? count * TRACEROUTE_ITEM_COST :
	type == SPOOFINGRESS ? count * DUPLICATES :
	0;
    costEstimates.push_back(CostEstimate(type, count, est));
    tracker->goal += est;
}

bool Session::validateServerMsg()
{
    if (resp.has_txtmsg() && !handleTextMessage(resp.txtmsg()))
	return false;

    if (resp.has_hello()) {
	if (rcvdHello) {
	    severe("unexpected IPv%d ServerHello", ipv);
	    return false;
	}
	rcvdHello = true;
	if (!validateAddr(resp.hello().clientip(), ipv, "ServerHello"))
	    return false;
	ext_clientip = resp.hello().clientip();
	sessionid = resp.hello().sessionid();
	sessionkey = resp.hello().sessionkey();
	if (multiThreaded && !sessionkey.empty()) {
	    // Now that we have a sessionkey, let other sessions use it.
	    debug(HIGH, "IPv%d got sessionkey; unlocked (nonempty: \"%s\")\n",
		ipv, sessionkey.c_str());
	    sessionkey_mutex.unlock();
	}
	for (int i = 0; i < resp.hello().work_est_size(); i++) {
	    const SpooferServerHello::WorkEstimate &work_est = resp.hello().work_est(i);
	    makeCostEstimate(work_est.type(), safe_int<int>(work_est.count()));
	}

    } else if (!rcvdHello) {
	severe("missing IPv%d ServerHello", ipv);
	return false;
    }

    for (int i = 0; i < resp.schedule_size(); i++) {
	int n_sched = 0;

	// note: we avoid the oneof API for 2.4 compatibility
	if (resp.schedule(i).has_spoof()) {
	    if (!sessionTests[SPOOF])
		warn("IPv%d server requested disallowed test type %s", ipv, names_TestType.fromId(SPOOF));
	    n_sched++;
	    const SpooferSpoofSchedule &sched = resp.schedule(i).spoof();
	    if (sched.item_size() > 400) {
		severe("Bad spoof test list from IPv%d server (size=%d).",
		    ipv, sched.item_size());
		return false;
	    }
	    for (int j = 0; j < sched.item_size(); j++) {
		const SpooferSpoofSchedule::Item &item = sched.item(j);
		if (!validateAddr(item.srcip(), ipv, "SpoofSchedule", j))
		    return false;
		if (!validateAddr(item.dstip(), ipv, "SpoofSchedule", j))
		    return false;
		// XXX validate seqno, timestamp, hmac?
	    }
	}

	if (resp.schedule(i).has_tracefilter()) {
	    if (!sessionTests[TRACEFILTER])
		warn("IPv%d server requested disallowed test type %s", ipv, names_TestType.fromId(TRACEFILTER));
	    n_sched++;
	    const SpooferTracefilterSchedule &sched = resp.schedule(i).tracefilter();
	    if (sched.item_size() > 100) {
		warn("Ignoring bad tracefilter test list from IPv%d server (size=%d).",
		    ipv, sched.item_size());
		resp.mutable_schedule(i)->mutable_tracefilter()->Clear();
	    }
	    for (int j = 0; j < sched.item_size(); j++) {
		const SpooferTracefilterSchedule::Item &item = sched.item(j);
		if (!validateAddr(item.srcip(), ipv, "TracefilterSchedule", j))
		    return false;
		if (!validateAddr(item.dstip(), ipv, "TracefilterSchedule", j))
		    return false;
	    }
	}

	if (resp.schedule(i).has_traceroute()) {
	    if (!sessionTests[TRACEROUTE])
		warn("IPv%d server requested disallowed test type %s", ipv, names_TestType.fromId(TRACEROUTE));
	    n_sched++;
	    const SpooferTracerouteSchedule &sched = resp.schedule(i).traceroute();
	    if (sched.item_size() > 100) {
		warn("Ignoring bad traceroute test list from IPv%d server (size=%d).",
		    ipv, sched.item_size());
		resp.mutable_schedule(i)->mutable_traceroute()->Clear();
	    }
	    for (int j = 0; j < sched.item_size(); j++) {
		const SpooferTracerouteSchedule::Item &item = sched.item(j);
		if (!validateAddr(item.dstip(), ipv, "TracerouteSchedule", j))
		    return false;
	    }
	}

	if (resp.schedule(i).has_spoofingress()) {
	    if (!sessionTests[SPOOFINGRESS])
		warn("IPv%d server requested disallowed test type %s", ipv, names_TestType.fromId(SPOOFINGRESS));
	    n_sched++;
	    const SpooferSpoofIngressSchedule &sched = resp.schedule(i).spoofingress();
	    if (sched.srcip_size() > 100) {
		severe("Bad spoofingress test list from IPv%d server (size=%d).",
		    ipv, sched.srcip_size());
		return false;
	    }
	    if (sched.timeout() > 300) {
		severe("Bad spoofingress timeout from IPv%d server (%u).",
		    ipv, sched.timeout());
		return false;
	    }
	    if (!validateAddr(sched.dstip(), ipv, "SpoofIngressSchedule"))
		return false;
	    for (int j = 0; j < sched.srcip_size(); j++) {
		if (!validateAddr(sched.srcip(j), ipv, "SpoofIngressSchedule", j))
		    return false;
	    }
	}

	if (n_sched == 0) {
	    severe("IPv%d Schedule %d: Unknown or missing sub-schedule", ipv, i);
	    return false;
	} else if (n_sched > 1) {
	    severe("IPv%d Schedule %d: multiple sub-schedules (%d)", ipv, i, n_sched);
	    return false;
	}
    }

    if (resp.has_summary() && resp.schedule_size() > 0)
	warn("Found %d schedules in final IPv%d message", resp.schedule_size(), ipv);

    return true;
}

bool Session::init()
{
    if (pretendMode) return true;

    Session::TestItem sessitem(*this);
    if (!sessitem.initSockets(true)) {
	if (spoof_layer[ipv])
	    notice("Can not test IPv%d spoofing at layer %d.", ipv, spoof_layer[ipv]);
	else
	    notice("Can not test IPv%d spoofing.", ipv);
	return false;
    }

    if (sessionTests[TRACEROUTE]) {
	if (!RouteTracer::init(ipv))
	    sessionTests[TRACEROUTE] = false;
    }
    return true;
}

bool Session::serverConnect()
{
    struct probe_info *server_pinfo = nullptr;
    socklen_t len = 0;

    sockaddr_storage server_ss;
    struct sockaddr *server_sa = (struct sockaddr *)&server_ss;
    sockaddr_storage client_ss;
    struct sockaddr *client_sa = (struct sockaddr *)&client_ss;

    memset(server_sa, 0, sizeof(server_ss));
    server_sa->sa_family = family;
    inet_pton(family, ipv == IPv4 ? server4 : server6, sa_ipaddr(server_sa));
    sa_port(server_sa) = enableTLS ? htons(REPORT_PORT_SSL) : htons(REPORT_PORT_CLEAR);

    int socktype = standaloneMode ? SOCK_DGRAM : SOCK_STREAM;
    int sockproto = standaloneMode ? IPPROTO_UDP : IPPROTO_TCP;
    const char *verb = standaloneMode ? "Routing" : "Connecting";

    // Establish TCP control connection (or UDP interface for routing info)
    printf(">> %s to IPv%d server %s port %d\n", verb, ipv,
	ntopBuf(server_sa)(), ntohs(sa_port(server_sa)));
    ctrlsock = newSocket(family, socktype, sockproto);
    if (ctrlsock == INVALID_SOCKET) {
	severe("can't create IPv%d server socket.", ipv);
	goto fail;
    }
    debug(DEVELOP, "created IPv%d ctrlsock\n", ipv);

#ifdef HAVE_LIBSSL
    if (enableTLS) {
	ctrl_ssl = SSL_new(ssl_ctx);
	if (!ctrl_ssl) {
	    ssl_err("SSL_new() failed");
	    goto fail;
	}
	if (!SSL_set_fd(ctrl_ssl, safe_int<int>(ctrlsock))) {
	    ssl_err("SSL_set_fd() failed");
	    goto fail;
	}
	X509_VERIFY_PARAM *param = SSL_get0_param(ctrl_ssl);
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (!X509_VERIFY_PARAM_set1_host(param, report_host, 0)) {
	    ssl_err("X509_VERIFY_PARAM_set1_host() failed");
	    goto fail;
	}
	// SSL_set1_host() was not added until OpenSSL 1.1.0
    }
#endif

    if (connect(ctrlsock, server_sa, sa_len(server_sa)) < 0) {
        severe("connecting to IPv%d server %s port %d: %s",
	    ipv, ntopBuf(server_sa)(), ntohs(sa_port(server_sa)),
	    SockLastErrmsg()());
	goto fail;
    }
    debug(DEVELOP, "connected to IPv%d server %s port %d\n",
	ipv, ntopBuf(server_sa)(), ntohs(sa_port(server_sa)));

    len = sizeof(client_ss);
    if (getsockname(ctrlsock, client_sa, &len) < 0) {
        severe("Couldn't get local IPv%d address: %s", ipv, SockLastErrmsg()());
	goto fail;
    } 
    if (len != sa_len(server_sa)) {
        severe("Error in local IPv%d address: sockaddr length %u (expected %u)", ipv, len, sa_len(server_sa));
	goto fail;
    } 
    if (client_sa->sa_family != family) {
        severe("Error in local IPv%d address: family %u (expected %u)", ipv, client_sa->sa_family, family);
	goto fail;
    } 
    int_clientip.assign(sa_ipaddr(client_sa), addrlen());
    req.mutable_hello()->set_clientip(int_clientip);

    if (standaloneMode) {
	closesocket(ctrlsock);
	ctrlsock = INVALID_SOCKET;
    } else {
#ifdef HAVE_LIBSSL
	if (enableTLS) {
	    int ret = SSL_connect(ctrl_ssl);
	    if (ret != 1) {
		ssl_io_error(ctrl_ssl, ret, "SSL_connect");
		goto fail;
	    }
	    debug(DEVELOP, "IPv%d TLS cipher: %s\n",
		ipv, SSL_get_cipher_name(ctrl_ssl));

	    // verify server certificate
	    X509 *cert = SSL_get_peer_certificate(ctrl_ssl);
	    if (!cert) {
		pprintf(enableTLSverify ? "Error" : "Warning",
		    "missing server certificate");
		if (enableTLSverify) goto fail;
	    } else {
		char namebuf[1024];
		X509_NAME *xname = X509_get_subject_name(cert); // in openssl 1.0.2, undocumented
		X509_NAME_oneline(xname, namebuf, sizeof(namebuf));
		debug(DEVELOP, "IPv%d cert name: %s\n", ipv, namebuf);
		long rc = SSL_get_verify_result(ctrl_ssl);
		if (rc != X509_V_OK) {
		    const char *msg = X509_verify_cert_error_string(rc);
		    pprintf(enableTLSverify ? "Error" : "Warning",
			"IPv%d Server certificate verification error for %s: [%ld] %s",
			ipv, report_host, rc, msg ? msg : "(null)");
		    if (enableTLSverify) goto fail;
		} else {
		    debug(DEVELOP, "IPv%d server certificate verification ok\n", ipv);
		}
		X509_free(cert);
	    }
	}
#endif
	server_pinfo = new_probe_info(IPPROTO_TCP, false, ctrlsock, nullptr,
	    server_sa);
    }

    // Send Hello
    printClientMsg(req, ipv, time(nullptr));
    if (!standaloneMode) {
	pbs =
#ifdef HAVE_LIBSSL
	    enableTLS ? new PBStreamer(ctrl_ssl, pbs_magic) :
#endif
	    new PBStreamer(ctrlsock, pbs_magic);
	PBStreamer::Result pbsresult;
	if ((pbsresult = pbs->writeMessage(&req)) != PBStreamer::OK) {
	    severe("sending IPv%d SpooferClientHello: %s", ipv, pbs->last_errmsg());
	    goto fail;
	}
	free_probe_info(server_pinfo);
	server_pinfo = nullptr;
    }
    return true;

fail:
    if (server_pinfo) free_probe_info(server_pinfo, true);
    notice("Can not test IPv%d spoofing.", ipv);
#ifdef HAVE_LIBSSL
    if (ctrl_ssl) {
	SSL_shutdown(ctrl_ssl);
	SSL_free(ctrl_ssl);
	ctrl_ssl = nullptr;
    }
#endif
    if (ctrlsock != INVALID_SOCKET) closesocket(ctrlsock);
    ctrlsock = INVALID_SOCKET;
    return false;
}

static void displayResults(const char *skey) {
    char buf[BUFSIZE];
    if (!*skey) return;
    snprintf(buf, BUFSIZE, "https://%s/report.php?sessionkey=%s", 
        report_host, skey);
    printf("\nTest Complete.\n");
    // NB: GUI depends on this output format
    printf("Your test results:\n    %s\n\n", buf);
#if 0 // don't open webbrowser
    if (is_interactive()) {
	// open webbrowser to display report
#ifdef _WIN32
	debug(DEVELOP, ">> prober: launching browser\n");
	ShellExecute(nullptr, "open", buf, NULL, NULL, SW_SHOWNORMAL);
#else
 #ifdef _OSX
	const char *opencmd = "open";
 #else // unix gui?
	const char *opencmd = "xdg-open";
 #endif
	debug(DEVELOP, ">> prober: launching browser\n");
	execlp(opencmd, opencmd, buf, nullptr);
#endif
    }
#endif
}

static void banner() {
    // NB: GUI depends on this output format
    printf(">> %s version %s\n", PACKAGE_DESC, PACKAGE_VERSION);
    printf(">> %s\n", PACKAGE_URL);
    const char *start;
    size_t len;
    for (start = COPYRIGHT, len = 0; start[len]; start += len + 1) {
	while (isspace(*start)) ++start;
	len = strcspn(start, ";");
	if (len > 0) printf(">> %.*s\n", int(len), start);
    }
    printf(">>\n");

#ifdef HAVE_PCAP
    printf(">> %s\n", pcap_lib_version());
#else
    printf(">> %s\n", "libpcap not available");
#endif
    printf(">> Google Protobuf version %d.%d.%d\n",
	GOOGLE_PROTOBUF_VERSION / 1000000,
	GOOGLE_PROTOBUF_VERSION / 1000 % 1000,
	GOOGLE_PROTOBUF_VERSION % 1000);
#ifdef HAVE_LIBSSL
    printf(">> %s\n", OPENSSL_VERSION_TEXT);
#else
    printf(">> %s\n", "SSL disabled");
#endif
    printf(">>\n");

    for (start = PACKAGE_LONGDESC, len = 0; start[0]; start += len) {
	while (isspace(start[len])) ++start;
	if ((len = strlen(start)) > 75) {
	    len = 75;
	    while (!isspace(start[len-1])) --len;
	}
	printf(">> %.*s\n", int(len), start);
    }
    printf(">>\n");
}

NORETURN static void usage (char *prog, int exitcode) {
    banner();
    printf("\n");
    printf("Usage %s [options]\n", prog);
    printf("options:\n");
    printf("-h, --help  print this help and exit\n");
    printf("--version   print version information and exit\n");
    printf("-s{1|0}     " DESC_SHARE_PUBLIC " (yes/no)\n");
    printf("-r{1|0}     " DESC_SHARE_REMEDY " (yes/no)\n");
    printf("-v          be more verbose (repeatable)\n");
    printf("-4          test IPv4 (default: both IPv4 and IPv6)\n");
    printf("-6          test IPv6 (default: both IPv4 and IPv6)\n");
    printf("-L<n>       spoof with layer <n> API: 3 (IP), 2 (link), or 0 (auto).\n");
#ifdef HAVE_PTHREAD
    printf("-1          run single-threaded\n");
#endif
#if DEBUG
    printf("-P          pretend mode - don't send any probe packets\n");
    printf("-S          standalone debugging mode - run a test without server\n");
    printf("-T          use the development test server\n");
    printf("-V<n>       masquerade as version <n>\n");
    printf("-D<n>       delay traceroutes by <n> milliseconds\n");
    printf("-A<types>   allow only test types in comma-separated list\n");
    printf("--server4 <addr>   address of IPv4 server [%s]\n", PROD_SERVER);
    printf("--server6 <addr>   address of IPv6 server [%s]\n", PROD_SERVER6);
    printf("--tfsrc4 <addr>    address of v4 tracefilter source (with -S)\n");
    printf("--tfsrc6 <addr>    address of v6 tracefilter source (with -S)\n");
#endif
#ifdef HAVE_LIBSSL
    printf("--no-tls           connect to server without SSL/TLS\n");
#if DEBUG
    printf("--no-verify        ignore TLS certificate verification errors\n");
    printf("--no-defaultca     don't load default openssl certs\n");
    printf("--cafile <file>    load CA certs from <file>\n");
#endif // DEBUG
#endif // HAVE_LIBSSL
    printf("\n");
    exitpause(exitcode);
}

static void optionPrompt(int &opt, const char *name, const char *desc)
{
    if (opt < 0) {
	char buf[SMALLBUF];
	if (!is_interactive())
	    fatal("Missing required %s option.\n", name);
	printf("%s? [yes/no/quit] ", desc);
	if (standaloneMode) printf("\n(ignored in standalone mode) ");
	fflush(stdout);
	if (!fgets(buf, SMALLBUF, stdin))
	    fatal("Aborting.\n");
	if (tolower(buf[0]) == 'y')
	    opt = 1;
	else if (tolower(buf[0]) == 'n')
	    opt = 0;
	else
	    fatal("Aborting.\n");
    }
}

#ifndef HAVE_GETOPT_LONG
static int spoofer_getopt_long(int argc, char * const argv[],
    const char *optstring, const struct option *longopts, int *longindex)
{
    char optstring_long[64];
    strcpy(optstring_long, optstring);
    strcat(optstring_long, "-:"); // also accept "--name"
    int opt = getopt(argc, argv, optstring_long);
    if (opt == '-') {  // --name
	for (int i = 0; longopts[i].name; i++) {
	    if (strcmp(optarg, longopts[i].name) == 0) {
		optarg = longopts[i].has_arg ? argv[optind++] : nullptr;
		opt = 0;
		*(longopts[i].flag ? longopts[i].flag : &opt) = longopts[i].val;
		if (longindex) *longindex = i;
		return opt;
	    }
	}
	fprintf(stderr, "%s: unknown option '--%s'\n", argv[0], optarg);
    }
    return opt;
}
#endif

enum { OPT_VERSION = 256, OPT_SERVER4, OPT_SERVER6, OPT_TFSRC4, OPT_TFSRC6,
    OPT_CAFILE };

int main(int argc, char **argv) {
    int opt;
    bool enable4 = false, enable6 = false;

    AppInfo appInfo(argv[0]);

    setvbuf(stderr, nullptr, _IONBF, 0);
    setvbuf(stdout, nullptr, _IONBF, 0);

    for (auto entry : names_TestType)
	enabledTests[entry.id] = true;

    const struct option longopts[] = {
	{ "help",         0, nullptr,          'h' },
	{ "version",      0, nullptr,          OPT_VERSION },
	{ "server4",      1, nullptr,          OPT_SERVER4 },
	{ "server6",      1, nullptr,          OPT_SERVER6 },
	{ "tfsrc4",       1, nullptr,          OPT_TFSRC4 },
	{ "tfsrc6",       1, nullptr,          OPT_TFSRC6 },
#ifdef HAVE_LIBSSL
	{ "no-tls",       0, &enableTLS,       0 },
	{ "no-verify",    0, &enableTLSverify, 0 },
	{ "no-defaultca", 0, &default_ca,      0 },
	{ "cafile",       1, nullptr,          OPT_CAFILE },
#endif
	{ nullptr,        0, nullptr,          0 }
    };
    while ((opt = getopt_long(argc, argv, "s:r:vV:D:PSThL:A:146",
	longopts, nullptr)) != -1)
    {
        switch (opt) {
        case 's':
	    if (strcmp(optarg, "1") == 0)
		sharePublic = 1;
	    else if (strcmp(optarg, "0") == 0)
		sharePublic = 0;
	    else
		usage(argv[0], -1);
            break;
        case 'r':
	    if (strcmp(optarg, "1") == 0)
		shareRemedy = 1;
	    else if (strcmp(optarg, "0") == 0)
		shareRemedy = 0;
	    else
		usage(argv[0], -1);
            break;
        case 'v':
            verbosity++;
            break;
#if DEBUG
	case 'V':
	    spoofer_protocol_version = safe_int<uint32_t>(strtoul(optarg, nullptr, 10));
	    break;
	case 'D':
	    traceroute_delay = safe_int<unsigned>(strtoul(optarg, nullptr, 10));
	    break;
	case 'A':
	    for (auto entry : names_TestType)
		enabledTests[entry.id] = false;
	    while (char *token = strtok(optarg, ",")) {
		optarg = nullptr;
		SpooferTestType type;
		if (!names_TestType.toId(token, type)) {
		    fprintf(stderr, "%s: invalid test type \"%s\"\n", argv[0], token);
		    usage(argv[0], -1); // no return
		}
		enabledTests[type] = true;
	    }
	    break;
#endif
        case 'P':
            pretendMode = TRUE;
            break;
        case 'S':
            standaloneMode = TRUE;
            break;
        case 'T':
	    useDevServer = true;
            break;
        case 'L':
            spoof_layer[IPv4] = atoi(optarg);
            spoof_layer[IPv6] = atoi(optarg);
            break;
	case '1':
	    multiThreaded = false;
	    break;
	case '4':
	    enable4 = true;
	    break;
	case '6':
	    enable6 = true;
	    break;
        case 'h':
            usage(argv[0], 0); // no return
	case OPT_TFSRC4:
	    standaloneTraceSrc4 = strdup(optarg);
	    break;
	case OPT_TFSRC6:
	    standaloneTraceSrc6 = strdup(optarg);
	    break;
	case OPT_VERSION:
	    banner();
	    exit(0);
	case OPT_SERVER4:
	    server4 = strdup(optarg);
	    break;
	case OPT_SERVER6:
	    server6 = strdup(optarg);
	    break;
#ifdef HAVE_LIBSSL
	case OPT_CAFILE:
	    ca_file = strdup(optarg);
	    break;
#endif
	case 0: // long option flag
	    break;
        default:
            usage(argv[0], -1); // no return
        }
    }
    if (optind < argc) {
	fprintf(stderr, "%s: unexpected argument\n", argv[0]);
	usage(argv[0], -1); // no return
    }

    banner();

    if (useDevServer) {
	if (standaloneMode)
	    warn("-S option overrides -T option");
	if (!server4) server4 = TEST_SERVER;
	    else warn("--server4 option overrides -T option");
	if (!server6) server6 = TEST_SERVER6;
	    else warn("--server6 option overrides -T option");
	report_host = TEST_REPORT_HOST;
    } else {
	if (!server4) server4 = PROD_SERVER;
	if (!server6) server6 = PROD_SERVER6;
	report_host = PROD_REPORT_HOST;
    }

    if (!enable4 && !enable6)
	enable4 = enable6 = true; // default to both

    /* Init */
    streamSetup();

    /* Ask about data sharing */
    printf(">> Ready to test (please allow several minutes to complete).\n");

    optionPrompt(sharePublic, "-s", DESC_SHARE_PUBLIC);
    optionPrompt(shareRemedy, "-r", DESC_SHARE_REMEDY);

    printf(">> Options:\n");
    printf(">>   IPv4: %s\n", enable4 ? "enabled" : "disabled");
    printf(">>   IPv6: %s\n", enable6 ? "enabled" : "disabled");
    printf(">>   sharePublic: %s\n", sharePublic ? "yes" : "no");
    printf(">>   shareRemedy: %s\n", shareRemedy ? "yes" : "no");
    printf(">>   enableTLS: %s\n", enableTLS ? "yes" : "no");
#ifdef HAVE_PTHREAD
    printf(">>   multiThreaded: %s\n", multiThreaded ? "yes" : "no");
#else
    printf(">>   multiThreaded: %s\n", "not available");
#endif
    if (useDevServer) printf(">>   useDevServer\n");
    if (pretendMode) printf(">>   pretendMode\n");
    if (standaloneMode) printf(">>   standaloneMode\n");
    if (traceroute_delay != DEFAULT_TRACEROUTE_DELAY)
	printf(">>   traceroute_delay=%d\n", traceroute_delay);

    printf(">> Started: %s UTC\n", gmTimeStr()());
    puts("");

#ifdef _WIN32
    win_init();
#endif
#ifdef HAVE_LIBSSL
    if (enableTLS) {
	SSL_load_error_strings();
	SSL_library_init();
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ssl_ctx) {
	    ssl_err("SSL_CTX_new() failed");
	    exitpause(1);
	}
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

	if (default_ca) {
	    SSL_CTX_set_default_verify_paths(ssl_ctx); // in openssl 1.0.2, undocumented
	}

#ifdef _OSX
	char ca_file_buf[PATH_MAX];
	if (!ca_file) {
	    // Export OSX root certificates to a file that openssl can load.
	    char tmp[PATH_MAX];
	    char cmd[PATH_MAX+128];
	    sprintf(tmp, "%s/osx_cert.tmp", AppInfo::dir());
	    sprintf(ca_file_buf, "%s/osx_cert.pem", AppInfo::dir());
	    sprintf(cmd, "security find-certificate -a -p %s >%s",
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		tmp);
	    debug(DEVELOP, "cmd: %s\n", cmd);
	    int rc = system(cmd);
	    if (rc == -1) {
		warn("'%s' failed to fork or wait: %s", cmd, strerror(errno));
	    } else if (rc == 127) {
		warn("'%s' failed to execute shell", cmd);
	    } else if (rc != 0) {
		warn("'%s' exited %d", cmd, rc);
	    } else if (rename(tmp, ca_file_buf) < 0) {
		warn("rename %s %s: %s", tmp, ca_file_buf, strerror(errno));
	    } else {
		ca_file = ca_file_buf;
	    }
	}
#endif // _OSX

	if (ca_file) {
	    if (!SSL_CTX_load_verify_locations(ssl_ctx, ca_file, nullptr)) {
		ssl_err(ca_file);
		exitpause(1);
	    }
	}

#ifdef _WIN32
	// Copy root certificates from win32 cryptoapi into openssl store.
	debug(DEVELOP, "loading system certs\n");
	HCERTSTORE hStore;
	PCCERT_CONTEXT pCtx = nullptr;
	X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
	
	if (!(hStore = CertOpenSystemStoreA(0, "ROOT"))) {
	    debug(LOW, "CertOpenSystemStore(): error %ld", GetLastError());

	} else {
	    while ((pCtx = CertEnumCertificatesInStore(hStore, pCtx))) {
		X509 *x509 = d2i_X509(nullptr,
		    const_cast<const unsigned char **>(&pCtx->pbCertEncoded),
		    safe_int<long>(pCtx->cbCertEncoded));
		if (x509) {
		    char namebuf[1024] = "????";
		    X509_NAME *xname = X509_get_subject_name(x509);
		    X509_NAME_oneline(xname, namebuf, sizeof(namebuf));
		    if (X509_STORE_add_cert(store, x509) == 1)
			debug(DEVELOP, "stored cert: %s\n", namebuf);
		    else
			debug(LOW, "X509_STORE_add_cert(): %s: error %ld",
			    namebuf, GetLastError());
		    X509_free(x509);
		}
	    }

	    CertFreeCertificateContext(pCtx); // free the last one
	    CertCloseStore(hStore, 0);
	}
#endif // _WIN32
    }
#endif // HAVE_LIBSSL

#ifdef REGRESS 
  #include "regress.c"
#endif 

    dump_ifaces();

    // Notes:
    // * If both v4 and v6 are enabled, the server expects v4 first.
    // * Failure in init() is not something that is likely to change in the
    //   near future, so we do not indicate it in exitstatus, so the Scheduler
    //   will not retry this Prober.
    if (enable4) sessions.push_back(new Session(IPv4));
    if (enable6) sessions.push_back(new Session(IPv6));

    for (unsigned i = 0; i < sessions.size(); i++) {
	if (sessions[i]->init()) {
#ifdef HAVE_PTHREAD
	    if (multiThreaded) {
		// start in another thread
		int rc = pthread_create(&sessions[i]->thread, nullptr, &Session::run, sessions[i]);
		if (!(sessions[i]->thread_ok = (rc == 0)))
		    severe("pthread_create: %s", strerror(rc));
		continue;
	    }
#endif
	    sessions[i]->run(); // run in main thread
	}
    }

    int exitstatus = 1;
    for (unsigned i = 0; i < sessions.size(); i++) {
#ifdef HAVE_PTHREAD
	if (multiThreaded && sessions[i]->thread_ok) {
	    int rc = pthread_join(sessions[i]->thread, nullptr);
	    if (rc != 0)
		severe("pthread_join: %s", strerror(rc));
	}
#endif
	if (sessions[i]->status == SS_SUCCESS)
	    exitstatus = 0;
    }

    displayResults(sessionkey.c_str());

    exitpause(exitstatus);
}

