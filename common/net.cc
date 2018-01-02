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
   Program:     $Id: net.cc,v 1.152 2017/12/07 22:56:19 kkeys Exp $
   Author:      Rob Beverly <rbeverly at csail.mit.edu>
                Ken Keys, CAIDA
   Date:        $Date: 2017/12/07 22:56:19 $
   Description: Spoofer utility routines
****************************************************************************/
#include <stdarg.h>
#include <map>
#include "spoof_pcap.h"
#include "spoof.h"

#ifdef HAVE_PCAP
static const int always_verify = 1;
#else
static const int always_verify = 0;
#endif

struct iface_info {
    enum {UNKNOWN, BROKEN, WORKS};
    const char * const ifname;  // name of interface with this->src
    int dlt;                    // data link type
    OptMutex mutex;
    volatile int online_udp_filter_able; // whether online pcap filter works for UDP
                                // (may be different for TCP?)

    iface_info(const char *ifname_) : ifname(ifname_), dlt(-1), mutex(),
	online_udp_filter_able(iface_info::UNKNOWN)
	{ }
private:
    iface_info(const iface_info&) NO_METHOD;
    iface_info operator=(const iface_info&) NO_METHOD;
};

struct route_info {
    static const size_t FAILED = INT_MAX;
    struct iface_info * const ifinfo;  // interface info
    uint8_t *linkhdr;           // copy of sniffed link layer header
    volatile size_t linklen;    // length of this->linkhdr

    route_info(struct iface_info *ii) : ifinfo(ii), linkhdr(), linklen()
	{ }
private:
    route_info(const route_info&) NO_METHOD;
    route_info operator=(const route_info&) NO_METHOD;
};

struct probe_info {
    const int proto;
    const int spoof;
    enum ProbeStatus status;
    int layer_sent;             // layer of attempted send
    int layer_sniffed;          // layer of sniffed pkt; -1 for sniff error
    bool warnedSkipSpoof;       // already warned about skipping spoof
    sockaddr_storage src_ss;
    sockaddr *src_sa;
    const sockaddr *dst_sa;
    struct route_info *rtinfo;
#ifdef HAVE_PCAP
    struct bpf_program cap_bpfprog; // capturing filter
    struct bpf_program test_bpfprog; // scanning/checking filter (offline)
    bool has_online_filter;
    bool has_cap_bpfprog;
    bool has_test_bpfprog;
    pcap_t *sniffer;            // for sniffing packets we've sent
    pcap_t *writer;             // for sending spoofed packets
    mutable char dlt_buf[16];
#endif

private:
    probe_info(const probe_info&) NO_METHOD;
    probe_info operator=(const probe_info&) NO_METHOD;
public:
    probe_info(int proto_, bool spoof_,
	sockaddr *src_sa_, const sockaddr *dst_sa_);

    ~probe_info() {
#ifdef HAVE_PCAP
	free_sniffer();
	if (writer) pcap_close(writer);
#endif // HAVE_PCAP
    }

    void setStatus(ProbeStatus s) {
	if (status < s) status = s;
	if (status == s) {
	    debug(DEVELOP, "setStatus %s\n", probeStatusStr[s]);
	} else {
	    debug(DEVELOP, "setStatus %s (still %s)\n",
		probeStatusStr[s], probeStatusStr[status]);
	}
    }
#ifdef HAVE_PCAP
    void free_sniffer();
    const char *dlt_str() const;
#endif // HAVE_PCAP
};

// layer to spoof on:  0 = undecided, 2 = link, 3 = ip
//                     v0  v1  v2  v3  v4  v5  v6
int spoof_layer[7] = { -1, -1, -1, -1,  0, -1,  0 };

#define spoof_layer(sa) \
    (*((sa)->sa_family == AF_INET6 ? &spoof_layer[6] : &spoof_layer[4]))
    // note: spoof_layer(sa) is an lvalue

OptMutex spoof_layer_4_mutex;
OptMutex spoof_layer_6_mutex;
#define spoof_layer_mutex(sa) \
    ((sa)->sa_family == AF_INET6 ? spoof_layer_6_mutex : spoof_layer_4_mutex)

// copy a sockaddr to a std::string (in binary form)
struct saToStr {
    std::string str;
    saToStr(const sockaddr *sa) : str(sa_ipaddr(sa), addrlen(sa->sa_family)) {}
};

#ifdef HAVE_PCAP
std::map<std::string, iface_info *> iface_info_map; // indexed by src addr
OptMutex ifinfo_mutex;
std::map<std::string, route_info *> route_info_map; // indexed by dst addr
OptMutex routeinfo_mutex;
#endif // HAVE_PCAP

/* compare the IP address part of two sockaddrs */
static inline int sa_addr_cmp(const sockaddr *a, const sockaddr *b)
{
    return (a->sa_family != b->sa_family) ?
	(a->sa_family - b->sa_family) :
	memcmp(sa_ipaddr(a), sa_ipaddr(b), addrlen(a->sa_family));
}

// Similar to inet_ntop(), but takes a sockaddr argument.  If dst is
// NULL, sa_ntop() will return a pointer to (non-reentrant-safe) static memory.
const char *sa_ntop(const sockaddr *sa, char *dst, size_t len)
{
    static char buf[INET6_ADDRSTRLEN+1];
    const void *addr = sa_ipaddr(sa);
    if (!dst) {
        dst = buf;
        len = sizeof(buf);
    }
    if (!addr) {
        sprintf(dst, "(unknown family %d)", sa->sa_family);
        return dst;
    }
    memset(dst, 0, len);
    if (!inet_ntop(sa->sa_family, addr, dst, safe_int<unsigned>(len)))
        printf("!! inet_ntop error: %d %s\n", errno, strerror(errno));
    return dst;
}

/*
 * Writes into buf if it is not null, otherwise writes into a static buffer.
 */
const char *sock_errmsg(int err, char *buf, size_t buflen)
{
    static char staticbuf[256];
    if (!buf) {
	buf = staticbuf;
	buflen = sizeof(staticbuf);
    }
#ifdef _WIN32
    char str[1024] = "";
    FormatMessage(
	FORMAT_MESSAGE_FROM_SYSTEM |
	FORMAT_MESSAGE_IGNORE_INSERTS,
	nullptr, static_cast<DWORD>(err), 0,
	str, sizeof(str), nullptr);
#else
    char *str = strerror(err);
#endif
    snprintf(buf, buflen, "%s (error %d)", str, err);
    return buf;
}

/* Can only be called immediately after a socket function that caused an error.
 * Writes into buf if it is not null, otherwise writes into a static buffer.
 */
const char *sock_last_errmsg(char *buf, size_t buflen)
{
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    return sock_errmsg(err, buf, buflen);
}

#ifdef HAVE_LIBSSL
void ssl_err(const char *str)
{
    unsigned long err;
    char buf[2048] = "(no error)";
    char *p = buf;
    while ((err = ERR_get_error()) && p + 4 < buf + sizeof(buf)) {
	if (p != buf)
	    p += sprintf(p, " // ");
	ERR_error_string_n(err, p, safe_int<size_t>(buf + sizeof(buf) - p));
	p += strlen(p);
    }
    severe("%s: %s", str, buf);
}

void ssl_io_error(SSL *ssl, int ret, const char *str)
{
    char buf[256];
    unsigned long err;
    switch (SSL_get_error(ssl, ret)) {
	case SSL_ERROR_NONE:
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    severe("%s: SSL_ERROR_ZERO_RETURN", str);
	    break;
	case SSL_ERROR_WANT_READ:
	    severe("%s: SSL_ERROR_WANT_READ", str);
	    break;
	case SSL_ERROR_WANT_WRITE:
	    severe("%s: SSL_ERROR_WANT_WRITE", str);
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    severe("%s: SSL_ERROR_WANT_CONNECT", str);
	    break;
	case SSL_ERROR_SYSCALL:
	    if (ret == 0) {
		severe("%s: SSL/system: invalid EOF", str);
	    } else if (ret == -1) {
		severe("%s: SSL/system: %s", str, SockLastErrmsg()());
	    } else {
		while ((err = ERR_get_error()))
		    severe("%s: SSL/system: %s", str, ERR_error_string(err, buf));
	    }
	    break;
	case SSL_ERROR_SSL:
	    while ((err = ERR_get_error()))
		severe("%s: SSL/lib: %s", str, ERR_error_string(err, buf));
	    break;
	default:
	    severe("%s: unknown ssl error", str);
	    break;
    }
}
#endif // HAVE_LIBSSL

#ifdef HAVE_PCAP
const char *probe_info::dlt_str() const
{
    if (!rtinfo || !rtinfo->ifinfo)
	return "DLT undef"; // shouldn't happen
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
    const char *result = pcap_datalink_val_to_name(rtinfo->ifinfo->dlt);
    if (result) return result;
#endif
    sprintf(dlt_buf, "DLT %d", rtinfo->ifinfo->dlt);
    return dlt_buf;
}

static void print_pcap_error(pcap_t *pcap, ssize_t rc, const char *fmt, ...) FORMAT_PRINTF(3, 4);
static void print_pcap_error(pcap_t *pcap, ssize_t rc, const char *fmt, ...)
{
    char buf[1024+PCAP_ERRBUF_SIZE];
    size_t space = sizeof(buf);
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, space, fmt, ap);
    va_end(ap);
    if (len < 0) return;
    space -= static_cast<size_t>(len);
    switch (rc) {
    case 0:
        snprintf(buf+len, space, ": %s\n", "success");
        break;
#ifdef PCAP_WARNING
    case PCAP_WARNING:
#endif
    case PCAP_ERROR:
        snprintf(buf+len, space, ": %s\n", pcap_geterr(pcap));
        break;
#ifdef PCAP_WARNING
    case PCAP_WARNING_PROMISC_NOTSUP:
    case PCAP_ERROR_NO_SUCH_DEVICE:
    case PCAP_ERROR_PERM_DENIED:
        //snprintf(buf+len, space, ": %s (%s)\n", pcap_statustostr(rc), pcap_geterr(pcap));
        snprintf(buf+len, space, ": %zd (%s)\n", rc, pcap_geterr(pcap));
        break;
#endif
    default:
        //snprintf(buf+len, space, ": %s\n", pcap_statustostr(rc));
        snprintf(buf+len, space, ": %zd\n", rc);
    }
    severe("%s", buf);
}

/* Returns pointer to allocated memory.  Caller should free() it when done. */
static char *get_ifname_by_addr(const sockaddr *sa)
{
    char *ifname = nullptr;
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        warn("pcap_findalldevs: %s", errbuf);
        goto done;
    }
    pcap_if_t *dev;
    for (dev = alldevs; dev; dev = dev->next) {
        for (pcap_addr_t *daddr = dev->addresses; daddr; daddr = daddr->next) {
	    if (daddr->addr && sa_addr_cmp(daddr->addr, sa) == 0) {
                ifname = strdup(dev->name);
                goto done;
            }
        }
    }

done:
    if (alldevs) pcap_freealldevs(alldevs);
    debug(DEVELOP, ">> get_ifname_by_addr %s: %s\n",
	ntopBuf(sa)(), ifname ? ifname : "(NONE)");
    return ifname;
}
#endif // HAVE_PCAP

static unsigned count_leading_ones(const void *data, size_t len)
{
    const uint8_t *s = reinterpret_cast<const uint8_t*>(data);
    unsigned n = 0;
    for (size_t i = 0; i < len && s[i]; i++) {
	if (s[i] != 0xFF) {
	    for (int j = 0; j < 8 && (s[i] & (0x80 >> j)); j++)
		n++;
	    break;
	}
	n += 8;
    }
    return n;
}

void dump_ifaces()
{
#ifdef HAVE_PCAP
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        warn("pcap_findalldevs: %s", errbuf);
        return;
    }
    pcap_if_t *dev;
    for (dev = alldevs; dev; dev = dev->next) {
	printf("dev %s", dev->name);
#ifdef PCAP_IF_LOOPBACK
	if (dev->flags & PCAP_IF_LOOPBACK) printf(" LOOPBACK");
#endif
#ifdef PCAP_IF_UP
	if (dev->flags & PCAP_IF_UP) printf(" UP");
#endif
#ifdef PCAP_IF_RUNNING
	if (dev->flags & PCAP_IF_RUNNING) printf(" RUNNING");
#endif
	if (dev->description) printf(" (%s)", dev->description);
	printf("\n");
        for (pcap_addr_t *daddr = dev->addresses; daddr; daddr = daddr->next) {
	    if (!daddr->addr) {
		printf("  %s\n", "(no address)");
		continue;
	    } else if (daddr->addr->sa_family == AF_INET) {
		printf("  inet %s", ntopBuf(daddr->addr)());
		if (daddr->netmask)
		    printf(" mask=%s", ntopBuf(daddr->netmask)());
	    } else if (daddr->addr->sa_family == AF_INET6) {
		printf("  inet6 %s", ntopBuf(daddr->addr)());
		if (daddr->netmask) {
		    printf("/%u", count_leading_ones(sa_ipaddr(daddr->netmask),
			addrlen(daddr->netmask->sa_family)));
		}
		unsigned long scope =
		    reinterpret_cast<sockaddr_in6*>(daddr->addr)->sin6_scope_id;
		if (scope)
		    printf(" scope=%#lx", scope);
	    } else {
		continue;
	    }
	    if (daddr->broadaddr && daddr->broadaddr->sa_family != AF_UNSPEC)
		printf(" bcast=%s", ntopBuf(daddr->broadaddr)());
	    if (daddr->dstaddr && daddr->dstaddr->sa_family != AF_UNSPEC)
		printf(" dst=%s", ntopBuf(daddr->dstaddr)());
	    printf("\n");
        }
    }
    printf("\n");

    if (alldevs) pcap_freealldevs(alldevs);
#endif // HAVE_PCAP
}

#ifdef HAVE_PCAP
/* Find or create an iface_info for an outbound address. */
static struct iface_info *get_iface_info(const sockaddr *src_sa)
{
    debug(DEVELOP, ">> get_iface_info %s\n", ntopBuf(src_sa)());
    LockGuard lock(ifinfo_mutex);

    // If we have the answer cached, return that.
    iface_info * &ref = iface_info_map[saToStr(src_sa).str];
    if (ref) {
	debug(DEVELOP, ">> get_iface_info: found %s\n", ref->ifname);
	return ref;
    }

    // Look it up.
    char *ifname = get_ifname_by_addr(src_sa);
    if (!ifname) return nullptr;
    return ref = new iface_info(ifname);
}
#endif // HAVE_PCAP

/* Find or create a route_info matching the parameters. */
static void get_route_info(struct probe_info *pinfo)
{
#ifdef HAVE_PCAP
    debug(DEVELOP, ">> get_route_info %s\n", ntopBuf(pinfo->dst_sa)());
    LockGuard lock(routeinfo_mutex);

    // If we have the answer cached, use that.
    route_info * &ref = route_info_map[saToStr(pinfo->dst_sa).str];
    if (ref) {
	debug(DEVELOP, ">> get_route_info: found %s\n", ref->ifinfo->ifname);
	pinfo->rtinfo = ref;
	return;
    }

    if (pinfo->spoof)
	return; // caller will have to use a pilot to find the route

    if (!pinfo->src_sa) { // shouldn't happen
	severe("internal error: no src_sa");
	return;
    }

    // Find the interface for the source address.
    struct iface_info *ifinfo = get_iface_info(pinfo->src_sa);
    if (!ifinfo) { // shouldn't happen
	severe("no interface for %s", ntopBuf(pinfo->src_sa)());
	return;
    }

    pinfo->rtinfo = ref = new route_info(ifinfo);
#endif
}

#ifdef HAVE_PCAP
static OptMutex pcap_compiler_mutex;

/* Prepare to sniff a probe packet, if necessary. */
static void init_sniffer(struct probe_info *pinfo)
{
    const int snaplen = 62;
    const char *ifname;
    char errbuf[PCAP_ERRBUF_SIZE] = "(empty errbuf)";
    int rc;
    pcap_t *dead_pcap = nullptr;
    pcap_t *test_pcap = nullptr;

    if (pinfo->sniffer) return;
    debug(DEVELOP, ">> init_sniffer\n");
    if (!pinfo->rtinfo) get_route_info(pinfo);
    if (!pinfo->rtinfo) goto error;
    ifname = pinfo->rtinfo->ifinfo->ifname;
    debug(DEVELOP, ">> init_sniffer: pcap_create %s\n", ifname);
#ifdef HAVE_PCAP_CREATE
    pinfo->sniffer = pcap_create(ifname, errbuf);
    if (!pinfo->sniffer) {
	printf("error in pcap_create: %s\n", errbuf);
	goto error;
    }
    rc = pcap_set_snaplen(pinfo->sniffer, snaplen);
    if (rc != 0) { // error or warning
	print_pcap_error(pinfo->sniffer, rc, "%s: pcap_set_snaplen", ifname);
	if (rc < 0) goto error; // error
    }
    debug(DEVELOP, ">> init_sniffer: pcap_activate\n");
    rc = pcap_activate(pinfo->sniffer);
    if (rc != 0) { // error or warning
	print_pcap_error(pinfo->sniffer, rc, "%s: pcap_activate", ifname);
	if (rc < 0) goto error; // error
    }
#else
    pinfo->sniffer = pcap_open_live(ifname, snaplen, 0, 0, errbuf);
    if (!pinfo->sniffer) {
	printf("error in pcap_open_live: %s\n", errbuf);
	goto error;
    }
#endif
    if (pcap_setnonblock(pinfo->sniffer, 1, errbuf) < 0) {
	printf("error in pcap_setnonblock: %s\n", errbuf);
	goto error;
    }
    pinfo->rtinfo->ifinfo->dlt = pcap_datalink(pinfo->sniffer);
    debug(DEVELOP, "pcap_create %s ok, %s\n", ifname, pinfo->dlt_str());

    if (pinfo->rtinfo->ifinfo->dlt == DLT_LINUX_SLL) {
	// Online userspace filters are known to be broken on LINUX_SSL (per
	// https://github.com/the-tcpdump-group/libpcap/issues/184 and my own
	// testing on a linux ppp iface), but they do _occasionally_ match, so
	// we don't rely on a functional test and risk a false positive.
        LockGuard guard(pinfo->rtinfo->ifinfo->mutex);
        pinfo->rtinfo->ifinfo->online_udp_filter_able = iface_info::BROKEN;
    }

    char expr[1024];

    // Compile a capturing filter (preferably online)
    sprintf(expr, "%s and dst port %d and dst host %s and src port %d",
	(pinfo->proto == IPPROTO_TCP ? "tcp" : "udp"),
	ntohs(sa_port(pinfo->dst_sa)), ntopBuf(pinfo->dst_sa)(),
	ntohs(sa_port(pinfo->src_sa)));
    // If not spoofing, also filter on src addr.  If spoofing, we want to
    // capture even if the OS rewrote the addr; sniff_spoofed will check it.
    if (!pinfo->spoof)
	sprintf(expr + strlen(expr), " and src host %s", ntopBuf(pinfo->src_sa)());

    pinfo->has_online_filter = false;

    debug(DEVELOP, ">> init_sniffer (cap): %s\n", expr);
    {
	LockGuard guard(pcap_compiler_mutex);
	rc = pcap_compile(pinfo->sniffer, &pinfo->cap_bpfprog, expr, 1,
	    0xFFFFFFFF);
	if (rc != 0) { // error or warning
	    print_pcap_error(pinfo->sniffer, rc, "%s: pcap_compile (cap)", ifname);
	    if (rc < 0) goto error; // error
	}
    }
    pinfo->has_cap_bpfprog = true;

    if (pinfo->rtinfo->ifinfo->online_udp_filter_able == iface_info::BROKEN) {
	// We'll apply the capturing filter offline instead.
	debug(DEVELOP, ">> init_sniffer: no online filter\n");
    } else {
	debug(DEVELOP, ">> init_sniffer: pcap_setfilter\n");
	rc = pcap_setfilter(pinfo->sniffer, &pinfo->cap_bpfprog);
	if (rc < 0) { // error
	    print_pcap_error(pinfo->sniffer, rc, "%s: pcap_setfilter", ifname);
	} else {
	    pinfo->has_online_filter = true;
	    pinfo->has_cap_bpfprog = false;
	    pcap_freecode(&pinfo->cap_bpfprog);
	}
    }

    // Compile an offline filter for scanning for the IP header (non-spoof) or
    // checking the src address (spoof)
    if (!pinfo->spoof) {
	if (!(test_pcap = dead_pcap = pcap_open_dead(DLT_RAW, snaplen))) {
	    severe("pcap_open_dead: %s", errbuf);
	    goto error;
	}
    } else {
	sprintf(expr, "src host %s", ntopBuf(pinfo->src_sa)());
	test_pcap = pinfo->sniffer;
    }
    debug(DEVELOP, ">> init_sniffer (test): %s\n", expr);
    {
	LockGuard guard(pcap_compiler_mutex);
	rc = pcap_compile(test_pcap, &pinfo->test_bpfprog, expr, 1, 0xFFFFFFFF);
	if (rc != 0) { // error or warning
	    print_pcap_error(test_pcap, rc, "%s: pcap_compile (test)", ifname);
	    if (rc < 0) goto error; // error
	}
    }
    pinfo->has_test_bpfprog = true;
    if (dead_pcap) pcap_close(dead_pcap);
    return;
error:
    if (pinfo->sniffer) pcap_close(pinfo->sniffer);
    if (dead_pcap) pcap_close(dead_pcap);
    pinfo->sniffer = nullptr;
}
#endif // HAVE_PCAP

probe_info::probe_info(int proto_, bool spoof_,
    sockaddr *src_sa_, const sockaddr *dst_sa_) :
    proto(proto_), spoof(spoof_),
    status(UNTRIED), layer_sent(0), layer_sniffed(0), warnedSkipSpoof(),
    src_ss(), src_sa(spoof_ ? src_sa_ : nullptr), dst_sa(dst_sa_), rtinfo(0)
#ifdef HAVE_PCAP
    , cap_bpfprog(), test_bpfprog(),
    has_online_filter(false), has_cap_bpfprog(false), has_test_bpfprog(false),
    sniffer(0), writer(0)
#endif
{
    memset(&src_ss, 0, sizeof(src_ss));
#ifdef HAVE_PCAP
    memset(&cap_bpfprog, 0, sizeof(cap_bpfprog));
    memset(&test_bpfprog, 0, sizeof(test_bpfprog));
#endif
}

struct probe_info *new_probe_info(int proto, bool spoof, socket_t nonSpoofSock,
    sockaddr *src_sa, const sockaddr *dst_sa)
{
    probe_info *pinfo = new probe_info(proto, spoof, src_sa, dst_sa);
    if (!pinfo) {
	severe("out of memory in new_probe_info");
	return pinfo;
    }

    if (!always_verify && spoof_layer(dst_sa) == 3)
	return pinfo;

    if (!spoof) {
	/* Identify the source address for routing to the destination. */
        pinfo->src_sa = (sockaddr*)&pinfo->src_ss;
        socklen_t srclen = sizeof(pinfo->src_ss);
	// note: getsockname() depends on sock already being connect()ed
        if (getsockname(nonSpoofSock, pinfo->src_sa, &srclen) < 0) {
            pinfo->src_sa = nullptr;
            severe("getsockname: %s", SockLastErrmsg()());
	    delete pinfo;
	    return nullptr;
        }
	debug(DEVELOP, ">> new_probe_info: connected from %s port %d\n",
	    ntopBuf(pinfo->src_sa)(), ntohs(sa_port(pinfo->src_sa)));

	sockaddr_storage peer_ss;
	sockaddr *peer_sa = (sockaddr*)&peer_ss;
        socklen_t peerlen = sizeof(peer_ss);
        if (getpeername(nonSpoofSock, peer_sa, &peerlen) < 0) {
            severe("getpeername: %s", SockLastErrmsg()());
        } else {
	    debug(DEVELOP, ">> new_probe_info: connected to %s port %d\n",
		ntopBuf(peer_sa)(), ntohs(sa_port(peer_sa)));
	}
    }

    get_route_info(pinfo);
    return pinfo;
}

#ifdef HAVE_PCAP

static const u_char *get_ip_packet(/*const*/ struct probe_info *pinfo,
    const struct pcap_pkthdr *phdr, const u_char *data)
{
    assert(!pinfo->spoof && pinfo->has_test_bpfprog);
    const u_char *result = nullptr;

    // Instead of trying to implement many link layer parsers ourselves, or
    // relying on a poorly maintained or insufficiently portable third-party
    // library, we use an offline pcap filter to scan for the IP header.  It's
    // not very efficient, but it applies only to packets that already passed
    // the capture filter.
    int v = 0;
    for (size_t i = 0; i < phdr->caplen - 20; i++) {
	if (pcap_offline_filter(&pinfo->test_bpfprog, phdr, data + i)) {
	    v = ((data[i] & 0xF0) >> 4);
	    if (v != 4 && v != 6) continue; // shouldn't happen
	    result = data + i;
	    break;
	}
    }
    if (!result) {
	severe("internal error: IP packet not found (%s)", pinfo->dlt_str());
	return nullptr;
    }
    debug(DEVELOP, "IPv%d offset: %zd (%s)\n", v, result - data,
	pinfo->dlt_str());

    return result;
}

// Record a copy of a link layer header.
static void sniff_link(u_char *userdata,
    const struct pcap_pkthdr *phdr, const u_char *data)
{
    debug(DEVELOP, ">> sniff_link\n");
    if (verbosity >= DEVELOP) {
        printf("sniffed packet:\n");
        binDump(data, phdr->caplen, TRUE);
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    struct probe_info *pinfo = (struct probe_info*)userdata;
#pragma GCC diagnostic pop

    if (!pinfo->has_online_filter) {
	// We didn't filter online, so we must filter offline.
	assert(pinfo->has_cap_bpfprog);
	if (!pcap_offline_filter(&pinfo->cap_bpfprog, phdr, data)) {
	    debug(DEVELOP, "(no capture)\n");
	    return;
	}
	debug(DEVELOP, "(capture)\n");
    }
    pinfo->setStatus(CONFIRMED);

    time_t t; debug(DEVELOP, "(%ld)", time(&t));
    struct route_info *rtinfo = pinfo->rtinfo;
    const u_char *pdu = get_ip_packet(pinfo, phdr, data);
    if (pdu) {
	rtinfo->linklen = safe_int<size_t>(pdu - data);
	rtinfo->linkhdr = new uint8_t[rtinfo->linklen];
	memcpy(rtinfo->linkhdr, data, rtinfo->linklen);
	if (pinfo->proto == IPPROTO_UDP && pinfo->has_online_filter &&
	    rtinfo->ifinfo->online_udp_filter_able == iface_info::UNKNOWN)
	{
	    // NB: TCP and UDP results may differ, and we care only about UDP.
	    debug(DEVELOP, "Online filter works on %s (%s).\n",
		pinfo->rtinfo->ifinfo->ifname, pinfo->dlt_str());
	    LockGuard guard(rtinfo->ifinfo->mutex);
	    rtinfo->ifinfo->online_udp_filter_able = iface_info::WORKS;
	}
	pinfo->layer_sniffed = pinfo->layer_sent;
    }
}

static void sniff_spoofed(u_char *userdata,
    const struct pcap_pkthdr *phdr, const u_char *data)
{
    debug(DEVELOP, ">> sniff_spoofed\n");
    if (verbosity >= DEVELOP) {
        printf("sniffed packet:\n");
        binDump(data, phdr->caplen, TRUE);
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    struct probe_info *pinfo = (struct probe_info*)userdata;
#pragma GCC diagnostic pop

    if (!pinfo->has_online_filter) {
	// We didn't filter online, so we must filter offline.
	assert(pinfo->has_cap_bpfprog);
	if (!pcap_offline_filter(&pinfo->cap_bpfprog, phdr, data)) {
	    debug(DEVELOP, "(no capture)\n");
	    return;
	}
	debug(DEVELOP, "(capture)\n");
    }

    time_t t; debug(DEVELOP, "(%ld)", time(&t));

    // Compare sniffed address to the spoofed address we originally sent
    if (pcap_offline_filter(&pinfo->test_bpfprog, phdr, data)) {
	// Src addresses matched; spoofing works at layer_sent.
	debug(HIGH, "(M%d)", pinfo->layer_sent);
	debug(DEVELOP, "sniffed pkt DOES contain spoof addr\n");
	pinfo->setStatus(CONFIRMED);
	pinfo->layer_sniffed = pinfo->layer_sent;
	// Higher spoof_layer is preferred, so if a parallel thread already
	// set it higher, don't clobber that.
	LockGuard spoof_layer_guard(spoof_layer_mutex(pinfo->dst_sa));
	if (spoof_layer(pinfo->dst_sa) < pinfo->layer_sniffed)
	    spoof_layer(pinfo->dst_sa) = pinfo->layer_sniffed;
    } else {
	// Src address was REWRITTEN
	debug(HIGH, "(!M%d)", pinfo->layer_sent);
	debug(DEVELOP, "sniffed pkt DOES NOT contain spoof addr\n");
	pinfo->setStatus(REWRITTEN);
    }
}

void probe_info::free_sniffer()
{
    if (has_cap_bpfprog) {
	pcap_freecode(&cap_bpfprog);
	has_cap_bpfprog = false;
    }
    if (has_test_bpfprog) {
	pcap_freecode(&test_bpfprog);
	has_test_bpfprog = false;
    }
    if (sniffer) {
	pcap_close(sniffer);
	sniffer = nullptr;
    }
}

// Pcap timeout does not work on all platforms, so we use a nonblocking pcap
// and poll it until we find what we're looking for, or 3s has elapsed.
static int spoofer_pcap_dispatch(struct probe_info *pinfo, const char *label)
{
    time_t end, now;
    time(&end);
    end += 3;
    while (true) {
	debug(DEVELOP, ">> %s: pcap_dispatch (%ld)\n", label, time(&now));
	int rc = pcap_dispatch(pinfo->sniffer, 1,
	    pinfo->spoof ? sniff_spoofed : sniff_link, (u_char*)pinfo);
	debug(DEVELOP, ">> %s: pcap_dispatch done (%ld)\n", label, time(&now));
	if (rc < 0) {
	    print_pcap_error(pinfo->sniffer, rc, "pcap_dispatch on %s",
		pinfo->rtinfo->ifinfo->ifname);
	    pinfo->free_sniffer();
	    debug(DEVELOP, "status: %s\n", probeStatusStr[pinfo->status]);
	    return rc;
	} else if (pinfo->layer_sniffed > 0) {
	    debug(DEVELOP, ">> sniffed %sspoofed L%d\n",
		pinfo->spoof ? "" : "non-", pinfo->layer_sniffed);
	    pinfo->free_sniffer();
	    debug(DEVELOP, "status: %s\n", probeStatusStr[pinfo->status]);
	    return rc; // found what we're looking for
	}
	if (time(&now) > end) break;
	msleep(100); // 0.1s
    }
    pinfo->free_sniffer();
    printf("lost(L%d)\n", pinfo->layer_sent);
    if (!pinfo->spoof && !pinfo->layer_sniffed && pinfo->has_online_filter &&
	pinfo->proto == IPPROTO_UDP)
    {
	iface_info * const &ifinfo = pinfo->rtinfo->ifinfo;
	LockGuard guard(ifinfo->mutex);
	if (ifinfo->online_udp_filter_able == iface_info::UNKNOWN) {
	    ifinfo->online_udp_filter_able = iface_info::BROKEN;
	    pprintf((verbosity >= DEVELOP) ? "Warning" : "Info",
		"Online filter failed on %s (%s); reverting to offline filter.\n",
		ifinfo->ifname, pinfo->dlt_str());
	}
    }
    if (!pinfo->spoof && !pinfo->layer_sniffed && pinfo->proto == IPPROTO_UDP &&
	(!pinfo->has_online_filter ||
	pinfo->rtinfo->ifinfo->online_udp_filter_able == iface_info::WORKS))
    {
	// Failure to sniff a non-spoofed packet indicates a lack of routing
	// (assuming filtering works); remember that fact, so we can skip
	// future attempts.  (Note: failure to sniff a L3 spoofed packet might
	// mean that, or might mean the OS blocks L3 spoofing.)
	pinfo->rtinfo->linklen = route_info::FAILED;
	debug(DEVELOP, "routing to %s failed\n", ntopBuf(pinfo->dst_sa)());
    }
    debug(DEVELOP, "status: %s\n", probeStatusStr[pinfo->status]);
    return 0;
}
#endif // HAVE_PCAP

bool spoof_layer2possible(const IPv &ipv)
{
    static bool flags[7] = { false, false, false, false, false, false, false };
#ifdef HAVE_PCAP
    static bool cached = false;

    if (cached) return flags[ipv];

    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // This test looks for a device with a routable address that can be opened
    // with pcap_open_live().  Thus it will catch some cases of insuffucient
    // permission, or no interfaces for the given ipv.  It will not catch the
    // (much more rare) case of having multiple interfaces where one can be
    // opened but the one we'll need can not.
    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        warn("pcap_findalldevs: %s", errbuf);
        goto done;
    }
    pcap_if_t *dev;
    unsigned char loopback4[IPV4ADDRLEN];
    unsigned char loopback6[IPV6ADDRLEN];
    inet_pton(AF_INET, "127.0.0.1", loopback4);
    inet_pton(AF_INET6, "::1", loopback6);
    for (dev = alldevs; dev; dev = dev->next) {
	bool *flag;
        for (pcap_addr_t *daddr = dev->addresses; daddr; daddr = daddr->next) {
	    // Check for useful address
	    if (!daddr->addr) continue;
	    switch (daddr->addr->sa_family) {
	    case AF_INET:
		if (memcmp(sa_ipaddr(daddr->addr), loopback4, IPV4ADDRLEN) == 0)
		    continue; // ignore loopback address
		flag = &flags[IPv4];
		break;
	    case AF_INET6:
		if (memcmp(sa_ipaddr(daddr->addr), loopback6, IPV6ADDRLEN) == 0)
		    continue; // ignore loopback address
		if (nptohl(ua_field(sockaddr_in6, daddr->addr, sin6_scope_id)))
		    continue; // ignore site-local and link-local addresses
		flag = &flags[IPv6];
		break;
	    default:
		continue; // ignore non-IP address
	    }
	    if (*flag) continue; // no need to repeat test

	    // Check for ability to open
	    pcap_t *writer = pcap_open_live(dev->name, 0, 0, 0, errbuf);
	    if (!writer) {
		debug(LOW, "ERROR: pcap_open_live: %s\n", errbuf);
		break; // failed to open DEVICE; another address won't help
	    }

	    // We'd like to test pcap_sendpacket() here, but we don't yet know
	    // how to generate a valid packet for this iface (and using a dummy
	    // packet with length 0 gives false negatives on some platforms).

	    pcap_close(writer);
	    *flag = true;
	}
    }
    cached = true;

done:
    if (alldevs) pcap_freealldevs(alldevs);
#endif // HAVE_PCAP
    return flags[ipv];
}

enum ProbeStatus free_probe_info(struct probe_info *pinfo, bool skipSniffing)
{
#ifdef HAVE_PCAP
    if (pinfo->sniffer && !skipSniffing) {
	spoofer_pcap_dispatch(pinfo, "free_probe_info");
    }
    pinfo->free_sniffer();
#endif // HAVE_PCAP

    enum ProbeStatus pstatus = pinfo->status;
    delete pinfo;
    return pstatus;
}

// If !spoof and src, udpsock will be bound to src.
// Note: UDP errors may be asynchronously generated due to an ICMP response and
// not reported until the next use of the socket.  We must open a new socket for
// each destination to be sure it doesn't receive errors from a previous probe.
bool initSockets(bool spoof, IPv ipv, socket_t& spoofsock, socket_t& udpsock,
    const sockaddr *src, const sockaddr *dst)
{
    spoofsock = INVALID_SOCKET;
    udpsock = INVALID_SOCKET;
    family_t family = ipvtofamily(ipv);
    {
	// We need udpsock...
	// if not spoofing, to send a nonspoofed probe;
	// if spoofing, we may need to learn the outbound iface for sniffing;
	// if spoofing layer 2, we may need to send a nonspoofed pilot packet.
	udpsock = newSocket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (udpsock == INVALID_SOCKET)
	    return false;
	debug(DEVELOP, "IPv%d udpsock=%d\n", ipv, udpsock);
	int ttl = spoof ? 1 : // pilot pkt goes just far enough to be sniffed
	    TTL_OUT; // pkt must reach server and have known initial TTL
	if (setSockTTL(family, udpsock, ttl) < 0) {
	    severe("set IPv%d socket TTL: %s", ipv, SockLastErrmsg()());
	    return false;
	}
	if (!spoof && src) {
	    debug(DEVELOP, "bind IPv%d src %s %d\n", ipv, ntopBuf(src)(),
		    ntohs(sa_port(src)));
	    if (bind(udpsock, src, sa_len(src)) < 0) {
		info("bind IPv%d src %s %d: %s", ipv, ntopBuf(src)(),
		    ntohs(sa_port(src)), SockLastErrmsg()());
		return false;
	    }
	}
    }
    if (udpsock != INVALID_SOCKET && dst) {
	// code that depends on this connect():
	// - getsockname() in new_probe_info()
	// - send() in socketSend() for nonspoof or pilot
	if (connect(udpsock, dst, sa_len(dst)) < 0) {
	    info("connect IPv%d target %s %d: %s", ipv, ntopBuf(dst)(),
		ntohs(sa_port(dst)), SockLastErrmsg()());
	    return false;
	}
	debug(DEVELOP, "connect IPv%d target %s %d: %s\n", ipv,
	    ntopBuf(dst)(), ntohs(sa_port(dst)), "success");
    }
    if (!spoof)
	return true;
    if (ipv == IPv4 &&
	(spoof_layer[ipv] == 0 || spoof_layer[ipv] == 3))
    {
	// we want to at least try to spoof at layer 3 
	spoofsock = newSocket(family, SOCK_RAW, IPPROTO_UDP);
	if (spoofsock == INVALID_SOCKET) {
	    severe("Spoofer needs root/admin or other special privileges to "
		"open raw sockets.");
	} else {
	    debug(DEVELOP, "IPv%d spoofsock=%d\n", ipv, spoofsock);
	    if (optSocketHDRINCL(spoofsock) == 0) // IPv4 only
		return true; // layer 3 spoofing is possible
	}
    }
    if (spoof_layer[ipv] == 0 || spoof_layer[ipv] == 2) {
	// we may want to spoof at layer 2 
	if (spoof_layer2possible(ipv))
	    return true; // layer 2 spoofing is possible
	notice("No accessible nonlocal IPv%d interfaces.", ipv);
    }
    return false;
}

// Get and clear any error on the socket.  For best results, allow some time
// for an ICMP error response after the last operation before calling this.
const char *getSockErr(socket_t sock, char *buf, size_t buflen)
{
    int err = 0;
    socklen_t errlen = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen) < 0) {
	return sock_last_errmsg(buf, buflen);
    } else if (err != 0) {
	return sock_errmsg(err, buf, buflen);
    }
    return nullptr;
}

// Close a probing socket.  If there were any asynchronous errors pending on
// the socket, report them and return false.
bool closeSocket(socket_t &sock, IPv ipv)
{
    int err = 0;
    if (sock == INVALID_SOCKET) return true;
    char ebuf[256];
    if (getSockErr(sock, ebuf, sizeof(ebuf)))
	debug(DEVELOP, "async error before IPv%d close: %s\n", ipv, ebuf);
    ::closesocket(sock);
    sock = INVALID_SOCKET;
    return err == 0;
}

/* IP pseudo headers for TCP/UDP checksum. */
struct pseudo_ip4 {
    struct in_addr pip_src, pip_dst;
    uint8_t zeros[1];
    uint8_t pip_p;
    uint16_t pip_udp_len;
};

struct pseudo_ip6 {
    struct in6_addr pip6_src, pip6_dst;
    uint32_t pip6_udp_len;
    uint8_t zeros[3];
    uint8_t pip6_nxt;
};

// Properly aligned memory layout for crafting a packet
struct ip4udp {
    union {
	ip ip4;
	struct {
	    char unused_padding[sizeof(ip) - sizeof(pseudo_ip4)];
	    pseudo_ip4 pip4;
	};
    };
    udphdr udp;
};
STATIC_ASSERT(sizeof(ip4udp) == sizeof(ip) + sizeof(udphdr),
    ip4udp_size_is_incorrect);

struct ip6udp {
    union {
	ip6_hdr ip6;
	struct {
	    char unused_padding[sizeof(ip6_hdr) - sizeof(pseudo_ip6)];
	    pseudo_ip6 pip6;
	};
    };
    udphdr udp;
};
STATIC_ASSERT(sizeof(ip6udp) == sizeof(ip6_hdr) + sizeof(udphdr),
    ip6udp_size_is_incorrect);

/**
 * craftPacket -  Fill buffer with the spoofed packet 
 */
size_t craftPacket(uint32_t *buf, const void *payload, size_t payloadlen,
             const sockaddr *src, const sockaddr *dst, u_char ttl,
             unsigned short ipid)
{
    struct udphdr *udp = nullptr;
    size_t ip_hdr_len, packetlen;

    if (dst->sa_family == AF_INET) {
	ip_hdr_len = sizeof(ip);
	udp = &((ip4udp *)buf)->udp;
    } else {
	ip_hdr_len = sizeof(ip6_hdr);
	udp = &((ip6udp *)buf)->udp;
    }
    packetlen = ip_hdr_len + sizeof(*udp) + payloadlen;
    memset(buf, 0, ip_hdr_len + sizeof(*udp));
    memcpy((uint8_t*)udp + sizeof(*udp), payload, payloadlen);

    /* Fill in UDP header. */
    udp->uh_sport = sa_port(src);
    udp->uh_dport = sa_port(dst);
    udp->uh_ulen = htons(safe_int<uint16_t>(sizeof(*udp) + payloadlen));

    /* Fill in IP pseudo header. */
    if (dst->sa_family == AF_INET) {
	struct pseudo_ip4 *pip4 = &((ip4udp *)buf)->pip4;
	pip4->pip_p = IPPROTO_UDP;
	pip4->pip_udp_len = udp->uh_ulen;
	memcpy(&pip4->pip_src, sa_ipaddr(src), IPV4ADDRLEN);
	memcpy(&pip4->pip_dst, sa_ipaddr(dst), IPV4ADDRLEN);
    } else if (dst->sa_family == AF_INET6) {
	struct pseudo_ip6 *pip6 = &((ip6udp *)buf)->pip6;
	pip6->pip6_nxt = IPPROTO_UDP;
	pip6->pip6_udp_len = udp->uh_ulen;
	memcpy(&pip6->pip6_src, sa_ipaddr(src), IPV6ADDRLEN);
	memcpy(&pip6->pip6_dst, sa_ipaddr(dst), IPV6ADDRLEN);
    } else {
	return 0; // shouldn't happen
    }

    /* Calculate UDP checksum. */
    if ((udp->uh_sum = in_cksum(buf, packetlen)) == 0)
        udp->uh_sum = 0xffff;

    /* Now fill in the real IP header fields. */
    memset(buf, 0, ip_hdr_len);

    if (dst->sa_family == AF_INET) {
	/* Note: BSD raw (ip) sockets expect host byte order for ip_len and
	 * ip_off, but that will be handled later if we actually use raw ip. */
	struct ip *ip4 = &((ip4udp *)buf)->ip4;
	ip4->ip_v = IPVERSION;
	ip4->ip_hl = (ip_hdr_len >> 2) & 0x0F;
	ip4->ip_tos = 0;
	ip4->ip_len = htons(safe_int<uint16_t>(packetlen));
	ip4->ip_id = (ttl == TTL_OUT) ?
			safe_int<unsigned short>(spoofer_rand(32768)) :
			htons(ipid);
	ip4->ip_off = htons(IP_DF);
	ip4->ip_ttl = ttl;
	ip4->ip_p = IPPROTO_UDP;
	memcpy(&ip4->ip_src, sa_ipaddr(src), IPV4ADDRLEN);
	memcpy(&ip4->ip_dst, sa_ipaddr(dst), IPV4ADDRLEN);

	/* Calculate IPv4 checksum. */
	ip4->ip_sum = in_cksum(ip4, sizeof(*ip4));

    } else {
	struct ip6_hdr *ip6 = &((ip6udp *)buf)->ip6;
	ip6->ip6_vfc = 6 << 4;
	ip6->ip6_plen = htons(safe_int<uint16_t>(sizeof(*udp) + payloadlen));
	ip6->ip6_nxt = IPPROTO_UDP;
	ip6->ip6_hlim = ttl;
	memcpy(&ip6->ip6_src, sa_ipaddr(src), IPV6ADDRLEN);
	memcpy(&ip6->ip6_dst, sa_ipaddr(dst), IPV6ADDRLEN);
    }

    if (verbosity >= DEVELOP) {
        printf("IP packet:\n");
        binDump(buf, packetlen, TRUE);
    }
    return (packetlen);
}


/**
 * craftProbe -  Build Spoofer probe payload
 */
void craftProbe(probe_t *probe, bool spoof, const SpooferSpoofSchedule::Item *item) {
    memset(probe, 0, sizeof(*probe));
    probe->hdr.ver = htons(PAYLOAD_VERSION);
    probe->hdr.spoofed = htons(!spoof);
    probe->tst.ts = htonl(item->timestamp());
    memcpy(probe->tst.src_addr + IPV6ADDRLEN - item->srcip().size(),
	item->srcip().data(), item->srcip().size());
    memcpy(probe->tst.dst_addr + IPV6ADDRLEN - item->dstip().size(),
	item->dstip().data(), item->dstip().size());
    memcpy(probe->tst.seqno, item->seqno().data(), SEQNOSIZE);
    memcpy(probe->tst.hmac, item->hmac().data(), HMACSIZE);
}


/**
 * in_cksum - compute an IP checksum
 */
unsigned short in_cksum(const void *addr, size_t len) {
	size_t nleft = len;
	uint32_t sum = 0;
	const unsigned short *w = (const unsigned short *)addr;
	unsigned short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

		/* 4mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(const unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = static_cast<uint16_t>(~sum);	/* truncate to 16 bits */
	return(answer);
}

/**
 * genSequence -  Generate a random sequence of digits and lowercase letters
 * (not NUL terminated).
 */
char *genSequence(char *buf, int len) {
    for (int i = 0; i < len; i++) {
        char c = (char)spoofer_rand(10+26);
	buf[i] = safe_int<char>((c < 10) ? '0' + c : 'a' + (c - 10));
    }   
    return buf;
}


#if 0
/*!
 * \brief Subtract one struct timeval from another.
 *
 * Taken from:
 * http://www.gnu.org/software/hello/manual/libc/Elapsed-Time.html
 *
 * \param[out] result difference between the struct timevals at \a x and
 * \a y (x minus y).  This parameter may be NULL.
 *
 * \return 1 if the difference is negative, otherwise 0.
 */
static int
timeval_subtract(
    struct timeval *resultPtr,
    struct timeval x,
    struct timeval y)
{
    struct timeval result;

    /* Perform the carry for the later subtraction by updating y. */
    if (x.tv_usec < y.tv_usec) {
        int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
        y.tv_usec -= 1000000 * nsec;
        y.tv_sec += nsec;
    }
    if (x.tv_usec - y.tv_usec > 1000000) {
        int nsec = (x.tv_usec - y.tv_usec) / 1000000;
        y.tv_usec += 1000000 * nsec;
        y.tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       tv_usec is certainly positive. */
    result.tv_sec = x.tv_sec - y.tv_sec;
    result.tv_usec = x.tv_usec - y.tv_usec;

    if (resultPtr)
        *resultPtr = result;

    /* Return 1 if result is negative. */
    return x.tv_sec < y.tv_sec;
}

/* 
  Handy routines that follow taken directly from R. Stevens UNP 
*/

/*! \brief Read "n" bytes from a descriptor. */
ssize_t readn(int fd, void *vptr, size_t n, time_t wait) {
    size_t	nleft;
    ssize_t	nread;
    char	*ptr;
    fd_set fds;
    struct timeval deadline;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    if (gettimeofday(&deadline, NULL))
        return -1;
    deadline.tv_sec += wait;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        struct timeval timeout;
        {
            struct timeval now;
            if (gettimeofday(&now, NULL))
                return -1;
            if (timeval_subtract(&timeout, deadline, now))
                /* timed out */
                break;
        }
        
        int ret = 0;
        if ((ret = select(fd + 1, &fds, NULL, NULL, &timeout)) < 0)
            return -1;
        else if (ret == 0)
            /* timed out */
            break;
#ifdef _WIN32
        if ( (nread = recv(fd, ptr, nleft, 0)) < 0)
#else
        if ( (nread = read(fd, ptr, nleft)) < 0)
#endif
	{
            if (errno == EINTR)
                nread = 0;		/* and call read() again */
            else
                return(-1);
        } else if (nread == 0)
            break;				/* EOF */

        nleft -= nread;
        ptr   += nread;
    }
    return(n - nleft);		/* return >= 0 */
}
/* end readn */

ssize_t
Readn(int fd, void *ptr, size_t nbytes, time_t wait)
{
	ssize_t		n;

	if ( (n = readn(fd, ptr, nbytes, wait)) < 0)
		warn("readn error: %s", SockLastErrmsg()());
	return(n);
}
#else

/* Rob's read function */
size_t Readn(socket_t fd, void *vptr, size_t n, time_t timeout) {
    ssize_t nread = 0;
    size_t bytes_read = 0;
    char    *ptr;
    fd_set fds;
    struct timeval tv;

    ptr = (char*)vptr;
    while (bytes_read < n) {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_usec = 0;
        tv.tv_sec = timeout;
        if (select(static_cast<int>(fd) + 1, &fds, nullptr, nullptr, &tv) <= 0)
            break;
#ifdef _WIN32
        if ( (nread = recv(fd, ptr, 1, 0)) < 0) {
#else
        if ( (nread = read(fd, ptr, 1)) < 0) {
#endif
	    warn("unexpected read: %d: %s", (int) nread, SockLastErrmsg()());
        } else if (nread == 0) {
            break;              /* EOF */
        } else if (nread == 1) {
            bytes_read++;
            ptr++;
        } else {
            warn("unexpected read: %d", (int) nread);
        }
    }
    return(bytes_read);
}
#endif

static ssize_t						/* Write "n" bytes to a descriptor. */
writen(socket_t fd, const void *vptr, size_t n)
{
    SEND_LEN_T nleft = safe_int<SEND_LEN_T>(n);
    SEND_RET_T nwritten;
    const char *ptr;

    ptr = (const char*)vptr;
    while (nleft > 0) {
	if ((nwritten = send(fd, ptr, nleft, 0)) <= 0) {
	    if (errno == EINTR) continue; // keep trying
	    return -1; // error
	}
	nleft -= safe_int<SEND_LEN_T>(nwritten);
	ptr   += nwritten;
    }
    return safe_int<ssize_t>(n);
}
/* end writen */

void
Writen(socket_t fd, const void *ptr, size_t nbytes)
{
	if (writen(fd, ptr, nbytes) != (ssize_t)nbytes)
		warn("writen error: %s", SockLastErrmsg()());
}


static int
my_read(socket_t fd, char *ptr)
{
	static ssize_t	read_cnt = 0;
	static char	*read_ptr;
	static char	read_buf[MAXMSGSIZE];

	if (read_cnt <= 0) {
again:
#ifdef _WIN32
		read_cnt = recv(fd, read_buf, sizeof(read_buf), 0);
#else
		read_cnt = read(fd, read_buf, sizeof(read_buf));
#endif
		if (read_cnt < 0) {
			if (errno == EINTR)
				goto again;
			return(-1);
		} else if (read_cnt == 0) 
			return(0);
		read_ptr = read_buf;
	}

	read_cnt--;
	*ptr = *read_ptr++;
	return(1);
}

static ssize_t
readline(socket_t fd, void *vptr, size_t maxlen)
{
	size_t	n;
	int	rc;
	char	c, *ptr;

	ptr = (char *)vptr;
	for (n = 1; n < maxlen; n++) {
		if ( (rc = my_read(fd, &c)) == 1) {
			*ptr++ = c;
			if (c == '\n')
				break;	/* newline is stored, like fgets() */
		} else if (rc == 0) {
			if (n == 1)
				return(0);	/* EOF, no data read */
			else
				break;		/* EOF, some data was read */
		} else
			return(-1);		/* error, errno set by read() */
	}

	*ptr = 0;	/* null terminate like fgets() */
	return safe_int<ssize_t>(n);
}
/* end readline */

ssize_t
Readline(socket_t fd, void *ptr, size_t maxlen)
{
	ssize_t		n;

	if ( (n = readline(fd, ptr, maxlen)) < 0)
		warn("readline error: %s", SockLastErrmsg()());
    if (n == 0)
        printf("** server terminated prematurely");
	return(n);
}

/* New socket wrapper */
socket_t newSocket(family_t family, int type, int proto) {
    socket_t sock = 0;

    if ((sock = socket(family, type, proto)) == INVALID_SOCKET)
        warn("create socket failed: %s", SockLastErrmsg()());
    return (sock);
}

int setSockTTL(family_t family, socket_t sock, int val)
{
    if (family == AF_INET6)
	return setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&val, sizeof(val));
    else
	return setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&val, sizeof(val));
}

int getSockTTL(family_t family, socket_t sock, int *val)
{
    socklen_t size = sizeof(*val);
    if (family == AF_INET6)
	return getsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)val, &size);
    else
	return getsockopt(sock, IPPROTO_IP, IP_TTL, (char *)val, &size);
}

int optSocketHDRINCL(socket_t sock) {
#ifdef _WIN32
    BOOL on = TRUE;
#else
    int on = 1;
#endif

    int ret = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));
    if (ret < 0)
        severe("setsockopt IP_HDRINCL: %s", SockLastErrmsg()());
    return ret;
}

int socketSend(socket_t sock, const void *msg, size_t len,
    struct probe_info *pinfo)
{
    if (pinfo->spoof) {
	severe("internal error: socketSend() with pinfo->spoof==true");
	return -1;
    }

#ifdef HAVE_PCAP
    if (!pinfo->sniffer && (
	// need verification
	(always_verify && !pinfo->layer_sniffed) ||
	// need linkhdr
	(spoof_layer(pinfo->dst_sa) != 3 && pinfo->rtinfo &&
	    !pinfo->rtinfo->linkhdr)))
    {
	init_sniffer(pinfo);
    }
#endif

    pinfo->layer_sent = 4;
    debug(DEVELOP, ">> socketSend: send %zd bytes to %s port %d\n",
	len, ntopBuf(pinfo->dst_sa)(), ntohs(sa_port(pinfo->dst_sa)));

    // On FreeBSD connected datagram sockets, an ICMP error response to an
    // earlier packet is reported as an error in the next use of the socket
    // (see: SO_ERROR in man getsockopt).  We don't want to count those
    // external errors as send failure, so we use SO_ERROR to clear errors
    // before the next send().  Note, there's still a tiny chance of receiving
    // an ICMP response between SO_ERROR and send().  We could ignore certain
    // error code values from send(), but that would open a maze of #ifdefs
    // and platform-specific interpretations of error codes.  (An alternate
    // solution would be to open a new socket for every packet.)
    char ebuf[256];
    if (getSockErr(sock, ebuf, sizeof(ebuf))) {
	debug(DEVELOP, ">> socketSend: %s port %d: ignoring async error: %s\n",
	    ntopBuf(pinfo->dst_sa)(), ntohs(sa_port(pinfo->dst_sa)),
	    ebuf);
    }
    // sock is already connect()ed, so we don't need sendto() with a dest (and
    // BSD would fail if we supplied one, even if it's the same).
    if (send(sock, (const char*)msg, safe_int<SEND_LEN_T>(len), 0) >= 0) {
	pinfo->setStatus(UNCONFIRMED);
	return 0;
    } else {
	pinfo->setStatus(SENDFAIL);
	return -1;
    }
}

int socketSendSpoof(socket_t spoofsock, socket_t udpsock, const void *msg,
    size_t len, struct probe_info *pinfo)
{
    struct probe_info *pilot_pinfo = nullptr;
    const sockaddr *dst = pinfo->dst_sa;
    ssize_t rc;

    if (!pinfo->spoof) {
	severe("internal error: socketSendSpoof() with pinfo->spoof==false");
	return -1;
    }

    // Note: If spoof_layer==0, the first thread to sniff a spoofed probe will
    // set it, which may affect other threads.  In older versions, we'd block
    // other threads in that case, which was especially slow if our dest was
    // unroutable:  we'd hold the lock through sniffer timeouts for both the
    // L3 spoof and the L2 spoof's pilot.  Now, other threads aren't blocked;
    // furthermore, one will likely succeed and set spoof_layer=3 fast enough
    // that we'll know to not bother trying L2.

    debug(DEVELOP, ">> socketSendSpoof: layer %d\n", spoof_layer(dst));

    if (pinfo->rtinfo && pinfo->rtinfo->linklen == route_info::FAILED) {
	// Sniffing failed for a non-spoofed packet to same destination.
	// We can't even try L2 spoofing without the linkhdr.
	// We _could_ try L3 spoofing, but it would be a waste of time; and it's
	// better to leave the status at UNTRIED, not UNCONFIRMED.
	if (!pinfo->warnedSkipSpoof || verbosity >= DEVELOP)
	    info("skipping spoof to %s where non-spoof failed%s",
		ntopBuf(dst)(), pinfo->warnedSkipSpoof ? " (debug)" : "");
	pinfo->warnedSkipSpoof = true;
	goto error;
    }

    if (!pinfo->rtinfo || !pinfo->rtinfo->ifinfo) {
	// use the pilot socket to fill in rtinfo and ifinfo
	pilot_pinfo =
	    new_probe_info(IPPROTO_UDP, false, udpsock, nullptr, pinfo->dst_sa);
	if (!pilot_pinfo) goto error;
	pinfo->rtinfo = pilot_pinfo->rtinfo;
    }

    // Try L3 (raw IP), if we haven't already ruled it out
    if (spoofsock != INVALID_SOCKET &&
	(spoof_layer(dst) == 0 || spoof_layer(dst) == 3))
    {
	pinfo->layer_sent = 3;
	debug(DEVELOP, ">> socketSendSpoof: sendto %zd bytes to %s port %d\n",
	    len, ntopBuf(dst)(), ntohs(sa_port(dst)));

#ifdef HAVE_PCAP
	if (spoof_layer(dst) == 0) {
	    printf("Attempting to spoof IPv%d with raw ip (L3)\n",
		familytoipv(dst->sa_family));
	    init_sniffer(pinfo); // to verify that L3 spoofing works
	} else if ((always_verify && !pinfo->layer_sniffed)) {
	    init_sniffer(pinfo); // to verify this pinfo
	}
#endif

#ifdef _BSD /* BSD raw (ip) sockets expect ip_len and ip_off in host order */
	uint32_t *bsd_msg = new uint32_t[(len+3)/4]; // uint32 for alignment
	memcpy(bsd_msg, msg, len);
	struct ip *ip = (struct ip *)bsd_msg;
	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_off = ntohs(ip->ip_off);
	rc = sendto(spoofsock, bsd_msg, len, 0, dst, sa_len(dst));
	delete[] bsd_msg;
#else
	rc = sendto(spoofsock, (const char*)msg, safe_int<SEND_LEN_T>(len), 0, dst, sa_len(dst));
#endif

	if (rc < 0) {
	    warn("send (L3) to %s: %s", ntopBuf(dst)(), SockLastErrmsg()());
	    pinfo->setStatus(SENDFAIL);
	    if (spoof_layer(dst) < 3) goto rawlinklayer;
	    goto error;
	}
	pinfo->setStatus(UNCONFIRMED);

	// Sendto did not report an error.
#ifdef HAVE_PCAP
	if (!pinfo->sniffer) {
	    debug(DEVELOP, "not sniffing\n");
	} else if (spoof_layer(dst) >= 3) {
	    // Layer is already known; defer sniffing til free_probe_info()
	    debug(DEVELOP, "defer sniffing\n");
	} else {
	    debug(DEVELOP, "sniffing\n");
	    // Sniff the packet to make sure it was transmitted intact.
	    if (spoofer_pcap_dispatch(pinfo, "socketSendSpoof") < 0)
		goto error;
	    if (pinfo->layer_sniffed <= 0) { // did not sniff this packet
		if (spoof_layer(dst) != 3) goto rawlinklayer; // L2 might work
		goto error; // L3 worked for others, so don't bother trying L2
	    }
	}
#else // HAVE_PCAP
	// Can't sniff; assume L3 spoofing worked.  (We can't try L2 anyway.)
#endif // HAVE_PCAP
	if (pilot_pinfo)
	    free_probe_info(pilot_pinfo, true);
	return 0;
    }

rawlinklayer:
#ifdef HAVE_PCAP_SENDPACKET
    if (spoof_layer(dst) != 2)
	printf("Attempting to spoof IPv%d with raw link (L2)\n",
	    familytoipv(dst->sa_family));

    if (pinfo->rtinfo && pinfo->rtinfo->linklen == route_info::FAILED) {
	// Sniffing failed for a non-spoofed packet to same destination.
	// We can't even try L2 spoofing without the linkhdr.
	info("%s: Couldn't find route to host", ntopBuf(dst)());
	goto error;
    }

    if (!pinfo->rtinfo || !pinfo->rtinfo->linkhdr) {
	debug(DEVELOP, "%s: No known route to host; sending pilot packet\n",
	    ntopBuf(dst)());
	if (!pilot_pinfo)
	    pilot_pinfo =
		new_probe_info(IPPROTO_UDP, false, udpsock, nullptr, pinfo->dst_sa);
	if (!pilot_pinfo) goto error;
	bool skipSniffing = false;
        if (socketSend(udpsock, "", 0, pilot_pinfo) < 0) {
	    debug(DEVELOP, "pilot to %s: %s\n", ntopBuf(dst)(),
		SockLastErrmsg()());
	    skipSniffing = true; // no need to sniff after send failed
	}

	pinfo->rtinfo = pilot_pinfo->rtinfo;
	free_probe_info(pilot_pinfo, skipSniffing);
	pilot_pinfo = nullptr;
	if (!pinfo->rtinfo || !pinfo->rtinfo->linkhdr) {
	    info("%s: Can't find route to host", ntopBuf(dst)());
	    goto error;
	}
	debug(DEVELOP, "%s: pilot packet successful\n", ntopBuf(dst)());
    }

    u_char pktbuf[BIGBUF]; // link layer PDU
    // Copy previously sniffed link header into new packet.  (This won't work
    // if link header includes a checksum or other payload-dependent fields.)
    memcpy(pktbuf, pinfo->rtinfo->linkhdr, pinfo->rtinfo->linklen);
    memcpy(pktbuf + pinfo->rtinfo->linklen, msg, len);

    if (!pinfo->writer) {
	debug(DEVELOP, ">> pcap_open_live\n");
	char errbuf[PCAP_ERRBUF_SIZE];
	pinfo->writer = pcap_open_live(pinfo->rtinfo->ifinfo->ifname, 0, 0, 0, errbuf);
	if (!pinfo->writer) {
	    printf("ERROR: pcap_open_live: %s", errbuf);
	    return -1;
	}
	if (verbosity >= DEVELOP) {
	    printf("L2 (%s) PDU:\n", pinfo->dlt_str());
	    binDump(pktbuf, pinfo->rtinfo->linklen + len, TRUE);
	}
    }

    pinfo->layer_sent = 2;
    if (always_verify && !pinfo->layer_sniffed)
	init_sniffer(pinfo); // sniff spoofed pkt

    debug(DEVELOP, ">> socketSendSpoof: pcap_sendpacket %zd bytes to %s port %d\n",
	len, ntopBuf(dst)(), ntohs(sa_port(dst)));
    rc = pcap_sendpacket(pinfo->writer, pktbuf,
	safe_int<int>(pinfo->rtinfo->linklen + len));
    if (rc < 0) {
	print_pcap_error(pinfo->writer, rc, "pcap_sendpacket (L2) on %s to %s",
	    pinfo->rtinfo->ifinfo->ifname, ntopBuf(dst)());
	return -1;
    }

    if (!pinfo->sniffer) {
	debug(DEVELOP, "not sniffing\n");
    } else if (spoof_layer(dst) >= 2) {
	// Layer is already known; defer sniffing til free_probe_info()
	debug(DEVELOP, "defer sniffing\n");
    } else {
	// Sniff the packet to make sure it was transmitted intact.
	debug(DEVELOP, "sniffing\n");
	if (spoofer_pcap_dispatch(pinfo, "socketSendSpoof") < 0)
	    return -1;
	return pinfo->layer_sniffed > 0 ? 0 : -1;
    }
    return 0; // assume it worked

#else // !HAVE_PCAP_SENDPACKET
    warn("Can not test spoofing at link layer.  Recompile with a modern version of "
	"libpcap that has pcap_sendpacket().");
#endif // HAVE_PCAP_SENDPACKET
error:
    if (pilot_pinfo)
	free_probe_info(pilot_pinfo, true);
    return -1;
}

#ifndef HAVE_INET_PTON
static int inet_pton4(const char *src, struct in_addr *dst)
{
	int octet;
	unsigned int num;
	const char *p, *off;
	uint8_t tmp[4];
	static const char digits[] = "0123456789";

	octet = 0;
	p = src;
	while (1) {
		num = 0;
		while (*p && ((off = strchr(digits, *p)) != NULL)) {
			num *= 10;
			num += (off - digits);

			if (num > 255) return 0;

			p++;
		}
		if (!*p) break;

		/*
		 *	Not a digit, MUST be a dot, else we
		 *	die.
		 */
		if (*p != '.') {
			return 0;
		}

		tmp[octet++] = num;
		p++;
	}

	/*
	 *	End of the string.  At the fourth
	 *	octet is OK, anything else is an
	 *	error.
	 */
	if (octet != 3) {
		return 0;
	}
	tmp[3] = num;

	memcpy(dst, &tmp, sizeof(tmp));
	return 1;
}


#ifdef HAVE_STRUCT_SOCKADDR_IN6
/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
static int
inet_pton6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[IPV6ADDRLEN], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	u_int val;

	memset((tp = tmp), 0, IPV6ADDRLEN);
	endp = tp + IPV6ADDRLEN;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			if (tp + 2> endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + IPV4ADDRLEN) <= endp) &&
		    inet_pton4(curtok, (struct in_addr *) tp) > 0) {
			tp += IPV4ADDRLEN;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + 2 > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	/* bcopy(tmp, dst, IN6ADDRSZ); */
	memcpy(dst, tmp, IPV6ADDRLEN);
	return (1);
}
#endif

/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
int inet_pton(int af, const char *src, void *dst)
{
	if (af == AF_INET) {
		return inet_pton4(src, (struct in_addr*)dst);
	}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (af == AF_INET6) {
		return inet_pton6(src, (unsigned char*)dst);
	}
#endif

	return -1;
}
#endif


#ifndef HAVE_INET_NTOP
/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
const char *inet_ntop(int af, const void *src, char *dst, size_t cnt)
{
	if (af == AF_INET) {
		const uint8_t *ipaddr = (const uint8_t *)src;

		if (cnt <= INET_ADDRSTRLEN) return NULL;

		snprintf(dst, cnt, "%d.%d.%d.%d",
			 ipaddr[0], ipaddr[1],
			 ipaddr[2], ipaddr[3]);
		return dst;
	}

	/*
	 *	If the system doesn't define this, we define it
	 *	in missing.h
	 */
	if (af == AF_INET6) {
		const struct in6_addr *ipaddr = (const struct in6_addr *)src;

		if (cnt <= INET6_ADDRSTRLEN) return NULL;

		snprintf(dst, cnt, "%x:%x:%x:%x:%x:%x:%x:%x",
			 (ipaddr->s6_addr[0] << 8) | ipaddr->s6_addr[1],
			 (ipaddr->s6_addr[2] << 8) | ipaddr->s6_addr[3],
			 (ipaddr->s6_addr[4] << 8) | ipaddr->s6_addr[5],
			 (ipaddr->s6_addr[6] << 8) | ipaddr->s6_addr[7],
			 (ipaddr->s6_addr[8] << 8) | ipaddr->s6_addr[9],
			 (ipaddr->s6_addr[10] << 8) | ipaddr->s6_addr[11],
			 (ipaddr->s6_addr[12] << 8) | ipaddr->s6_addr[13],
			 (ipaddr->s6_addr[14] << 8) | ipaddr->s6_addr[15]);
		return dst;
	}

	return NULL;		/* don't support IPv6 */
}
#endif
