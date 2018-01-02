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
   Program:     $Id: spoof.h,v 1.129 2017/12/01 18:33:25 kkeys Exp $
   Date:        $Date: 2017/12/01 18:33:25 $
   Description: spoofer header
                Should be included after system and third-party headers,
                but before any other spoofer headers.
****************************************************************************/

#include "config.h"

#ifdef HAVE_PTHREAD
# include <pthread.h>
#endif

#ifndef COMMON_SPOOF_H
#define COMMON_SPOOF_H 1

// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wshadow"
#include "spoofer.pb.h"
// #pragma GCC diagnostic pop

#ifdef _WIN32
  #define NOGDI // prevents <wingdi.h> from polluting our namespace
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <unistd.h>
  #include <stdint.h>
  #undef HAVE_NETINET_IP_H
  #undef HAVE_IN_ADDR_T
  #if _WIN32_WINNT >= _WIN32_WINNT_VISTA  // Vista does have these functions
    #define HAVE_INET_PTON
    #define HAVE_INET_NTOP
    // Fix the missing "const" in the Windows declaration of inet_ntop().
    #define inet_ntop(f, a, b, s) \
      (inet_ntop)(f, const_cast<void*>(static_cast<const void*>(a)), b, s)
  #endif
  typedef SOCKET socket_t; // SOCKET is defined by winsock (an unsigned integer)
  // INVALID_SOCKET is defined by winsock (maximum value of its type)
  // closesocket() is defined by winsock (close() does not work on sockets)
  #define SEND_RET_T int  // return type of send()/sendto()
  #define SEND_LEN_T int  // type of length parameter of send()/sendto()
#else
  #include <sys/types.h>
  #ifndef __FAVOR_BSD
    #define  __FAVOR_BSD
  #endif
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netinet/in_systm.h>
  #include <netinet/ip.h>
  #ifdef HAVE_NETINET_IP6_H
    #include <netinet/ip6.h>
  #endif
  #include <netdb.h>
  // Winsock compatibility
  typedef int socket_t;
  #define INVALID_SOCKET -1
  #define closesocket(fd) close(fd)
  #define SEND_RET_T ssize_t  // return type of send()/sendto()
  #define SEND_LEN_T size_t   // type of length parameter of send()/sendto()
#endif

/* The UDP header layout is an universal standard, not OS-specific, so it makes
 * more sense to define our own copy than to depend on differently-named
 * definitions provided by the host OS. */
struct udphdr
{
  uint16_t uh_sport;           /* source port */
  uint16_t uh_dport;           /* destination port */
  uint16_t uh_ulen;            /* udp length */
  uint16_t uh_sum;             /* udp checksum */
};

#include <cstdio>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <climits> // INT_MAX, etc
#ifdef HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#include "port.h"  // after system headers
#include "safe_int.h"
#include "messages.h"

#define VERBOSE 0
//#define REGRESS 1
#ifdef REGRESS
#undef VERSION
#define VERSION 99
#endif

#define BUFSIZE 1500
#define SMALLBUF 80
#define BIGBUF 9000
#define MAXMSGSIZE 4096
#define LISTENQ 1024

#define TTL_OUT 64
#define SRC_PORT 5353
#define CLIENT_TIMEOUT 60

#define TEST_SERVER "192.172.226.236"
#define TEST_SERVER6 "2001:48d0:101:501::236"
#define TEST_REPORT_HOST "spoofer-test.caida.org"

#define PROD_SERVER "192.172.226.242"
#define PROD_SERVER6 "2001:48d0:101:501::242"
#define PROD_REPORT_HOST "spoofer.caida.org"

#if 0
// testing
 #define SERVER TEST_SERVER
 #define SERVER6 TEST_SERVER6
 #define REPORT_HOST TEST_REPORT_HOST
#else
// production
 #define SERVER PROD_SERVER
 #define SERVER6 PROD_SERVER6
 #define REPORT_HOST PROD_REPORT_HOST
#endif

extern const std::string *pbs_magic;

#if 0
  #define SERV_PORT 5353
  #define REPORT_PORT_SSL 4443
  #define REPORT_PORT_CLEAR 8080
  #define ICMP_DIVERT_PORT 3002 
  #define UDP_DIVERT_PORT 3003 
#else
  #define SERV_PORT 53
  #define REPORT_PORT_SSL 443
  #define REPORT_PORT_CLEAR 80
  #define ICMP_DIVERT_PORT 2002 
  #define UDP_DIVERT_PORT 2003 
#endif

#ifndef FALSE
 #define FALSE 0
 #define TRUE !FALSE
#endif

#ifndef HAVE_NETINET_IP_H
/*
 * Structure of an internet header, naked of options.
 */
struct ip {
#ifdef _IP_VHL
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
#else
	/* Note: the base type of ip_hl and ip_v must be an 8-bit type, since
	 * some compilers (at least mxe/mingw gcc 5.1.0) allocate the full
	 * size of the base type. */
#ifdef HAVE_BIG_ENDIAN
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#else
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#endif
#endif /* not _IP_VHL */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#endif /* HAVE_NETINET_IP_H */

STATIC_ASSERT(sizeof(struct ip) == 20, struct_ip_is_not_20_bytes);

enum IPv { IPv4 = 4, IPv6 = 6 };

#ifdef HAVE_SA_FAMILY_T
typedef sa_family_t family_t;
#else
typedef uint16_t family_t;
#endif

#ifndef HAVE_NETINET_IP6_H
/* RFC 3542 */
struct ip6_hdr {
    union {
        struct ip6_hdrctl {
            uint32_t ip6_un1_flow; /* 4 bits version, 8 bits TC, 20 bits
                                      flow-ID */
            uint16_t ip6_un1_plen; /* payload length */
            uint8_t  ip6_un1_nxt;  /* next header */
            uint8_t  ip6_un1_hlim; /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;     /* 4 bits version, top 4 bits
                                    tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src;   /* source address */
    struct in6_addr ip6_dst;   /* destination address */
};

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

#endif /* HAVE_NETINET_IP6_H */

STATIC_ASSERT(sizeof(struct ip6_hdr) == 40, struct_ip6_hdr_is_not_40_bytes);

#ifndef HAVE_INET_PTON
int inet_pton(int af, const char *src, void *dst);
#endif
#ifndef HAVE_INET_NTOP
const char *inet_ntop(int af, const void *src, char *dst, size_t cnt);
#endif

#ifndef HAVE_STRUCT_SOCKADDR_IN6
struct in6_addr
{
  uint8_t 	  s6_addr[16];
};

struct sockaddr_in6
{
  sa_family_t	  sin6_family;		/* AF_INET6 */
  in_port_t	  sin6_port;		/* Port number. */
  uint32_t	  sin6_flowinfo;	/* Traffic class and flow inf. */
  struct in6_addr sin6_addr;		/* IPv6 address. */
  uint32_t	  sin6_scope_id;	/* Set of interfaces for a scope. */
};
#endif

#ifndef IPVERSION
 #define IPVERSION 4
#endif

#ifndef IP_DF
 #define IP_DF 0x4000
#endif

#ifndef AF_INET6
 #define AF_INET6 10
#endif


// get a ref to the port part of a sockaddr_{in,in6} (in network order)
static inline uint16_t &sa_port(sockaddr *sa)
{
    static uint16_t zero = 0;
    if (sa->sa_family == AF_INET)
        return (reinterpret_cast<sockaddr_in *>(sa))->sin_port;
    if (sa->sa_family == AF_INET6)
        return (reinterpret_cast<sockaddr_in6 *>(sa))->sin6_port;
    return zero; // shouldn't happen
}

// get the port part of a const sockaddr_{in,in6} (in network order)
static inline uint16_t sa_port(const sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return (reinterpret_cast<const sockaddr_in *>(sa))->sin_port;
    if (sa->sa_family == AF_INET6)
        return (reinterpret_cast<const sockaddr_in6 *>(sa))->sin6_port;
    return 0; // shouldn't happen
}

/* get a pointer to the IP address part of a sockaddr_{in,in6} */
static inline char *sa_ipaddr(sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return reinterpret_cast<char *>(&(reinterpret_cast<sockaddr_in *>(sa))->sin_addr);
    if (sa->sa_family == AF_INET6)
        return reinterpret_cast<char *>(&(reinterpret_cast<sockaddr_in6 *>(sa))->sin6_addr);
    return nullptr;
}

/* get a pointer to the IP address part of a const sockaddr_{in,in6} */
static inline const char *sa_ipaddr(const sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return reinterpret_cast<const char *>(&(reinterpret_cast<const sockaddr_in *>(sa))->sin_addr);
    if (sa->sa_family == AF_INET6)
        return reinterpret_cast<const char *>(&(reinterpret_cast<const sockaddr_in6 *>(sa))->sin6_addr);
    return nullptr;
}

// get the size of a const sockaddr_{in,in6}
static inline uint16_t sa_len(const sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
        return sizeof(struct sockaddr_in);
    if (sa->sa_family == AF_INET6)
        return sizeof(struct sockaddr_in6);
    return 0;
}

static inline unsigned int addrlen(const family_t &family)
{
    return
	(family == AF_INET6) ? IPV6ADDRLEN :
	(family == AF_INET) ? IPV4ADDRLEN :
	0;
}

static inline unsigned int familytoipv(const family_t &family)
{
    return
	(family == AF_INET6) ? IPv6 :
	(family == AF_INET) ? IPv4 :
	0;
}

static inline family_t ipvtofamily(const IPv &ipv) {
    return
	(ipv == IPv6) ? AF_INET6 :
	(ipv == IPv4) ? AF_INET :
	0;
}


/* get pointer to address within an old-style right-aligned address buffer */
#define right_addr(family, addr) \
    (((unsigned char*)addr) + IPV6ADDRLEN - addrlen(family))


/* prettyprint */
#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]

// nptohl(p) is Like ntohl(*p), but does not require p to be aligned.
#define nptohl(p) \
    (static_cast<uint32_t>( \
	(((const uint8_t*)p)[0] << 24) | \
	(((const uint8_t*)p)[1] << 16) | \
	(((const uint8_t*)p)[2] << 8) | \
	(((const uint8_t*)p)[3])))

// htonpl(p,n) is like *p = htonl(n), but does not require p to be aligned.
#define htonpl(p, n) \
    do { \
	(((uint8_t*)p))[0] = (uint8_t)((n >> 24) & 0xFF); \
	(((uint8_t*)p))[1] = (uint8_t)((n >> 16) & 0xFF); \
	(((uint8_t*)p))[2] = (uint8_t)((n >> 8) & 0xFF); \
	(((uint8_t*)p))[3] = (uint8_t)(n & 0xFF); \
    } while (0)

// nptohs(p) is Like ntohs(*p), but does not require p to be aligned.
#define nptohs(p) \
    (static_cast<uint16_t>( \
	(((const uint8_t*)p)[0] << 8) | \
	(((const uint8_t*)p)[1])));

// Interpret ptr as a pointer to type, and return a pointer to ptr->field.
// *ptr does not need to be aligned.
#define ua_field(type, ptr, field) \
    (((const uint8_t*)ptr) + offsetof(type, field))

/* error messages */
#define tracefunc() \
    do { \
	if (verbosity >= DEVELOP) \
	    fprintf(stdout, "\t>> %s:%s():%d\n", __FILE__, __FUNCTION__, __LINE__); \
    } while (0)

// printf with a prefix and newline.  We use an internal buffer so that writes
// (up to a certain size) will be atomic.
#define pprintf(prefix, ...) \
    do { \
	int n1 = snprintf(nullptr, 0, "*** %s: ", prefix); \
	int n2 = snprintf(nullptr, 0, __VA_ARGS__); \
	if (n1 < 0 || n2 < 0) break; \
	char *ppbuf = new char[safe_int<size_t>(n1+n2+2)]; \
	sprintf(ppbuf, "*** %s: ", prefix); \
	sprintf(ppbuf+n1, __VA_ARGS__); \
	sprintf(ppbuf+n1+n2, "\n"); \
	fputs(ppbuf, stdout); \
	delete[] ppbuf; \
    } while (0)

#define info(...)   pprintf("Info", __VA_ARGS__)    // not displayed in gui
#define notice(...) pprintf("Notice", __VA_ARGS__)  // displayed in gui
#define warn(...)   pprintf("Warning", __VA_ARGS__) // displayed in gui
#define severe(...) pprintf("Error", __VA_ARGS__)   // displayed in gui

#define debug(level, ...) \
    do { if (verbosity >= level) fprintf(stdout, __VA_ARGS__); } while (0)

enum debugLevel {OFF, LOW, HIGH, DEVELOP};
extern int verbosity;

typedef void Sigfunc(int);

// A mutex object that does nothing if HAVE_PTHREAD is not defined.
class OptMutex {
#ifdef HAVE_PTHREAD
    pthread_mutex_t mutex;
public:
    OptMutex() : mutex() { pthread_mutex_init(&mutex, nullptr); }
    void lock() { pthread_mutex_lock(&mutex); }
    void unlock() { pthread_mutex_unlock(&mutex); }
#else
public:
    void lock() {}
    void unlock() {}
#endif
};

// RAII-style scoped mutex wrapper (similar to C++11 std::lock_guard), plus
// unlock() to manually unlock early (like C++11 std::unique_lock)
class LockGuard {
    LockGuard(const LockGuard&) NO_METHOD;
    OptMutex &m;
    bool locked;
public:
    LockGuard(OptMutex &mutex) : m(mutex), locked(true) { m.lock(); }
    ~LockGuard() { if (locked) m.unlock(); }
    void unlock() { m.unlock(); locked = false; }
};

/* net.cc */

static const char * const probeStatusStr[] =
    { "UNTRIED", "SENDFAIL", "UNCONFIRMED", "REWRITTEN", "CONFIRMED" };
enum ProbeStatus { UNTRIED, SENDFAIL, UNCONFIRMED, REWRITTEN, CONFIRMED };

extern int spoof_layer[];
typedef struct probe_info probe_info_t;
const char *sock_errmsg(int err, char *buf = nullptr, size_t buflen = 0);
const char *sock_last_errmsg(char *buf = nullptr, size_t buflen = 0);

// Convenient shorthand for using sock_last_errmsg() with a buffer, for thread
// safety.
class SockLastErrmsg {
    char buf[256];
public:
    SockLastErrmsg() { sock_last_errmsg(buf, sizeof(buf)); }
    const char *operator()() { return buf; }
};

#ifdef HAVE_LIBSSL
void ssl_err(const char *str);
void ssl_io_error(SSL *ssl, int ret, const char *str);
#endif
void dump_ifaces();
size_t craftPacket(uint32_t *, const void *, size_t, 
    const sockaddr *, const sockaddr *, u_char, unsigned short) ATR_NONNULL();
void craftProbe(probe_t *probe, bool spoof, const SpooferSpoofSchedule::Item *item) ATR_NONNULL();
unsigned short in_cksum(const void *, size_t);
char * genSequence(char *, int) ATR_NONNULL();
Sigfunc *Signal(int signo, Sigfunc *func);
void sig_chld(int signo);
size_t Readn(socket_t fd, void *ptr, size_t nbytes, time_t timeout) ATR_NONNULL();
void Writen(socket_t fd, const void *ptr, size_t nbytes) ATR_NONNULL();
ssize_t Readline(socket_t fd, void *ptr, size_t maxlen) ATR_NONNULL();
ssize_t readn(socket_t fd, void *vptr, size_t n, time_t wait) ATR_NONNULL();
bool spoof_layer2possible(const IPv &ipv);
socket_t newSocket(family_t, int, int);
int getSockTTL(family_t family, socket_t sock, int *val) ATR_NONNULL();
int setSockTTL(family_t family, socket_t sock, int val);
int optSocketHDRINCL(socket_t);
struct probe_info *new_probe_info(int proto, bool spoof, socket_t sock,
    sockaddr *src_sa, const sockaddr *dst_sa) ATR_NONNULL((5));
int socketSend(socket_t, const void *, size_t, struct probe_info *) ATR_NONNULL();
int socketSendSpoof(socket_t, socket_t, const void *, size_t, struct probe_info *) ATR_NONNULL();
enum ProbeStatus free_probe_info(struct probe_info *pinfo, bool skipSniffing = false) ATR_NONNULL();
bool initSockets(bool spoof, IPv ipv, socket_t& spoofsock, socket_t& udpsock,
    const sockaddr *src, const sockaddr *dst);
const char *getSockErr(socket_t sock, char *buf = nullptr, size_t buflen = 0);
bool closeSocket(socket_t &sock, IPv ipv);
const char *sa_ntop(const sockaddr *sa, char *dst = nullptr, size_t len = INET6_ADDRSTRLEN+1) ATR_NONNULL((1));

// Convenient shorthand for using sa_ntop() with a buffer, for thread safety.
class ntopBuf {
    char pbuf[INET6_ADDRSTRLEN+1];
public:
    ntopBuf(const sockaddr *sa) { sa_ntop(sa, pbuf, sizeof(pbuf)); }
    const char *operator()() { return pbuf; }
};

/* util.cc */
void spoofer_rand_stir();
unsigned long spoofer_rand(unsigned long max);
void binDump(const void *msg, size_t len, int pretty, const char *prefix = nullptr) ATR_NONNULL((1));
void win_init(void);
void msleep(unsigned int msec);
void spoofSleep(void);

#ifdef _WIN32
int spoofer_snprintf(char *buf, size_t size, const char *fmt, ...) FORMAT_PRINTF(3, 4);
#undef snprintf // in case WinPcap's pcap.h defined it
#define snprintf spoofer_snprintf // replace Windows' broken snprintf()
#endif
int is_interactive(void);
NORETURN void exitpause(int status);
NORETURN void fatal(const char *, ...) FORMAT_PRINTF(1, 2);
NORETURN void pfatal(const char *, ...) FORMAT_PRINTF(1, 2);
void streamSetup(void);
char *timestring(void); // Uses static buffer - not threadsafe!
uint32_t n6ton4(const unsigned char *addr) ATR_PURE ATR_NONNULL();
uint32_t n6toh4(const unsigned char *addr) ATR_PURE ATR_NONNULL();
int n4ton6(const uint32_t ip, unsigned char *addr) ATR_PURE ATR_NONNULL();
int h4ton6(const uint32_t ip, unsigned char *addr) ATR_PURE ATR_NONNULL();
int n6tohexstring(const unsigned char *addr, char *res) ATR_NONNULL();
int isIPv4(const unsigned char *addr) ATR_PURE ATR_NONNULL();
int isIPv6(const unsigned char *addr) ATR_PURE ATR_NONNULL();
char *printIPv6(const unsigned char *a) ATR_NONNULL();
int isIPv6Equal(const unsigned char *a1, const unsigned char *a2) ATR_PURE ATR_NONNULL();
const char *strstrPortable(const char *a, const char *b, size_t n) ATR_PURE ATR_NONNULL();

// example:   printf("time: %s\n", gmTimeStr()());
class gmTimeStr {
    char buf[40]; // each gmTimeStr object has its own buffer
public:
    gmTimeStr(const time_t *tp = nullptr, const char *fmt = nullptr) {
	time_t t;
	if (!tp) { time(&t); tp = &t; }
	strftime(buf, sizeof(buf), fmt ? fmt : "%Y-%m-%d %H:%M:%S", gmtime(tp));
    }
    const char *operator()() { return buf; }
};

/* spoofer_pb_enum.cc */
template<class T>
struct EnumName {
    const T id;
    const char * const name;
};

template<class T>
struct EnumNames : public std::vector<EnumName<T> > {
    // Note: we avoid initializer_list because clang 3.2 doesn't implement it
    EnumNames(const EnumName<T> *first, const EnumName<T> *last) :
	std::vector<EnumName<T> >(first, last) {}

    // Return the name for an id.
    const char *fromId(T id) const {
	static char buf[32];
	for (auto entry : *this) {
	    if (id == entry.id)
		return entry.name; // success
	}
	sprintf(buf, "unknown(%d)", id);
	return buf; // failure
    }

    // Look up the id for a name.
    bool toId(const char *name, T &id) const {
	for (auto entry : *this) {
	    if (strcasecmp(name, entry.name) == 0) {
		id = entry.id;
		return true; // success
	    }
	}
	return false; // failure
    }
}; 

extern const EnumNames<SpooferSpoofReport_Item_Status> names_SpoofReport_Item_Status;
extern const EnumNames<SpooferResultSummary::Result> names_ResultSummary_Result;
extern const EnumNames<SpooferTestType> names_TestType;
extern const EnumNames<SpooferReportStatus> names_ReportStatus;

/* messages.cc */
const char *pb_ntop(family_t family, const std::string &addr, char *buf, size_t buflen);
const char *pb_ntop(family_t family, const std::string &addr);
void printServerMsg(const SpooferServerMsg &msg, IPv ipv, time_t ts = 0);
void printClientMsg(const SpooferClientMsg &msg, IPv ipv, time_t ts = 0);
#if 0
char *msg_type_name(uint8_t typ);
void printAddressList(struct in_addr *iplist, int num);
void printMsg(unsigned char *, int);
spoof_msg_t *readMsg(int sock, unsigned char **message, enum msg_types);
void defaultMsg(spoof_msg_t *msg);
int errorRequest(unsigned char *);
int helloRequest(unsigned char *);
int reportRequest(unsigned char *msg, unsigned char *seqno, 
    unsigned char *src_addr, unsigned char *dst_addr, int nat, int ipv6);
int doneRequest(unsigned char *msg);
int probeRequest(unsigned char *msg, int v6);
int readProbeList(unsigned char *buf, test_t **testlistptr);
int traceFilterRequest(unsigned char *msg);
#endif

#include "spoofer_stdio.h"

#endif // COMMON_SPOOF_H
