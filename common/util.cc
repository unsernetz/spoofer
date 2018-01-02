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
   Program:     $Id: util.cc,v 1.53 2017/11/07 18:00:26 kkeys Exp $
   Author:      Rob Beverly <rbeverly at csail.mit.edu>
                Ken Keys, CAIDA
   Date:        $Date: 2017/11/07 18:00:26 $
   Description: Spoofer utility routines
****************************************************************************/
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h> // for open()
#include "spoof.h"
#ifdef HAVE_GETTIMEOFDAY
 #include <sys/time.h>
#endif

int verbosity = OFF;

static const std::string pbs_magic_array[] = {
    std::string("SPOOFER\n\n", 9), // preferred as of version 1.1.0 
    std::string("SPOOFER\0", 8), // used in version <= 1.0.8
    std::string() // sentry
};
const std::string *pbs_magic = pbs_magic_array;


#ifdef _WIN32
// Windows' snprintf() and vsnprintf() prior to VC2015 do not handle buffer
// overflow as specified by C99:
// - it doesn't write the terminating NUL
// - it returns -1 instead of the would-be string length
// - %n arguments past the overflow point will not be set
// Windows' sprintf_s() doesn't match either: it guarantees NUL-termination,
// but writes an empty string instead of as much as possible.
// This version fixes all the issues.
int spoofer_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    int n = -1;
    if (buf) {
	va_start(ap, fmt);
	n = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	buf[size-1] = '\0';
	if (n >= 0) return n; // success
    }
    // work around broken overflow handling
    va_start(ap, fmt);
    FILE *file = fopen("NUL", "w");
    if (!file) return n; // shouldn't happen
    n = vfprintf(file, fmt, ap); // returns correct length and sets %n arguments
    va_end(ap);
    fclose(file);
    return n;
}
#endif

int is_interactive(void)
{
#ifdef _WIN32
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE); 
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE); 
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) return 0;
    DWORD dummyMode;
    return GetConsoleMode(hIn, &dummyMode) && GetConsoleMode(hOut, &dummyMode);
#else
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
#endif
}

NORETURN void exitpause(int status) {
#ifdef _WIN32
    DWORD proclist[1];
    if (is_interactive() && GetConsoleProcessList(proclist, 1) <= 1) {
	// This console has no other processes; it will close when we exit.
	fprintf(stdout, "\nPress Enter to Exit.\n"); \
	fflush(stdout); \
	while (getchar() != '\n');
    }
#endif
    exit(status);
}

/**
 * Fatal error condition function 
 */
NORETURN void fatal(const char *fmt, ...) {
    va_list ap;
    fflush(stdout);
    va_start(ap, fmt);
    fprintf(stderr, "*** ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exitpause(-1);
}

/**
 * Fatal error condition function; prints error
 */
NORETURN void pfatal(const char *fmt, ...) {
    va_list ap;
    fflush(stdout);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, " ");
    perror("Error");
    va_end(ap);
    exitpause(-1);
}

/**
 * binDump -  Debug routine for examining raw packets/buffer/char strings 
 *
 * @param[in]   msg     pointer to message buffer
 * @param[in]   len     length of buffer to print
 * @param[in]   pretty  if true, pretty print
 * @param[in]   indent  prefix for each line (if pretty)
 */
void binDump(const void *msg, size_t len, int pretty, const char *prefix) {
    size_t i;
    const unsigned char *p = static_cast<const unsigned char*>(msg);
    // Use a buffer so print is atomic (if len is small enough)
    size_t buflen = !pretty ? len*2 + 1 :
	(len/16+1) * ((prefix ? strlen(prefix) : 0) + 51) + 2;
    char *buf = new char[buflen];
    int off = 0; // offset in buf
    for (i = 1; i <= len; i++) {
	if (pretty) {
	    if (prefix && (i-1)%16 == 0) off += sprintf(buf+off, "%s", prefix);
	    off += sprintf(buf+off, "%02x ", *p++);
	    if (i >= len) break;
	    if (i%16 == 0) buf[off-1] = '\n';
	    else if (i%4 == 0) buf[off++] = ' ';
	} else {
	    off += sprintf(buf+off, "%02x", *p++);
	}
    }
    if (pretty) buf[off++] = '\n';
    buf[off++] = '\0';
    fputs(buf, stdout);
    delete[] buf;
}

/**
 * win_init -  Windows socket API startup 
 */
#ifdef _WIN32
void win_init(void) {
    WSADATA wsd;
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
        fatal("WSAStartup() failed");
    }
}
#endif

/**
 * Pseudo-random number generator
 */

void spoofer_rand_stir()
{
#if defined(HAVE_ARC4RANDOM)
    arc4random_stir();
#elif defined(HAVE_SRANDOMDEV)
    srandomdev();
#else
    unsigned int seed = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
	if (read(fd, &seed, sizeof(seed)) < (ssize_t)sizeof(seed))
	    seed = 0;
	close(fd);
    }
    if (!seed) {
 #if defined(HAVE_GETTIMEOFDAY)
	struct timeval tv;
	gettimeofday(&tv, 0);
	seed = static_cast<unsigned int>(tv.tv_sec * tv.tv_usec);
 #else
	seed = static_cast<unsigned int>(time(nullptr));
 #endif
	seed ^= static_cast<unsigned int>(getpid());
    }
 #if defined(HAVE_SRANDOM)
    srandom(seed);
 #else
    srand(seed);
 #endif
#endif
}

#if defined(HAVE_ARC4RANDOM)
 #define spoofer_rand_stir_if_needed() /* empty */
#else
static void spoofer_rand_stir_if_needed()
{
    // Make sure to re-stir if we've forked, so we don't generate the
    // same pseudorandom sequence as the parent or siblings.
    static pid_t stirred_pid = 0;
    if (stirred_pid != getpid()) {
	spoofer_rand_stir();
	stirred_pid = getpid();
    }
}
#endif

unsigned long spoofer_rand(unsigned long max)
{
    spoofer_rand_stir_if_needed();
#if defined(HAVE_ARC4RANDOM)
    return static_cast<unsigned long>(arc4random_uniform(static_cast<uint32_t>(max)));
#elif defined(HAVE_SRANDOM)
    return static_cast<unsigned long>(random()) % max;
#else
    return static_cast<unsigned long>(rand()) % max;
#endif
}

/**
 * msleep -  Portable millisecond sleep 
 */
void msleep(unsigned int msec) {
#ifdef _WIN32
    Sleep(msec);
#else
    usleep(msec * 1000);
#endif
}

/**
 * spoofSleep -  Portable 0.1 - 0.5 s random sleep 
 */
void spoofSleep(void) {
    msleep(100 + static_cast<unsigned>(spoofer_rand(400)));
}

/**
 * timestring - form time/date string
 */
char *timestring(void) {
   static char str[BUFSIZE];
   time_t now;
   struct tm *t;

   now = time(nullptr);
   t = localtime(&now);
   snprintf(str, sizeof(str), "%d/%02d/%02d %02d:%02d:%02d", t->tm_year + 1900,
       t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
   return (str);
}

/**
 * streamSetup - set stdout to be unbuffered, replicate stdout
 *               to the stderr file descriptor.  useful with
 *               the authorization services API (for osx gui)
 *               which doesn't pipe back stderr and prevents
 *               weird interleaving of stderr, stdout messages.
 */
void streamSetup(void) {
    if (setvbuf(stdout, nullptr, _IONBF, 0) == EOF) {
        perror("setvbuf");
    }
    if (dup2(1,2) < 0) {
        perror("dup2");
    }
}

/* Unified IPv4/IPv6 address field helper routines.
 *   Ex:
 *     char bob[IPV6ADDRLEN];
 *     uint32_t alice = 91232354;
 *     h4to6n(alice, bob);
 *     printf("Alice: %u %u\n", alice, n6toh4(bob));
 */
/* network byte-order IPv6 to network byte-order IPv4 */
uint32_t n6ton4(const unsigned char *addr) {
    const unsigned char *begin = addr + (IPV6ADDRLEN - IPV4ADDRLEN);
    uint32_t res;
    memcpy(&res, begin, IPV4ADDRLEN);
    return (res);
}

/* network byte-order IPv6 to host byte-order IPv4 */
uint32_t n6toh4(const unsigned char *addr) {
    return (ntohl(n6ton4(addr)));
}

/* network byte-order IPv4 to network byte-order IPv6 */
int n4ton6(const uint32_t ip, unsigned char *addr) {
    unsigned char *begin = addr + (IPV6ADDRLEN - IPV4ADDRLEN);
    memcpy(begin, &ip, IPV4ADDRLEN);
    return TRUE;
}

/* host byte-order IPv4 to network byte-order IPv6 */
int h4ton6(const uint32_t ip, unsigned char *addr) {
    unsigned char *begin = addr + (IPV6ADDRLEN - IPV4ADDRLEN);
    uint32_t res = htonl(ip);
    memcpy(begin, &res, IPV4ADDRLEN);
    return TRUE;
}

int n6tohexstring(const unsigned char *addr, char *res) {
    int i=0;
    snprintf(res, 3, "0x");
    for (i=1;i<=IPV6ADDRLEN;i++) {
        snprintf(res + (i*2), 3, "%02x", *addr);
        addr++;
    }
    return TRUE;
}

int isIPv4(const unsigned char *addr) {
    int i=0;
    const unsigned char *d = addr;
    for (i=0;i<(IPV6ADDRLEN - IPV4ADDRLEN);i++) {
        if (*d++ != 0x00)
            return FALSE;
    }
    return TRUE;
}

int isIPv6(const unsigned char *addr) {
    return (isIPv4(addr) ? FALSE : TRUE);
}

int isIPv6Equal(const unsigned char *a1, const unsigned char *a2) {
    int ret = memcmp(a1, a2, IPV6ADDRLEN);
    return (ret == 0 ? TRUE : FALSE);
}

char *printIPv6(const unsigned char *a) {
    static char v6string[SMALLBUF];
    inet_ntop(AF_INET6, a, v6string, SMALLBUF);
    return v6string;
}

// portable version of BSD's strnstr()
const char *strstrPortable(const char *a, const char *b, size_t n) {
    size_t alen, blen, i;
    // don't depend on there being a \0 within the first n chars
    for (alen = 0; alen < n; alen++)
	if (a[alen] == '\0') break;
    blen = strlen(b);
    if (blen > alen) return nullptr;
    if (n > alen - blen)
	n = alen - blen;
    for (i = 0; i <= n; i++) {
	if (memcmp(a+i, b, blen) == 0)
	    return a+i;
    }
    return nullptr;
}
