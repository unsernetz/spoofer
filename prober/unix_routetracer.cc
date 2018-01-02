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
   Author:      Rob Beverly <rbeverly at csail.mit.edu>
                Ken Keys, CAIDA
   Date:        $Date: 2017/10/13 22:11:38 $
   Description: Traceroute wrapper
****************************************************************************/
#ifndef _WIN32

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "spoof.h"
#include "prober.h"
#include "routetracer.h"

static const char cvsid[] ATR_USED = "$Id: unix_routetracer.cc,v 1.16 2017/10/13 22:11:38 kkeys Exp $";

class UnixRouteTracer : public RouteTracer {
    public:
    struct Child : public RouteTracer::Child {
	pid_t pid;
	int fd[2];
	int progress;
	int startTrace(unsigned delay, const char *const argv[]);
	void closePipe(Tracker *tracker);
	void kill(Tracker *tracker, const char *reason);
	Child(unsigned _id, RouteTracer *_rt, const std::vector<const char *> &dests) :
	    RouteTracer::Child(_id, _rt, dests),
	    pid(), progress() {}
    };
    std::vector<const char*> args;
    size_t first_alloc;

    static bool initUnix(IPv ipv);

    UnixRouteTracer(const UnixRouteTracer &) NO_METHOD;
    UnixRouteTracer operator=(const UnixRouteTracer &) NO_METHOD;
public:
    UnixRouteTracer(IPv _ipv) : RouteTracer(_ipv), args(), first_alloc(UINT_MAX) {}
    ~UnixRouteTracer() {
	for (size_t i = first_alloc; i < args.size(); i++)
	    if (args[i]) free(const_cast<char*>(args[i]));
    }
    int run(Tracker *tracker, const std::vector<const char *> &dest);
};

RouteTracer *RouteTracer::make(IPv _ipv)
    { return new UnixRouteTracer(_ipv); }

RouteTracer::Child *RouteTracer::Child::make(unsigned _id, RouteTracer *_rt,
    const std::vector<const char *> &dests)
    { return new UnixRouteTracer::Child(_id, _rt, dests); }

// Try different configurations until we find one that works.
bool RouteTracer::init(IPv ipv)
{
    // XXX TODO need mutex if used from multiple sessions with same ipv
    if (type[ipv] != UNKNOWN)
	return type[ipv] != MISSING;

    if (initScamper(ipv, "scamper", "/usr/local/bin/scamper"))
	return true;

    // Fall back to platform's traceroute
    std::vector<const char *> tr_candidate;

    tr_candidate.push_back("/usr/local/sbin/traceroute");
    tr_candidate.push_back("/usr/sbin/traceroute");
    tr_candidate.push_back("/sbin/traceroute");
    tr_candidate.push_back("/usr/bin/traceroute");
    tr_candidate.push_back("/usr/sbin/tracepath");
    if (ipv == IPv6) {
	tr_candidate.push_back("/usr/local/sbin/traceroute6");
	tr_candidate.push_back("/usr/sbin/traceroute6");
	tr_candidate.push_back("/sbin/traceroute6");
	tr_candidate.push_back("/usr/bin/traceroute6");
	tr_candidate.push_back("/usr/sbin/tracepath6");
    }

    static const char *options[] = {
	"-N1", // send only 1 probe at a time (Linux)
	"-w1", // wait at most 1s for a response (most unix-like systems)
	"-q1", // send only 1 packet per hop (most unix-like systems)
	"-m30", // max TTL 30 (most unix-like systems)
	// "-I", // icmp echo (some unix-like systems)
	nullptr
    };

    trace_args[ipv].push_back(nullptr); // program
    trace_args[ipv].push_back("-n");
    for (size_t i = 0; i < tr_candidate.size(); i++) {
	trace_args[ipv][0] = tr_candidate[i];
	if (checkProg(ipv, NATIVE)) {
	    // We found a working program; now try various options.
	    for (int j = 0; options[j]; j++) {
		trace_args[ipv].push_back(options[j]);
		if (!checkProg(ipv, NATIVE))
		    trace_args[ipv].pop_back(); // remove failed option
	    }
	    return finishInit(ipv, NATIVE);
        }
    }
    trace_args[ipv].clear();

    return finishInit(ipv);
}

void UnixRouteTracer::Child::closePipe(Tracker *tracker) {
    ::close(fd[0]);
    fd[0] = -1;
    this->done = true;
    this->parse(tracker); // parse any remaining text
    if (tracker) tracker->incGoal(this->tries - this->goal);
    this->goal = this->tries;
    int status;
    waitpid(pid, &status, WNOHANG);
}

/* Terminate child */
void UnixRouteTracer::Child::kill(Tracker *tracker, const char *reason) {
    debug(HIGH, "Terminating child %d (%s)\n", pid, reason);
    ::kill(pid, SIGKILL);
    closePipe(tracker);
}

int UnixRouteTracer::Child::startTrace(unsigned delay, const char *const argv[])
{
    /* open a pipe.  [0] is read end, [1] is write end. */
    if (pipe(fd) < 0) {
	perror("pipe");
	return -1;
    }

    /* spawn a process to perform the trace */
    switch (pid = fork()) {
    case -1:
	return -1;
    case 0: // child process
	::close(fd[0]); // close unused read end
	msleep(traceroute_delay * delay); // so all children don't probe the same hop simultaneously
	debug(HIGH, ">> Child %d running\n", getpid());
	dup2(fd[1], STDERR_FILENO);
	dup2(fd[1], STDOUT_FILENO);
	execv(argv[0], const_cast<char *const*>(argv));
	exit(1);
    default: // parent process
	if (!initializing[rt->ipv] || verbosity >= HIGH) {
	    FileGuard fileguard(stdout);
	    char buf[4096];
	    size_t off = 0;
	    off += unsigned(snprintf(buf+off, sizeof(buf)-off,
		">> IPv%d traceroute[%d]: ", rt->ipv, pid));
	    for ( ; *argv; ++argv) {
		off += unsigned(snprintf(buf+off, sizeof(buf)-off,
		    strpbrk(*argv, "\"' \\") ? "\"%s\" " : "%s ", *argv));
	    }
	    off += unsigned(snprintf(buf+off, sizeof(buf)-off, "\n"));
	    fputs(buf, stdout);
	}
	::close(fd[1]); // close unused write end
	fd[1] = -1;
    }
    return 0;
} 

int UnixRouteTracer::run(Tracker *tracker, const std::vector<const char *> &dests)
{
    if (!initRun(dests)) return -1;

    family_t family = ipvtofamily(ipv);
    struct timeval timeout;
    int nfds = 0;
    fd_set fds;
    char addrbuf[INET6_ADDRSTRLEN+1];

    args.reserve(trace_args[ipv].size() + (type[ipv] == SCAMPER ? dests.size() : 1) + 1);
    for (unsigned i = 0; i < trace_args[ipv].size(); i++)
	args.push_back(trace_args[ipv][i]);

    if (type[ipv] == SCAMPER) {
	first_alloc = args.size();
	for (unsigned i = 0; i < dests.size(); i++) {
	    inet_ntop(family, dests[i], addrbuf, sizeof(addrbuf));
	    args.push_back(strdup(addrbuf)); // will be freed in dtor
	}
	args.push_back(nullptr); // sentinel for exec()
	Child *child = static_cast<Child*>(children[0]);
	if (child->startTrace(0, args.data()) < 0)
	    return -1;

    } else {
	args.push_back(addrbuf); // dest address
	args.push_back(nullptr); // sentinel for exec()

	for (unsigned i = 0; i < children.size(); i++) {
	    Child *child = static_cast<Child*>(children[i]);
	    inet_ntop(family, dests[i], addrbuf, INET6_ADDRSTRLEN+1);
	    if (child->startTrace(i, args.data()) < 0)
		return -1;
	}
    }

    /* while traceroutes haven't run too long */
    while (time(nullptr) < too_long && !this->abort) {
        /* select reset */
        FD_ZERO(&fds);
	nfds = 0;
	for (unsigned i = 0; i < children.size(); i++) {
	    Child *child = static_cast<Child*>(children[i]);
	    if (child->fd[0] == -1) continue;
            FD_SET(child->fd[0], &fds);
	    if (child->fd[0] >= nfds)
		nfds = child->fd[0] + 1;
        }
	if (nfds == 0) break; // all pipes are closed
	timeout.tv_sec = too_long + 1 - time(nullptr);
        timeout.tv_usec = 0;

        /* find a pipe with pending data from which to read */
	int n_ready = select(nfds, &fds, nullptr, nullptr, &timeout);
        if (n_ready < 0) break;
        if (n_ready == 0) continue;

        /* read from pipes which have pending data */
	for (unsigned i = 0; i < children.size(); i++) {
	    Child *child = static_cast<Child*>(children[i]);
            if (child->fd[0] != -1 && FD_ISSET(child->fd[0], &fds)) {
                if (child->result->length >= maxlen - 1) {
		    child->kill(tracker, "buffer full");
		    break;
		}
                ssize_t n = read(child->fd[0],
		    child->result->text + child->result->length,
		    maxlen - child->result->length - 1);
		if (n < 0) { // error
                    child->kill(tracker, "read error");
		} else if (n == 0) { // EOF
		    child->closePipe(tracker);
                } else {
                    child->result->length += safe_int<size_t>(n);
		    child->parse(tracker);
		    if (!child->done && child->abort)
			child->kill(tracker, "gap limit");
		}
            }
        }
    }

    for (unsigned i = 0; i < children.size(); i++) {
	/* kill any children that didn't exit properly */
	Child *child = static_cast<Child*>(children[i]);
	if (!child->done)
	    child->kill(tracker, "unresponsive");
    }

    if (type[ipv] == SCAMPER)
	splitScamperOutput(dests);

    return 0;
}

#endif // !_WIN32
