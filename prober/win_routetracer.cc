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
   Author:      Rob Beverly <rbeverly@mit.edu>
                Ken Keys, CAIDA
   Date:        $Date: 2017/10/13 22:11:38 $
   Description: WIN32-Specific traceroute wrapper
****************************************************************************/
#ifdef _WIN32

#include "spoof.h"
#include "prober.h"
#include "routetracer.h"
static const char cvsid[] ATR_USED = "$Id: win_routetracer.cc,v 1.15 2017/10/13 22:11:38 kkeys Exp $";

struct WinRouteTracer : public RouteTracer {
    public:
    struct Child : public RouteTracer::Child {
	const std::vector<const char *> &dests;
	PROCESS_INFORMATION piProcInfo;
	HANDLE hThread;
	HANDLE StdOut_Rd;
	HANDLE StdOut_Wr;
	Child(unsigned _id, RouteTracer *_rt, const std::vector<const char *> &_dests) :
	    RouteTracer::Child(_id, _rt, _dests),
	    dests(_dests),
	    piProcInfo(), hThread(), StdOut_Rd(), StdOut_Wr()
	    {}
	Child(const Child &) NO_METHOD;
	Child operator=(const Child &) NO_METHOD;
	static DWORD WINAPI run(LPVOID lpParam);
    };
    WinRouteTracer(const WinRouteTracer &) NO_METHOD;
    WinRouteTracer operator=(const WinRouteTracer &) NO_METHOD;
public:
    WinRouteTracer(IPv _ipv) : RouteTracer(_ipv) { }
    ~WinRouteTracer() { }
    int run(Tracker *tracker, const std::vector<const char *> &dests);
};

RouteTracer *RouteTracer::make(IPv _ipv)
    { return new WinRouteTracer(_ipv); }

RouteTracer::Child *RouteTracer::Child::make(unsigned _id, RouteTracer *_rt,
    const std::vector<const char *> &dests)
    { return new WinRouteTracer::Child(_id, _rt, dests); }


/* thread which performs tracing work */
DWORD WINAPI WinRouteTracer::Child::run(LPVOID lpParam) {
    char cmd[BUFSIZE];
    DWORD status = 1; // failure

    /* from: http://msdn.microsoft.com/en-us/library/ms682499.aspx */
    STARTUPINFO siStartInfo;
    SECURITY_ATTRIBUTES saAttr;
    DWORD dwRead;
    BOOL bSuccess = FALSE;

    WinRouteTracer::Child *child = (WinRouteTracer::Child*)lpParam;
    RouteTracer *&rt = child->rt;
    family_t family = ipvtofamily(rt->ipv);
    RouteTracer::Result *&result = child->result;
    char addrbuf[INET6_ADDRSTRLEN+1];
    int offset = 0;
    for (unsigned i = 0; i < trace_args[rt->ipv].size(); i++)
	offset += sprintf(cmd + offset, "\"%s\" ", trace_args[rt->ipv][i]);
    offset--; // remove trailing space
    if (type[rt->ipv] == SCAMPER) {
	for (unsigned i = 0; i < child->dests.size(); i++) {
	    inet_ntop(family, child->dests[i], addrbuf, sizeof(addrbuf));
	    offset += sprintf(cmd + offset, " %s", addrbuf);
	}
    } else {
	inet_ntop(family, child->dests[child->id], addrbuf, sizeof(addrbuf));
	sprintf(cmd + offset, " %s", addrbuf);
    }

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    CreatePipe(&child->StdOut_Rd, &child->StdOut_Wr, &saAttr, 0);
    SetHandleInformation(child->StdOut_Rd, HANDLE_FLAG_INHERIT, 0);

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = nullptr;
    siStartInfo.hStdOutput = child->StdOut_Wr;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    Sleep(traceroute_delay * child->id); // so all children don't probe the same hop simultaneously
    if (!initializing[rt->ipv] || verbosity >= HIGH)
	printf(">> IPv%d traceroute[%d]: %s\n", rt->ipv, child->id, cmd);
    if (!CreateProcess(nullptr, cmd, nullptr, nullptr, TRUE, 0,
        nullptr, nullptr, &siStartInfo, &child->piProcInfo))
    {
	debug(HIGH, "CreateProcess %d: error %ld\n", child->id, GetLastError());
	CloseHandle(child->StdOut_Wr);
	goto done;
    }
    CloseHandle(child->StdOut_Wr);
    while (1) {
        if (child->abort || rt->abort) {
            debug(HIGH, "stopping [thread: %d]\n", child->id);
	    if (!TerminateProcess(child->piProcInfo.hProcess, 1))
		debug(HIGH, "TerminateProcess: child %d: error %ld\n", child->id, GetLastError());
            break;
        }

	if (result->length >= rt->maxlen - 1) { // buffer full
	    if (!TerminateProcess(child->piProcInfo.hProcess, 1))
		debug(HIGH, "TerminateProcess: child %d: error %ld\n", child->id, GetLastError());
	    break;
	}
	bSuccess = ReadFile(child->StdOut_Rd, 
	    result->text + result->length, rt->maxlen - result->length - 1, &dwRead, nullptr);
	if (!bSuccess) {
	    if (GetLastError() == ERROR_BROKEN_PIPE) // child closed pipe
		status = 0; // success
	    break;
	}
	if (dwRead > 0)
	    result->length += dwRead;
        // XXX printf("Thread: %d (%p) Read: [%lu] Total: [%d]\n",
	    // XXX child->id, child, dwRead, result->length);
	if (dwRead <= 0)
            Sleep(200);
    }
    result->text[result->length] = '\0';
done:
    if (!CloseHandle(child->piProcInfo.hProcess))
	debug(HIGH, "Close hProcess: child %d: error %ld\n", child->id, GetLastError());
    if (!CloseHandle(child->piProcInfo.hThread))
	debug(HIGH, "Close hThread: child %d: error %ld\n", child->id, GetLastError());
    debug(HIGH, "Thread %d exit.\n", child->id);
    if (!CloseHandle(child->StdOut_Rd))
	debug(HIGH, "CloseHandle: child %d StdOut_Rd: error %ld\n", child->id, GetLastError());
    child->done = true;
    return status; // not ExitThread()!
}

bool RouteTracer::init(IPv ipv)
{
    // XXX TODO need mutex if used from multiple sessions with same ipv
    if (type[ipv] != UNKNOWN)
	return type[ipv] != MISSING;

    if (initScamper(ipv, "scamper.exe", nullptr))
	return true;

    // Fall back to platform's traceroute
    trace_args[ipv].push_back("tracert");
    trace_args[ipv].push_back("-d");
    trace_args[ipv].push_back("-w");
    trace_args[ipv].push_back("1000");
    if (checkProg(ipv, NATIVE))
	return finishInit(ipv, NATIVE);
    trace_args[ipv].clear();

    return finishInit(ipv);
}

int WinRouteTracer::run(Tracker *tracker, const std::vector<const char *> &dests)
{
    if (!initRun(dests)) return -1;

    /* Start threads */
    for (unsigned i = 0; i < children.size(); i++) {
	Child *child = static_cast<Child*>(children[i]);
        child->hThread = CreateThread(nullptr, 0, WinRouteTracer::Child::run, 
            child, 0, nullptr);
    }
    
    /* Wait for threads to finish, or timeout */
    while (true) {
        Sleep(200);
	int children_running = 0;
	for (unsigned i = 0; i < children.size(); i++) {
	    Child *child = static_cast<Child*>(children[i]);
	    if (child->scanned < child->result->length + child->done)
		child->parse(tracker);
	    if (child->done) {
		if (tracker) tracker->incGoal(child->tries - child->goal);
		child->goal = child->tries;
	    } else {
		children_running++;
	    }
	}
	if (!children_running) break;
        // XXX debug(DEVELOP, "%d threads active\n", children_running);
	time_t now = time(nullptr);
	if (now > too_long) {
	    if (!abort) {
		printf("aborting.");
		abort = true;
	    } else if (now > too_long + 10) {
		// threads are still running 10s after we asked them to exit
		break;
	    }
        }
    }

    /* Shut down threads */
    Sleep(1000);
    for (unsigned i = 0; i < children.size(); i++) {
	Child *child = static_cast<Child*>(children[i]);
	if (WaitForSingleObject(child->hThread, 0) != WAIT_OBJECT_0) {
            debug(HIGH, "Thread %d still running. shut it down.\n", i);
	    TerminateThread(child->hThread, 666);
	    WaitForSingleObject(child->hThread, INFINITE);
	    debug(HIGH, "Thread %d terminated.\n", i);
	    child->done = true;
	}
        CloseHandle(child->hThread);
	child->parse(tracker); // parse any remaining text
	if (tracker && child->tries < child->goal) {
	    tracker->incGoal(child->tries - child->goal);
	    child->goal = child->tries;
	}
    }

    if (type[ipv] == SCAMPER)
	splitScamperOutput(dests);
    return 0;
}

#endif // _WIN32
