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
   Author:      Ken Keys
   Date:        $Date: 2017/10/13 22:11:38 $
   Description: Traceroute wrapper
****************************************************************************/

class RouteTracer {
protected:
    struct Result {
	char *text;
	size_t length;
    };
    struct Child {
	RouteTracer *rt;
	unsigned id;
	bool done; // child can set this to indicate it is done
	bool abort; // main thread can set this to request child to stop
	size_t num_dests;
	Result *result;
	size_t parsed;  // end of last parsed full line
	size_t scanned; // how far we've scanned for '\n'
	int tries;
	int goal;
	int gap;
	int current_goal; // goal of current scamper target
	int latest_hop; // latest hop seen for current scamper target
	Child(unsigned _id, RouteTracer *_rt, const std::vector<const char *> &dests) :
	    rt(_rt), id(_id), done(), abort(),
	    num_dests(type[_rt->ipv] == SCAMPER ? dests.size() : 1),
	    result(&rt->result[id]), parsed(), scanned(), tries(),
	    goal(static_cast<int>(num_dests) * TRACEROUTE_ITEM_COST), gap(),
	    current_goal(0), latest_hop(0)
	    { }
	Child(const Child&) NO_METHOD;
	Child operator=(const Child&) NO_METHOD;
	virtual ~Child() {}
	void parse(Tracker *tracker);
	void adjustScamperGoal(Tracker *tracker);
	static Child *make(unsigned _id, RouteTracer *_rt, const std::vector<const char *> &dests);
    };
    enum Type { UNKNOWN, MISSING, NATIVE, SCAMPER };

    static bool initializing[7];
    static Type type[7];
    static std::vector<const char *> trace_args[7];
public: // XXX
    IPv ipv;
    bool abort; // main thread can set this to request all children to stop
    size_t maxlen; // maximum length of output of a child process
protected:
    char *text;
    std::vector<Result> result; // per-target results
    std::vector<Child*> children; // per-child state
    time_t start_time;
    time_t too_long;

    RouteTracer(const RouteTracer &) NO_METHOD;
    void operator=(const RouteTracer &) NO_METHOD;
    void splitScamperOutput(const std::vector<const char *> &dests);
    static bool checkProg(IPv ipv, Type checktype);
    static bool finishInit(IPv ipv, Type foundtype = MISSING);
    static bool initScamper(IPv ipv, const char *name, const char *alternate);
    bool initRun(const std::vector<const char *> &dests);

    RouteTracer(IPv _ipv) : ipv(_ipv), abort(), maxlen(), text(), result(),
	children(), start_time(), too_long() {}
public:
    virtual ~RouteTracer() {
	if (text) delete[] text;
	for (unsigned i = 0; i < children.size(); i++)
	    delete children[i];
    };
    virtual int run(Tracker *tracker, const std::vector<const char *> &dest) = 0;
    const char *getText(unsigned i) ATR_PURE { return result[i].text; }
    size_t getLength(unsigned i) ATR_PURE { return result[i].length; }
    size_t resultCount() ATR_PURE { return result.size(); }

    static bool init(IPv ipv);
    static RouteTracer *make(IPv ipv);
};
