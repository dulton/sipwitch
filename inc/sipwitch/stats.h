// Copyright (C) 2009-2010 David Sugar, Tycho Softworks.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Basic server call statistics.
 * This provides the interface for managing server call statistics, which are
 * kept in shared memory.
 * @file sipwitch/stats.h
 */

#ifndef _SIPWITCH_STATS_H_
#define _SIPWITCH_STATS_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef _UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef _SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define STAT_MAP    "sipwitch.stats"

/**
 * A stat element of call traffic.  Stats may cover a specific element for
 * a current time period, and total stats for the life of the server.  This
 * is used to determine server utilization, to determine peak times such as
 * may be needed for acd traffic analysis, and to categorize the kind of
 * traffic we are processing through the server.  There is a "system" stat
 * node for ALL server call traffic, as well as nodes for collecting stats
 * on all extensions, on all service entries, etc.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT stats
{
public:
    char id[12];

    typedef enum {INCOMING = 0, OUTGOING = 1} stat_t;

    /**
     * We have stats for both incoming and outgoing traffic of various kinds.
     */
    struct
    {
        unsigned long total, period, pperiod;
        unsigned short current, peak, min, max, pmin, pmax;
    } data[2];

    time_t lastcall;
    unsigned short limit;

    /**
     * Assign a call to inbound or outbound statistic for this stat node.
     * Increments count.
     * @param elenent (in or out) to assign to.
     */
    void assign(stat_t element);

    /**
     * Release a call from inbound or outbound stastic for this stat node.
     * This is commonly related to call drop and decrements count.
     * @param element (in or out) to release from.
     */
    void release(stat_t element);

    /**
     * Total number of active calls in the server at the moment.
     * @return total active calls.
     */
    unsigned active(void) const;

    /**
     * Write out statistics to a file for the current period.  The stats
     * are also reset for the new period.  The period is also the sync
     * period of the sync event, and is set with the service::period method.
     * @param file to write to or NULL for none.
     */
    static void period(FILE *file = NULL);

    /**
     * Create stats in shared memory pool.  Creates several default statistic
     * nodes for groups of calls, and returns the "system" stat node for the
     * total server.
     */
    static stats *create(void);

    /**
     * Request a stat node from the memory pool by id.  If the node does not
     * exist, it is created.
     * @return node from shared memory or NULL if out of nodes.
     */
    static stats *request(const char *id);

    /**
     * Server allocate x number of stat nodes at startup.
     * @param number of stat nodes to allocate.
     */
    static void allocate(unsigned count);

    /**
     * Release stat nodes shared memory segment.
     */
    static void release(void);
};

END_NAMESPACE

#endif
