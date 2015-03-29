// Copyright (C) 2009-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015 Cherokees of Idaho.
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
 * Basic server call detail record.
 * This provides an interface for creating call detail objects which can be
 * logged through plugins.  The cdr system has it's own thread context and
 * buffering, so cdr records can be disposed without delaying calls processing.
 * @file sipwitch/cdr.h
 */

#ifndef _SIPWITCH_CDR_H_
#define _SIPWITCH_CDR_H_

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

#ifndef _SIPWITCH_MAPPED_H_
#include <sipwitch/mapped.h>
#endif

namespace sipwitch {

/**
 * Interface class for call detail records.  This is passed internally to
 * plugins via callbacks and can be logged to a database through one.  A
 * more limited subset of the cdr is passed via the events stream also.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT cdr : public LinkedObject
{
public:
    /**
     * Start or end of call?
     */
    enum {START, STOP} type;

    /**
     * A unique identifier for each and every call.
     */
    char uuid[48];

    /**
     * Ident of calling parting.
     */
    char ident[MAX_IDENT_SIZE];

    /**
     * Destination requested on our switch.
     */
    char dialed[MAX_IDENT_SIZE];

    /**
     * Call destination eventually joined to.
     */
    char joined[MAX_IDENT_SIZE];

    /**
     * Display name of calling party.
     */
    char display[MAX_DISPLAY_SIZE];

    /**
     * Subnet interface the caller appeared on.
     */
    char network[MAX_NETWORK_SIZE * 2];

    /**
     * Reason the call was terminated.
     */
    char reason[16];

    /**
     * Internal call sequence identifiers.
     */
    unsigned cid, sequence;

    /**
     * Time the call was received.
     */
    time_t starting;

    /**
     * Total duration of the call in seconds.
     */
    unsigned long duration;

    /**
     * Get a free cdr node to fill from the cdr memory pool.  To maximize
     * performance and allow parallel operation a memory pool of cdr objects
     * is used.
     * @return free record to fill.
     */
    static cdr *get(void);

    /**
     * Post cdr record to callbacks through the cdr thread queue.  This
     * returns the cdr object to the mem and then return to free list.
     * @param cdr record to post.
     */
    static void post(cdr *cdr);

    /**
     * Start cdr subsystem and que dispatch thread.
     */
    static void start(void);

    /**
     * Stop cdr subsystem.
     */
    static void stop(void);
};

} // namespace sipwitch

#endif
