// Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
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
 * Stream events to local clients.  This defines server side support for
 * streaming events to clients.  The client side code is not implemented
 * here to avoid the need to link with sipwitch runtime.
 * @file sipwitch/events.h
 */

#ifndef _SIPWITCH_EVENTS_H_
#define _SIPWITCH_EVENTS_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef _UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef _UCOMMON_SOCKET_H_
#include <ucommon/socket.h>
#endif

#ifndef __SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

#ifndef __SIPWITCH_MAPPED_H_
#include <sipwitch/mapped.h>
#endif

#ifndef __SIPWITCH_CDR_H_
#include <sipwitch/cdr.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT events
{
protected:
    bool put(events *event);

public:
    typedef enum {NOTICE, WARNING, FAILURE, TERMINATE, STATE, REALM, CALL, DROP, ACTIVATE, RELEASE, WELCOME, SYNC} type_t;

    type_t type;

    union {
        struct {
            time_t started;
            char reason[16];
            char network[MAX_NETWORK_SIZE * 2];
            char dialed[MAX_USERID_SIZE];
            char caller[MAX_IDENT_SIZE];
            char display[MAX_DISPLAY_SIZE];
        } call;
        struct {
            unsigned extension;
            char id[MAX_USERID_SIZE];
        } user;
        struct {
            time_t started;
            char version[16];
            char state[32];
            char realm[64];
        } server;
        char reason[160];
        unsigned period;
    };

    static bool start(void);

    static void state(const char *newstate);
    static void realm(const char *newrealm);
    static void connect(cdr *rec);
    static void drop(cdr *rec);
    static void activate(MappedRegistry *rr);
    static void release(MappedRegistry *rr);
    static void notice(const char *reason);
    static void warning(const char *reason);
    static void failure(const char *reason);
    static void terminate(const char *reason);
    static void sync(unsigned period = 0l);
};

typedef events event_t;

END_NAMESPACE

#endif
