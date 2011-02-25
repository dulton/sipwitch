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

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT events
{
protected:
    bool put(events *event);

public:
    typedef enum {NOTICE, WARNING, FAILURE, TERMINATE, STATE, CALL, REGISTER, RELEASE} type_t;

    type_t type;

    union {
        struct {
            char dialed[MAX_USERID_SIZE];
            char caller[MAX_IDENT_SIZE];
            char display[MAX_DISPLAY_SIZE];
        } call;
        char state[64];
        struct {
            unsigned extension;
            char userid[MAX_USERID_SIZE];
            char source[128];
        };
        char reason[160];
    };

    static bool startup(void);
    static void shutdown(void);
};

typedef events event_t;

END_NAMESPACE

#endif
