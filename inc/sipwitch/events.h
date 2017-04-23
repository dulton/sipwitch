// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015-2017 Cherokees of Idaho.
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
 * here to avoid the need to link with sipwitch runtime.  The runtime library
 * methods are meant for server use, and are called from existing runtime
 * library methods, so plugins should not need to call them directly.
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

namespace sipwitch {

/**
 * Event message and supporting methods for plugins.  This defines what
 * an event message is as passed from the server to clients listening on
 * (unix or inet) sockets, and also what functions are offered in the
 * runtime library for the server and plugins to send events to clients.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT events
{
protected:
    /**
     * Internal method to send an event message.
     * @param event to send to connected clients.
     * @return true if sent successfully.
     */
    bool put(events *event);

public:
    typedef enum {NOTICE, WARNING, FAILURE, TERMINATE, STATE, REALM, CALL, DROP, ACTIVATE, RELEASE, WELCOME, SYNC, CONTACT, PUBLISH} type_t;

    /**
     * Type of event message.
     */
    type_t type;

    /**
     * Content of message, based on type.
     */
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
        char contact[160];
        char reason[160];
        unsigned period;
    } msg;

    /**
     * Start server event system by binding event session listener.
     * @param true if sucessfully bound and started.
     */
    static bool start(void);

    /**
     * Send state change to connected clients.
     * @param newstate server changed to.
     */
    static void state(const char *newstate);

    /**
     * Send realm change to connected clients.
     * @param newrealm server changed to.
     */
    static void realm(const char *newrealm);

    /**
     * Send call connection to clients from cdr start record.
     * @param cdr record of started call.
     */
    static void connect(cdr *rec);

    /**
     * Send call disconnected event to clients from cdr stop record.
     * @param cdr of disconnected call.
     */
    static void drop(cdr *rec);

    /**
     * Send event for first instance of user registration.  This is sent
     * after the shared memory registry object is updated.
     * @param user registration record activated.
     */
    static void activate(MappedRegistry *user);

    /**
     * Send event for last instance of user expired or de-registering.
     * This is sent after the shared memory registry object is updated.
     * @param user registration record released.
     */
    static void release(MappedRegistry *user);

    /**
     * Send notice to user.  These are sent from the runtime logging, so
     * if plugins already log messages they do not have to separately
     * call this.
     * @param reason for notice.
     */
    static void notice(const char *reason);

    /**
     * Send warning to user.  These are sent from the runtime logging, so
     * if plugins already log messages they do not have to separately
     * call this.
     * @param reason for warning.
     */
    static void warning(const char *reason);

    /**
     * Send error to user.  These are sent from the runtime logging, so
     * if plugins already log messages they do not have to separately
     * call this.
     * @param reason for error.
     */
    static void failure(const char *reason);

    /**
     * Refresh clients with any config events...
     */
    static void reload(void);

    /**
     * Update publish address...
     * @param published address.
     */
    static void publish(const char *address);

    /**
     * Notify server termination.
     * @param reason server terminated.
     */
    static void terminate(const char *reason);

    /**
     * Test connection and housekeeping notification.  A sync with a period
     * of 0 is used to test existing sessions to see if they are connected.
     * @param period of housekeeping event or 0 if connection test.
     */
    static void sync(unsigned period = 0l);
};

typedef events event_t;

} // namespace sipwitch

#endif
