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
 * Used for definitions of plugin modules.
 * @file sipwitch/modules.h
 */

#ifndef _SIPWITCH_MODULES_H_
#define _SIPWITCH_MODULES_H_

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef __SIPWITCH_SERVICE_H_
#include <sipwitch/service.h>
#endif

#ifndef __SIPWITCH_CDR_H_
#include <sipwitch/cdr.h>
#endif

#ifndef _SIPWITCH_CONTROL_H_
#include <sipwitch/control.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

/**
 * Common interfaces and clases for plugins.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT modules
{
public:
    typedef enum {REG_FAILED, REG_SUCCESS} regmode_t;

    /**
     * Common base class for sipwitch plugin services.  This provides
     * interfaces for server and runtime library callbacks to notify
     * plugins about server operatios and events.
     * @author David Sugar <dyfet@gnutelephony.org>
     */
    class __EXPORT sipwitch : public service::callback
    {
    protected:
        /**
         * Create a service instance and add to runtime list of services to
         * start and stop.
         */
        sipwitch();

    public:
        /**
         * Period service request.  A period is an interval during which
         * stats are flushed and refreshed.  This notifies the plugin that
         * a period has occured, and what the interval for the period was
         * in seconds.
         * @param slice of period in seconds.
         */
        virtual void period(long slice);

        /**
         * Announce a SIP publish event from a registered user to plugins.
         * @param user registration who publushed.
         * @param type of message that is published.
         * @param event type description, such as \"presense\" message.
         * @param expires time for this message.
         * @param body of message published by user agent.
         * @return true if plugin wishes to swallow this message.
         */
        virtual bool announce(MappedRegistry *user, const char *type, const char *event, const char *expires, const char *body);

        /**
         * Notify plugins a user registration is being activated.
         * @param user registration activated.
         */
        virtual void activating(MappedRegistry *user);

        /**
         * Notify plugins a user registration has been expired or released.
         * @param user registration that was expired.
         */
        virtual void expiring(MappedRegistry *user);

        /**
         * Notify plugins about reply messages from external registrations.
         * This is used to get result of eXosip SIP registration requests.
         * This might be used to get the result of a plugin registering
         * itself with a gateway or SIP service provider, for example.
         * @param id of registration (eXosip rid).
         * @param result of registration
         */
        virtual void registration(int id, regmode_t reg);

        /**
         * Used to verify authentication of a registered session.  This is
         * for use by sessions registered by plugins.
         * @param id of registration (eXosip rid).
         * @param realm of this registration.
         * @return true if valid, false if invalid or to ignore in this plugin.
         */
        virtual bool authenticate(int id, const char *realm);

        /**
         * Enables plugin to redirect locally dialed destination to new uri.
         * Might be used by a plugin that does per-user speed-dialing
         * database, for example.
         * @param user that is dialing.
         * @param target user dialed.
         * @param buffer to store replacement uri in.
         * @param size of replacement buffer.
         * @return pointer to buffer or NULL if ignored.
         */
        virtual char *referLocal(MappedRegistry *user, const char *target, char *buffer, size_t size);

        /**
         * Enables plugin to remap users dialing remote destinations.
         * This might be used as a hook for a plugin that maintains gfc peer
         * tables, for example.
         * @param user that is dialing.
         * @param target of remote uri.
         * @param buffer to store replacement uri in.
         * @param size of replacement buffer.
         * @return pointer to buffer of new uri or NULL ignored.
         */
        virtual char *referRemote(MappedRegistry *user, const char *target, char *buffer, size_t size);
    };

    /**
     * A more generic service class for use by plugins.  This is meant for
     * plugins which do generic or unrelated operations, or to activate
     * a generic service thread.  This adds the inherited class to the
     * existing service start/stop framework in sipwitch.
     * @author David Sugar <dyfet@gnutelephony.org>
     */
    class __EXPORT generic : public service::callback
    {
    protected:
        /**
         * Construct a generic service instance.
         */
        generic();
    };

    /**
     * Interface to server network interface protocols.  This allows for
     * specific eXosip functions to be called from the server rather than
     * within a plugin.  This is needed on some platforms where we use
     * runtime plugins but where exosip2 is statically linked, otherwise
     * eXosip state code will get distributed all over the place.  This
     * is a singleton abstract class that is then filled out and initialized
     * by the server.
     */
    class __EXPORT protocols
    {
    public:
        static protocols *instance;

        /**
         * Initialize singleton.
         */
        protocols();

        virtual ~protocols();

        /**
         * Create a SIP registration on a remote server.  Registration events
         * are then returned to the plugin through the registration callback
         * method.
         * @param uri we are registering with the server.
         * @param server uri to register at.
         * @param contact uri of our identity locally.
         * @param expires in seconds.
         * @return registration id or -1 on failure.
         */
        virtual int create_registration(const char *uri, const char *server, const char *contact, int expires) = 0;

        /**
         * Release an existing registration.
         * @param id to release.
         * @return true if successful, false on failure.
         */
        virtual bool release_registration(int rid) = 0;

        /**
         * Add authentication digest for remote server.
         * @param userid we expect.
         * @param secret for the userid.
         * @param realm of remote server.
         */
        virtual bool add_authentication(const char *userid, const char *secret, const char *realm) = 0;

        /**
         * Compute a random uuid.
         * @param uuid output buffer.
         */
        virtual void random_uuid(char *uuid) = 0;

        /**
         * Publish sip message to remote.
         * @param uri to publish to.
         * @param contact info for our origin here.
         * @param event to publish.
         * @param duration until expires or NULL.
         * @param type of message.
         * @param body of message.
         */
        virtual bool publish(const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body) = 0;
    };

    /**
     * Create a SIP registration on a remote server.  Registration events
     * are then returned to the plugin through the registration callback
     * method.
     * @param uri we are registering with the server.
     * @param server uri to register at.
     * @param contact uri of our identity locally.
     * @param expires in seconds.
     * @return registration id or -1 on failure.
     */
    static inline int create_registration(const char *uri, const char *server, const char *contact, int expires)
        {return protocols::instance->create_registration(uri, server, contact, expires);}

    /**
     * Release existing registration.
     * @param id to release.
     * @return true if successful, false on failure.
     */
    static inline bool release_registration(int rid)
        {return protocols::instance->release_registration(rid);}

    /**
     * Add authentication digest for remote server.
     * @param userid we expect.
     * @param secret for the userid.
     * @param realm of remote server.
     */
    static inline bool add_authentication(const char *userid, const char *secret, const char *realm)
        {return protocols::instance->add_authentication(userid, secret, realm);}

    /**
     * Compute a random uuid.
     * @param uuid output buffer.
     */
    static inline void random_uuid(char *uuid)
        {protocols::instance->random_uuid(uuid);}

    /**
     * Publish sip message to remote.
     * @param uri to publish to.
     * @param contact info for our origin here.
     * @param event to publish.
     * @param duration until expires or NULL.
     * @param type of message.
     * @param body of message.
     */
    static inline bool publish(const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body)
        {return protocols::instance->publish(uri, contact, event, duration, type, body);}

    /**
     * Post cdr record to a file. This provides a generic way to output
     * cdr info, such as to a fifo for a database logger.
     * @param file to write to.
     * @param call record to publish.
     */
    static void cdrlog(FILE *file, cdr *call);

    /**
     * Module access to error logging system.  This also posts to the
     * events subsystem.
     * @param level of logging event.
     * @param text of logging event.
     */
    static void errlog(shell::loglevel_t level, const char *text);
};

END_NAMESPACE

#endif
