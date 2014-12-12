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
 * Service configuration and component callbacks.
 * The service class offers tree based configuration subsystem that is
 * parsed from XML configuration files.  The service class also offers a
 * callback bus for attaching server components and for controlling
 * component startup and shutdown.  This service bus can be extended through
 * plugins as well as local objects in your server, all of which derive from
 * the callback member class of service.  Other features include support of
 * snapshot dumps and checking functions to determine state of running
 * servers.
 * @file sipwitch/service.h
 */

#ifndef _SIPWITCH_SERVICE_H_
#define _SIPWITCH_SERVICE_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef _UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef _UCOMMON_FSYS_H_
#include <ucommon/fsys.h>
#endif

#ifndef _SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

#ifndef _SIPWITCH_MAPPED_H_
#include <sipwitch/mapped.h>
#endif

#ifndef _SIPWITCH_CONTROL_H_
#include <sipwitch/control.h>
#endif

#ifndef _SIPWITCH_CDR_H_
#include <sipwitch/cdr.h>
#endif

#define CONFIG_KEY_SIZE 177

namespace sipwitch {

/**
 * System configuration instance and service functions.  This provides an
 * instance of a system configuration compiled from xml configs.  There is
 * an active instance which represents the current configuration, and a new
 * instance can be created without stopping the server.  This also provides
 * high level service functions in the runtime library for the server and
 * plugins to use.  The xml tree nodes are stored in a paged allocator.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT service : public memalloc
{
public:
    /**
     * Definition of a xml node.
     */
    typedef treemap<char *> keynode;

    /**
     * Dialing mode supported.  Whether by extension, userid, or both.
     */
    typedef enum {EXT_DIALING, USER_DIALING, ALL_DIALING} dialmode_t;

    /**
     * Keyword and value pair definition lists.
     */
    typedef struct {
        const char *key;
        const char *value;
    } define;

    /**
     * Used to splice new chains onto an existing xml tree.  This is how
     * xml user templates are attached and activated to an existing
     * user node.  This assumes the template is used exclusively for
     * attaching additional child nodes.
     */
    class __EXPORT keyclone : public treemap<char *>
    {
    public:
        void splice(keyclone *trunk);

        inline void reset(const char *tag)
            {Id = (char *)tag;}
    };

    /**
     * Pointer to a provisioned user xml subtree.  This can be a subtree
     * in the master service xml tree, or a locally created temporary
     * tree that is for example filled in from a sql table query by a plugin.
     */
    class __EXPORT usernode
    {
    public:
        service::keynode *keys;
        service *heap;
        usernode();
    };

    /**
     * A pointer to a subtree in the xml configuration tree.
     */
    class __EXPORT pointer
    {
    private:
        keynode *node;

    public:
        pointer();
        pointer(const char *path);
        pointer(pointer const&);
        ~pointer();

        inline operator bool() const
            {return node != NULL;}

        inline bool operator!() const
            {return node == NULL;}

        void operator=(keynode *node);

        inline keynode *operator*() const
            {return node;}

        inline keynode *operator->() const
            {return node;}
    };

    /**
     * The current singleton instance of the active xml configuration tree.
     */
    class __EXPORT instance
    {
    private:
        int state;

    public:
        instance();
        ~instance();

        inline const service *operator->() const
            {return service::cfg;}
    };

    /**
     * Callback methods for objects managed under the service thread.  This
     * ultimately includes plugin modules.  Since it is used as a base class
     * for all plugin services, it is also a place to pass common config
     * info in the server that needs to be directly accessible by plugins.
     */
    class __EXPORT callback : public OrderedObject
    {
    protected:
        friend class service;
        friend class modules;
        friend class events;
        friend class srv;

        unsigned runlevel;
        bool active_flag;

        static LinkedObject *runlevels[4];
        static unsigned count;
        static unsigned short sip_port;
        static const char *sip_iface;
        static volatile char *sip_contact;
        static volatile char *sip_publish;
        static int sip_protocol;
        static int sip_family;
        static int sip_tlsmode;
        static bool sip_public;             // hotspot mode flag
        static const char *sip_domain;
        static const char *sip_realm;
        static const char *sip_tlspwd;
        static const char *sip_tlsdev;
        static const char *sip_tlsca;
        static const char *sip_tlsdh;
        static const char *sip_tlskey;
        static const char *sip_tlscert;
        static unsigned sip_prefix;
        static unsigned sip_range;
        static char session_uuid[40];

        callback(int level = 0);    // default is priority
        virtual ~callback();

        inline static void *alloc(service *cfgp, size_t size)
            {return cfgp->alloc(size);}

        inline static char *dup(service *cfgp, const char *s)
            {return cfgp->dup(s);}

        inline static bool is_configured(void)
            {return service::cfg != NULL;}

        inline bool is_active(void) const
            {return active_flag;}

        virtual void cdrlog(cdr *call);
        virtual void errlog(shell::loglevel_t level, const char *text);
        virtual bool check(void);
        virtual void snapshot(FILE *fp);
        virtual void start(service *cfg);
        virtual void stop(service *cfg);
        virtual void reload(service *cfg);
        virtual void publish(service *cfg);

    public:
        static voip::context_t out_context;
        static voip::context_t tcp_context;
        static voip::context_t udp_context;
        static voip::context_t tls_context;

        inline static void bind(unsigned short port)
            {sip_port = port;}

        inline static void setPublic(void)
            {sip_public = true;}

        static void bind(const char *addr);

        voip::context_t getContext(const char *uri);
    };

    service(const char *name, size_t s = 0);
    virtual ~service();

    static volatile dialmode_t dialmode;

    /**
     * Load xml file into xml tree.  This may load into the root node, or
     * to a subnode.  The <provision> xml files for users are all loaded
     * into the <provision> subtree this way.
     * @param file to load from.
     * @param node to load to or NULL to make a root node for master config.
     */
    bool load(FILE *file, keynode *node = NULL);

    keynode *getPath(const char *path);
    keynode *getNode(keynode *base, const char *id, const char *value);
    keynode *addNode(keynode *base, define *defs);
    keynode *addNode(keynode *base, const char *id, const char *value);
    keynode *getNode(keynode *base, const char *grp, const char *attr, const char *value);
    keynode *getList(const char *path);

    inline static LinkedObject *getModules(void)
        {return service::callback::runlevels[3];}

    inline static LinkedObject *getGenerics(void)
        {return service::callback::runlevels[2];}

    /**
     * Set and publish public "appearing" address of the server.  This
     * probably should also appear in the events system.
     * @param addr we are appearing as (dns name or ip addr).
     */
    static void publish(const char *addr);

    static void published(struct sockaddr_storage *peer);
    static const char *getValue(keynode *base, const char *id);
    static void dump(FILE *fp, keynode *node, unsigned level);
    static void snapshot(void);
    static void dumpfile(void);
    static bool period(long slice);
    static void result(const char *value);
    static void startup(void);
    static void shutdown(void);
    static long uptime(void);
    static bool match(const char *digits, const char *pattern, bool partial);
    static keynode *get(void);

    static keynode *getProtected(const char *path);
    static keynode *getUser(const char *uid);
    static keynode *path(const char *p);
    static keynode *list(const char *p);

    inline static keynode *getEnviron(void)
        {return getProtected("environ");}

    inline keynode *getRoot(void)
        {return &root;}

    static string_t getContact(void);

    inline void setContact(const char *text)
        {contact = dup(text);}

    static inline const char *getInterface(void)
        {return service::callback::sip_iface;}

    static inline unsigned short getPort(void)
        {return service::callback::sip_port;}

    virtual void dump(FILE *fp);
    virtual void confirm(void);
    void commit(void);

    static bool check(void);
    static void release(keynode *node);

protected:
    friend class instance;

    /**
     * Linked list of named xml node locations.
     */
    class __LOCAL keymap : public LinkedObject
    {
    public:
        service::keynode *node;
        const char *id;
    };

    keynode root;
    stringbuf<1024> buffer;
    LinkedObject *keys[CONFIG_KEY_SIZE];
    const char *contact;

    static service *cfg;
    static condlock_t locking;

    /**
     * Add attributes in a XML entity as child nodes of the xml node.
     * @param node in tree of our node.
     * @param attrib string we must decompose into child nodes.
     */
    void addAttributes(keynode *node, char *attrib);
};

#define RUNLEVELS   (sizeof(callback::runlevels) / sizeof(LinkedObject *))
#define PRIORITY_RUNLEVEL   0
#define DEFAULT_RUNLEVEL    1
#define MODULE_RUNLEVEL (RUNLEVELS - 1)
#define GENERIC_RUNLEVEL (RUNLEVELS - 2)

} // namespace sipwitch

#endif
