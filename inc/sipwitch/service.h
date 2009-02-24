// Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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
#define	_SIPWITCH_SERVICE_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	_UCOMMON_FSYS_H_
#include <ucommon/fsys.h>
#endif

#ifndef	_SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

#ifndef	_SIPWITCH_MAPPED_H_
#include <sipwitch/mapped.h>
#endif

#ifndef	_SIPWITCH_RTPPROXY_H_
#include <sipwitch/rtpproxy.h>
#endif

#ifndef	_SIPWITCH_PROCESS_H_
#include <sipwitch/process.h>
#endif

#ifndef	_SIPWITCH_CDR_H_
#include <sipwitch/cdr.h>
#endif

#define	CONFIG_KEY_SIZE 177

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT service : public memalloc
{
public:
	typedef treemap<char *>keynode;
	typedef	enum {EXT_DIALING, USER_DIALING, ALL_DIALING} dialmode_t;

	typedef struct {
		const char *key;
		const char *value;
	} define;

	class __EXPORT usernode
	{
	public:
		service::keynode *keys;
		service *heap;
		usernode();
	};

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
			{return node != NULL;};

		inline bool operator!() const
			{return node == NULL;};

		void operator=(keynode *node);

		inline keynode *operator*() const
			{return node;};

		inline keynode *operator->() const
			{return node;};
	};

	class __EXPORT instance
	{
	private:
		int state;
	
	public:
		instance();
		~instance();
		
		inline const service *operator->() const
			{return service::cfg;};
	};

	class __EXPORT callback : public OrderedObject
    {
	protected:
		friend class service;
		friend class modules;

		unsigned runlevel;
		bool active_flag;

		static LinkedObject *runlevels[4];
		static unsigned count;
		static unsigned short sip_port;
		static int sip_protocol;
		static int sip_family;
		static int sip_tlsmode;

        callback(int level = 0);
        virtual ~callback();

		inline static void *alloc(service *cfgp, size_t size)
			{return cfgp->alloc(size);};

		inline static char *dup(service *cfgp, const char *s)
			{return cfgp->dup(s);};

		inline static bool isConfigured(void) 
			{return service::cfg != NULL;};

		inline bool isActive(void) const
			{return active_flag;};

		virtual void period(long slice);
		virtual void cdrlog(cdr *call);
		virtual void errlog(errlevel_t level, const char *text);
		virtual bool check(void);
		virtual void snapshot(FILE *fp);
		virtual void start(service *cfg);
		virtual void stop(service *cfg);
		virtual void reload(service *cfg);
    };
    
	service(const char *name, size_t s = 0);
	virtual ~service();

	static volatile dialmode_t dialmode;

	bool load(FILE *fp, keynode *node = NULL);
	keynode *getPath(const char *path);
	keynode *getNode(keynode *base, const char *id, const char *value);	
	keynode *addNode(keynode *base, define *defs);
	keynode *addNode(keynode *base, const char *id, const char *value);
	keynode *getNode(keynode *base, const char *grp, const char *attr, const char *value);
	keynode *getList(const char *path);

	inline static LinkedObject *getModules(void)
		{return service::callback::runlevels[3];};

	inline static bool isLinked(keynode *node) 
		{return node->isLeaf();};

	inline static bool isValue(keynode *node)
		{return (node->getPointer() != NULL);};

	inline static bool isUndefined(keynode *node)
		{return !isLinked(node) && !isValue(node);};

	inline static bool isNode(keynode *node)
		{return isLinked(node) && isValue(node);};
	
	static const char *getValue(keynode *base, const char *id);
	static void dump(FILE *fp, keynode *node, unsigned level);
	static void snapshot(const char *uid);
	static void dumpfile(const char *uid);
	static bool period(long slice);
	static void result(const char *value);
	static FILE *open(const char *uid = NULL, const char *cfgpath = NULL);
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
		{return getProtected("environ");};

	virtual void dump(FILE *fp);
	virtual void confirm(const char *user);
	void commit(const char *user);

	static bool check(void);
	static void release(keynode *node);

protected:
	friend class instance;

	class __LOCAL keymap : public LinkedObject
	{
	public:
		service::keynode *node;
		const char *id;
	};
	
	keynode root;
	stringbuf<1024> buffer;
	LinkedObject *keys[CONFIG_KEY_SIZE];

	static service *cfg;
	static condlock_t locking;

	void setHeader(const char *header);
	void clearId(void);

private:
	void __LOCAL addAttributes(keynode *node, char *astr);
};

#define	RUNLEVELS	(sizeof(callback::runlevels) / sizeof(LinkedObject *))
#define	MODULE_RUNLEVEL	(RUNLEVELS - 1)
#define	GENERIC_RUNLEVEL (RUNLEVELS - 2)


END_NAMESPACE

#endif
