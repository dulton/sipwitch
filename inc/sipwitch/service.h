// Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
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

#ifndef	_SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT service : public mempager
{
public:
	typedef treemap<char *>keynode;
	
	typedef struct {
		const char *key;
		const char *value;
	} define;

	class pointer 
	{
	private:
		keynode *node;

	public:
		pointer();
		pointer(const char *path);
		pointer(pointer const&);
		~pointer();
		
		inline operator bool()
			{return node != NULL;};

		inline bool operator!()
			{return node == NULL;};

		void operator=(keynode *node);

		inline keynode *operator*()
			{return node;};

		inline keynode *operator->()
			{return node;};
	};

	class __EXPORT instance
	{
	private:
		int state;
	
	public:
		instance();
		~instance();
		
		inline const service *operator->()
			{return service::cfg;};
	};

	class __EXPORT subscriber : public LinkedObject
	{
	protected:
		friend class service;

		static rwlock_t locking;
		static LinkedObject *list;

		subscriber(const char *p, const char *listen = NULL);
		void reopen(const char *listen);
		void write(char *str);
		void close(void);

		mutex_t mutex;
		fd_t fd;
		char listen[80];
		char path[1];
	};

	class __EXPORT callback : public OrderedObject
    {
	protected:
		friend class service;

		const char *id;
		unsigned runlevel;
		bool active_flag;

		static LinkedObject *runlevels[4];
		static unsigned count;

        callback(unsigned level = 0, const char *id = NULL);
        virtual ~callback();

		inline void *alloc(service *cfgp, size_t size)
			{return cfgp->alloc_locked(size);};

		inline char *dup(service *cfgp, const char *s)
			{return cfgp->dup_locked(s);};

		inline bool isConfigured(void)
			{return service::cfg != NULL;};

		inline bool isActive(void)
			{return active_flag;};

		virtual bool check(void);
		virtual void snapshot(FILE *fp);
		virtual void start(service *cfg);
		virtual void stop(service *cfg);
		virtual bool reload(service *cfg);
    };
    
	service(char *name, size_t s = 0);
	virtual ~service();

	bool load(FILE *fp, keynode *node = NULL);
	keynode *getPath(const char *path);
	keynode *getNode(keynode *base, const char *id, const char *value);	
	keynode *addNode(keynode *base, define *defs);
	keynode *addNode(keynode *base, const char *id, const char *value);
	keynode *getNode(keynode *base, const char *grp, const char *attr, const char *value);
	keynode *getList(const char *path);

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
	static void unsubscribe(const char *path);
	static void subscribe(const char *path, const char *cmds = NULL);
	static void publish(const char *path, const char *fmt, ...) __PRINTF(2, 3);
	static void result(const char *value);
	static FILE *open(const char *uid = NULL, const char *cfgpath = NULL);
	static void startup(void);
	static void shutdown(void);
	static void snmptrap(unsigned id, const char *descr);
	static long uptime(void);
	static bool match(const char *digits, const char *pattern, bool partial);

	static callback *getComponent(const char *id);
	static keynode *getProtected(const char *path);
	static keynode *path(const char *p);
	static keynode *list(const char *p);

	inline static keynode *getEnviron(void)
		{return getProtected("environ");};

	virtual void dump(FILE *fp);
	virtual bool confirm(const char *user);
	bool commit(const char *user);

	static bool check(void);
	static void release(keynode *node);

protected:
	friend class instance;

	static service *cfg;
	static condlock_t locking;
	
	keynode root;
	stringbuf<1024> buffer;

	void setHeader(const char *header);

private:
	void __LOCAL addAttributes(keynode *node, char *astr);

	class __LOCAL snmpserver : public LinkedObject
	{
	public:
		struct sockaddr_internet server;
	};

	snmpserver *snmpservers;
	const char *community;
};

END_NAMESPACE

#endif
