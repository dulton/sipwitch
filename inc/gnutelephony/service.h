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

#ifndef _GNUTELEPHONY_SERVICE_H_
#define	_GNUTELEPHONY_SERVICE_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

NAMESPACE_UCOMMON

class __EXPORT service : public mempager
{
public:
	typedef enum
	{
		FAILURE = 0,
		ERROR,
		WARN,
		NOTIFY,
		NOTICE=NOTIFY,
		INFO,
		DEBUG1,
		DEBUG2,
		DEBUG3
	} errlevel_t;

	typedef treemap<char *>keynode;
	
	typedef struct {
		const char *key;
		const char *value;
	} define;

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

		subscriber(const char *p);
		void reopen(void);
		void write(char *str);
		void close(void);

		mutex_t mutex;
		fd_t fd;
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
	const char *getValue(keynode *base, const char *id, keynode *copy = NULL);
	keynode *getList(const char *path);

	inline static bool isLinked(keynode *node)
		{return node->isLeaf();};

	inline static bool isValue(keynode *node)
		{return (node->getPointer() != NULL);};

	inline static bool isUndefined(keynode *node)
		{return !isLinked(node) && !isValue(node);};

	inline static bool isNode(keynode *node)
		{return isLinked(node) && isValue(node);};
	
	inline static void setVerbose(errlevel_t idx)
		{verbose = idx;};

	static void dump(FILE *fp, keynode *node, unsigned level);
	static void snapshot(const char *id, const char *uid);
	static void dumpfile(const char *id, const char *uid);
	static void unsubscribe(const char *path);
	static void subscribe(const char *path);
	static void publish(const char *path, const char *fmt, ...) __PRINTF(2, 3);
	static void errlog(errlevel_t log, const char *fmt, ...) __PRINTF(2, 3);
	static bool control(const char *id, const char *uid, const char *fmt, ...) __PRINTF(3, 4);
	static void result(const char *value);
	static char *receive(void);
	static void reply(const char *err = NULL);
	static void util(const char *id);
	static void foreground(const char *id, const char *uid = NULL, const char *cfgpath = NULL, unsigned priority = 0, size_t ps = 0);
	static void background(const char *id, const char *uid = NULL, const char *cfgpath = NULL, unsigned priority = 0, size_t ps = 0);
	static FILE *open(const char *id, const char *uid = NULL, const char *cfgpath = NULL);
	static void startup(bool restarable = false);
	static void shutdown(void);

	static callback *getComponent(const char *id);
	static keynode *getProtected(const char *path);

	virtual void dump(FILE *fp);
	virtual bool confirm(const char *user);
	bool commit(const char *user);

	static bool check(void);
	static void release(keynode *node);

protected:
	friend class instance;

	static service *cfg;
	static condlock_t locking;
	static errlevel_t verbose;
	
	keynode root;
	stringbuf<1024> buffer;

private:
	void __LOCAL addAttributes(keynode *node, char *astr);
};

END_NAMESPACE

#endif
