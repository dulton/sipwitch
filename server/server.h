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

#include <gnutelephony/sipwitch.h>
#include <eXosip2/eXosip.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	CONFIG_KEY_SIZE 177

class thread;

class __LOCAL stack : private service::callback, private mapped_reuse<MappedCall>
{
private:
	friend class thread;

	class call;

	class __LOCAL background : public DetachedThread, public Conditional
	{
	public:
		static void create(timeout_t interval);
		static void signal(void);
		static void cancel(void);

	private:
		static background *thread;

		bool cancelled;
		bool signalled;
		timeout_t interval;

		background(timeout_t sync);
		void run(void);
	};

	class __LOCAL session : public LinkedObject
	{
	public:
		int cid, did;
		time_t activates;
		call *parent;
		unsigned sequence;
		sockaddr_internet address, interface;

		char contact[MAX_URI_SIZE];	// who the real destination is
		char via[MAX_URI_SIZE];		// how we get to the real destination
		char to[MAX_URI_SIZE];		// alternate "to" based on type...

		inline bool isSource(void)
			{return (this == parent->source);};

		inline bool isTarget(void)
			{return (this == parent->target);};

	};

	class __LOCAL segment : public OrderedObject
	{
	public:
		session sid;
	};

	class __LOCAL call : public LinkedObject
	{
	public:
		typedef enum
		{
			DIRECTED,
			CIRCULAR,
			TERMINAL,
			REDIRECTED,
			DISTRIBUTED
		} mode_t;

		call();

		char from[MAX_URI_SIZE];	// who the call is from
		char to[MAX_URI_SIZE];		// who is being called

		OrderedIndex segments;
		session *source;
		session *target;
		segment *select;
		MappedCall *map;
		unsigned count;
		mutex_t mutex;
		Timer timer;
		mode_t mode;
	};

	bool reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);
	bool check(void);

	static stack sip;

	unsigned threading, priority;
	size_t stacksize;

	volatile int timing;

	LinkedObject *hash[CONFIG_KEY_SIZE];
	const char *volatile restricted;
	const char *volatile trusted;
	const char *interface;
	const char *agent;
	short port;
	int send101;
	int family, tlsmode, protocol;

public:
	typedef	Socket::address address;

	stack();

	inline void access(void)
		{MappedReuse::access();};

	inline void release(void)
		{MappedReuse::release();};

	__EXPORT static session *createSession(call *cp, int cid);
	__EXPORT static session *create(MappedRegistry *rr, int cid);
	__EXPORT static void destroy(session *s);
	__EXPORT static void release(session *s);
	__EXPORT static void commit(session *s);
	__EXPORT static session *find(int cid);
	__EXPORT static session *modify(int cid);
	__EXPORT static char *sipAddress(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_URI_SIZE);
	__EXPORT static address *getAddress(const char *uri);
};

class __LOCAL config : public service
{
private:
	typedef	linked_value<profile_t, LinkedObject> profile;

	class __LOCAL keymap : public LinkedObject
	{
	public:
		service::keynode *node;
		const char *id;
	};

	LinkedObject *keys[CONFIG_KEY_SIZE];
	cidr::policy *acl;
	keynode **extmap;
	keynode *provision;
	LinkedObject *profiles;

	bool create(const char *id, keynode *node);
	keynode *find(const char *id);

	bool confirm(const char *user);
	void dump(FILE *fp);

public:
	config(char *id);

	__EXPORT static void *allocate(size_t size);
	__EXPORT static bool check(void);
	__EXPORT static profile_t *getProfile(const char *id); 
	__EXPORT static keynode *getProvision(const char *id);
	__EXPORT static keynode *getExtension(const char *id);
	__EXPORT static cidr *getPolicy(struct sockaddr *addr);
	__EXPORT static void release(cidr *access);
	__EXPORT static void release(keynode *node);
	__EXPORT static void reload(const char *uid);
	__EXPORT static void utils(const char *uid);
	__EXPORT static stack::address *getContact(const char *id);
};

class __LOCAL registry : private service::callback, private mapped_reuse<MappedRegistry> 
{ 
public: 
	class __LOCAL target : public LinkedObject 
	{ 
	public: 
		// internal hidden address indexing object
		class __LOCAL indexing : public LinkedObject
		{
		public:
			struct sockaddr *address;
			MappedRegistry *registry;
			target *getTarget(void);
		} index;
		sockaddr_internet address, interface; 
		time_t expires;
		char contact[MAX_URI_SIZE]; 
	};

private:
	class __LOCAL pattern : public LinkedObject
	{
	public:
		MappedRegistry *registry;
		unsigned priority;
		char text[MAX_USERID_SIZE];
	};

	class __LOCAL route : public LinkedObject
	{
	public:
		pattern entry;
	};

	bool check(void);
	bool reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);

	static void exclusive(MappedRegistry *rr);
	static target *createTarget(void);
	static route *createRoute(void);
	static void expire(MappedRegistry *rr);
	static MappedRegistry *find(const char *id);

	static registry reg;

	volatile time_t expires;

	const char *digest;
	const char *realm;
	unsigned prefix;
	unsigned range;

public:
	registry();

	inline static const char *getRealm(void)
		{return reg.realm;};

	inline static const char *getDigest(void)
		{return reg.digest;};

	inline static time_t getExpires(void)
		{return reg.expires;};

	inline static unsigned getPrefix(void)
		{return reg.prefix;};

	inline static unsigned getRange(void)
		{return reg.range;};

	inline void access(void)
		{MappedReuse::access();};

	inline void release(void)
		{MappedReuse::release();};

	__EXPORT static unsigned getEntries(void);
	__EXPORT static unsigned getIndex(MappedRegistry *rr);
	__EXPORT static unsigned setTargets(MappedRegistry *rr, stack::address *addr);
	__EXPORT static unsigned addTarget(MappedRegistry *rr, stack::address *via, time_t expires, const char *contact);
	__EXPORT static void addContact(MappedRegistry *rr, const char *id);
	__EXPORT static void addPublished(MappedRegistry *rr, const char *id);
	__EXPORT static void addRoute(MappedRegistry *rr, const char *pat, unsigned pri, const char *prefix, const char *suffix);
	__EXPORT static unsigned setTarget(MappedRegistry *rr, stack::address *via, time_t expires, const char *contact);
	__EXPORT static bool isExtension(const char *id);
	__EXPORT static MappedRegistry *address(struct sockaddr *addr);
	__EXPORT static MappedRegistry *contact(const char *uri);
	__EXPORT static MappedRegistry *contact(struct sockaddr *addr, const char *uid);
	__EXPORT static MappedRegistry *getExtension(const char *id);
	__EXPORT static MappedRegistry *create(const char *id);
	__EXPORT static MappedRegistry *access(const char *id);
	__EXPORT static MappedRegistry *modify(const char *id);
	__EXPORT static void release(MappedRegistry *m);
	__EXPORT static void update(MappedRegistry *m);
	__EXPORT static bool remove(const char *id);
	__EXPORT static void cleanup(void); 
};

class __LOCAL messages : public service::callback
{
private:
	class __LOCAL message : public LinkedObject
	{
	public:
		time_t expires;
		enum {
			SMS
		}	type;
		char user[MAX_USERID_SIZE];
		char from[MAX_USERID_SIZE];
		char reply[MAX_URI_SIZE];
		char text[MAX_URI_SIZE];
		
		message();
	};

	static messages manager;

	bool check(void);
	bool reload(service *cfg);
	void cleanup(void);

	static bool send(message *msg);

public:
	messages();

	static void automatic(void);
	static void update(const char *userid);
	static void sms(const char *from, const char *to, const char *text, const char *display = NULL);
};

class __LOCAL thread : private DetachedThread
{
private:
	friend class stack;

	unsigned instance;
	unsigned extension;
	cidr *access;
	service::keynode *authorized;
	MappedRegistry *destination;
	eXosip_event_t *sevent;
	char buffer[MAX_URI_SIZE];	
	char identity[MAX_USERID_SIZE];
	stack::address *via_address, *from_address, *to_address;
	osip_via_t *via_header, *origin_header;

	thread();

	void identify(void);
	bool getsource(void);
	bool unauthenticated(void);
	bool authenticate(void);
	void registration(void);
	void reregister(const char *contact, time_t interval);
	void deregister(void);
	void challenge(void);
	void options(void);
	void run(void);

public:
	__EXPORT static void shutdown(void);
};

END_NAMESPACE

