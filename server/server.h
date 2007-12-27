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
#include <ucommon/socket.h>
#include <eXosip2/eXosip.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	CONFIG_KEY_SIZE 177

class thread;

class __LOCAL stack : private service::callback, private mapped_reuse<MappedCall>, public TimerQueue
{
private:
	friend class thread;

	class call;

	class __LOCAL background : public DetachedThread, public Conditional
	{
	public:
		static void create(timeout_t interval);
		static void cancel(void);

		static background *thread;

		static void signal(void);
	
	private:
		bool cancelled;
		bool signalled;
		timeout_t interval;
		Timer expires;

		background(timeout_t sync);
		void run(void);
	};

	class __LOCAL session : public LinkedObject
	{
	public:
		MappedRegistry *registry;
		int cid, did;
		time_t activates;
		uint32_t sequence;
		call *parent;
		struct sockaddr_internet address;
		struct sockaddr_internet iface;
		time_t expires;					// session/invite expires...
		time_t ringing;					// ring no-answer timer...

		enum {OPEN, CLOSED, RING, BUSY, FWD, REORDER} state;

		char sdp[1024];					// sdp body to use in exchange
		char identity[MAX_URI_SIZE];	// our effective contact/to point...
		char sysident[MAX_IDENT_SIZE];	// ident of this session
		char display[MAX_DISPLAY_SIZE];	// displayed caller name

		char authid[MAX_USERID_SIZE];	// for authentication...
		char secret[MAX_USERID_SIZE];
		enum {NONE, DIGEST}	authtype;

		inline bool isSource(void)
			{return (this == parent->source);};

		inline bool isTarget(void)
			{return (this == parent->target);};
	};

	class __LOCAL segment : public OrderedObject
	{
	public:
		inline segment() : OrderedObject() {};

		session sid;
	};

	class __LOCAL call : public TimerQueue::event
	{
	public:
		enum {DIRECTED, CIRCULAR, TERMINAL, REDIRECTED, DISTRIBUTED} mode;

		enum {LOCAL, INCOMING, OUTGOING, REFER} type;

		enum {INITIAL, RINGING, REORDER, HOLDING, ACTIVE, BUSY, FINAL} state;

		call();

		char dialed[MAX_IDENT_SIZE];	// user or ip address...
		char subject[MAX_URI_SIZE];		// call subject

		void expired(void);
		void closing(session *s);
		void disconnect(void);
		void update(void);

		OrderedIndex segments;
		session *source;
		session *target;
		segment *select;
		MappedCall *map;
		unsigned count;			// total open segments
		unsigned invited;		// pending segments with invites
		unsigned ringing;		// number of ringing segments
		unsigned ringbusy;		// number of busy segments
		unsigned unreachable;	// number of unreachable segments
		unsigned forwarding;	// number of forwarding segments
		time_t expires, starting;
		mutex_t mutex;
	};

	bool reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);
	bool check(void);
	void update(void);
	void modify(void);

	static stack sip;

	unsigned threading, priority;
	size_t stacksize;

	volatile int timing;

	const char *volatile localnames;
	const char *volatile restricted;
	const char *volatile trusted;
	const char *volatile published;
	const char *iface;
	const char *agent;
	short port;
	bool incoming, outgoing;
	int send101;
	int family, tlsmode, protocol;

    __EXPORT static session *createSession(call *cp, int cid, int did);

public:
	typedef	Socket::address address;

	stack();

	__EXPORT static void logCall(const char *reason, session *session, const char *joined = NULL);
	__EXPORT static void setBusy(int tid, session *session);
	__EXPORT static void getInterface(struct sockaddr *iface, struct sockaddr *dest);
	__EXPORT static session *create(int cid, int did);
	__EXPORT static void destroy(session *s);
	__EXPORT static void destroy(call *cr);
	__EXPORT static void release(session *s);
	__EXPORT static void clear(session *s);
	__EXPORT static void close(session *s);
	__EXPORT static session *access(int cid);
	__EXPORT static char *sipAddress(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_URI_SIZE);
	__EXPORT static char *sipIdentity(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_IDENT_SIZE);
	__EXPORT static address *getAddress(const char *uri, address *addr = NULL);
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

	__EXPORT static bool check(void);
	__EXPORT static profile_t *getProfile(const char *id); 
	__EXPORT static keynode *getRouting(const char *id);
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
	class pointer
	{
	private:
		MappedRegistry *entry;

	public:
		pointer();
		pointer(const char *id);
		pointer(pointer const &copy);
		~pointer();
		
		void operator=(MappedRegistry *ptr);
		
		inline operator bool()
			{return entry != NULL;};

		inline bool operator!()
			{return entry == NULL;};

		inline MappedRegistry *operator->()
			{return entry;};

		inline MappedRegistry *operator*()
			{return entry;};
	};

	class target : public LinkedObject 
	{ 
	public: 
		// internal hidden address indexing object
		class indexing : public LinkedObject
		{
		public:
			struct sockaddr *address;
			MappedRegistry *registry;
			target *getTarget(void);
		} index;
		struct sockaddr_internet address;
		struct sockaddr_internet iface; 
		volatile time_t expires;
		char contact[MAX_URI_SIZE]; 
	};

	class pattern : public LinkedObject
	{
	public:
		MappedRegistry *registry;
		unsigned priority;
		char text[MAX_USERID_SIZE];
		char prefix[MAX_USERID_SIZE];
		char suffix[MAX_USERID_SIZE];
	};

private:
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
	unsigned routes;

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

	inline static unsigned getRoutes(void)
		{return reg.routes;};

	__EXPORT static unsigned getEntries(void);
	__EXPORT static unsigned getIndex(MappedRegistry *rr);
	__EXPORT static unsigned setTargets(MappedRegistry *rr, stack::address *addr);
	__EXPORT static unsigned addTarget(MappedRegistry *rr, stack::address *via, time_t expires, const char *contact);
	__EXPORT static void addContact(MappedRegistry *rr, const char *id);
	__EXPORT static void addPublished(MappedRegistry *rr, const char *id);
	__EXPORT static void addRoute(MappedRegistry *rr, const char *pat, unsigned pri, const char *prefix, const char *suffix);
	__EXPORT static unsigned setTarget(MappedRegistry *rr, stack::address *via, time_t expires, const char *contact);
	__EXPORT static bool isExtension(const char *id);
	__EXPORT static bool isUserid(const char *id);
	__EXPORT static MappedRegistry *address(struct sockaddr *addr);
	__EXPORT static MappedRegistry *contact(const char *uri);
	__EXPORT static MappedRegistry *contact(struct sockaddr *addr, const char *uid);
	__EXPORT static MappedRegistry *getExtension(const char *id);
	__EXPORT static MappedRegistry *create(const char *id);
	__EXPORT static MappedRegistry *access(const char *id);
	__EXPORT static MappedRegistry *invite(const char *id);
	__EXPORT static pattern *getRouting(unsigned trs, const char *id);
	__EXPORT static void release(MappedRegistry *m);
	__EXPORT static bool refresh(MappedRegistry *m, stack::address *adddr, time_t expires);
	__EXPORT static bool remove(const char *id);
	__EXPORT static void cleanup(time_t period); 
	__EXPORT static void deactivate(MappedRegistry *m);
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
		bool self;
		char user[MAX_USERID_SIZE];
		char from[MAX_USERID_SIZE];
		char reply[MAX_URI_SIZE];
		char text[MAX_URI_SIZE];
		
		void create();
	};

	static messages manager;

	bool check(void);
	bool reload(service *cfg);
	void cleanup(void);
	void snapshot(FILE *fp);

	static message *create(const char *reply, const char *display);
	static bool send(message *msg);

public:
	messages();

	static void automatic(void);
	static void update(const char *userid);
	static bool sms(const char *reply, const char *to, const char *text, const char *from = NULL);
};


class __LOCAL thread : private DetachedThread
{
private:
	friend class stack;

	unsigned instance;
	unsigned extension;
	cidr *access;
	service::keynode *authorized;
	service::keynode *dialed;
	MappedRegistry *registry;
	eXosip_event_t *sevent;
	char buffer[MAX_URI_SIZE];	
	char identbuf[MAX_USERID_SIZE + 12];
	char identity[MAX_USERID_SIZE];
	char dialing[MAX_USERID_SIZE];
	char display[MAX_DISPLAY_SIZE];
	struct sockaddr_internet iface;
	stack::address *via_address, *from_address, *request_address;
	stack::session *session;
	osip_header_t *header;
	long header_expires;
	osip_via_t *via_header, *origin_header;
	osip_from_t *from;
	osip_to_t *to;
	osip_uri_t *uri;

	enum {EXTERNAL, LOCAL, PUBLIC, ROUTED} destination;
	enum {CALL, MESSAGE, NONE} authorizing;

	thread();

	static void wait(unsigned count);

	void send_reply(int error);
	void expiration(void);
	void invite(void);
	void identify(void);
	bool getsource(void);
	bool unauthenticated(void);
	bool authenticate(void);
	bool authorize(void);
	void registration(void);
	void reregister(const char *contact, time_t interval);
	void deregister(void);
	void challenge(void);
	void options(void);
	void run(void);
	void getDevice(MappedRegistry *rr);
	const char *getIdent(void);

public:
	__EXPORT static void shutdown(void);
};

__EXPORT caddr_t allocate(size_t size, LinkedObject **list, volatile unsigned *count);

END_NAMESPACE

