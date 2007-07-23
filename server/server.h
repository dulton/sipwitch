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

	class __LOCAL session : public LinkedObject
	{
	public:
		int cid, did;
		time_t activates;
		call *parent;
		sockaddr_internet address, interface;

		inline bool isSource(void)
			{return (this == parent->source);};

		inline bool isTarget(void)
			{return (this == parent->target);};

	};

	class __LOCAL segment : public LinkedObject
	{
	public:
		session sid;
	};

	class __LOCAL call : public LinkedObject
	{
	public:
		LinkedObject *segments;
		session *source;
		session *target;
		MappedCall *map;
		unsigned count;
		mutex_t mutex;
		Timer timer;
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
	__EXPORT static char *sipAddress(struct sockaddr_internet *addr, char *buf, size_t size);
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

	LinkedObject  *keys[CONFIG_KEY_SIZE];
	keynode **extmap;
	keynode *provision;
	LinkedObject *profiles;

	bool create(const char *id, keynode *node);
	keynode *find(const char *id);

	bool confirm(void);
	void dump(FILE *fp);

public:
	config(char *id);

	__EXPORT static void *allocate(size_t size);
	__EXPORT static bool check(void);
	__EXPORT static profile_t *getProfile(const char *id); 
	__EXPORT static keynode *getProvision(const char *id);
	__EXPORT static keynode *getExtension(const char *id);
	__EXPORT static void release(keynode *node);
	__EXPORT static void reload(void);
	__EXPORT static void utils(void);
	__EXPORT static stack::address *getContact(const char *id);
};

class __LOCAL registry : private service::callback, private mapped_reuse<MappedRegistry>
{
private:
	class __LOCAL target : public LinkedObject
	{
	public:
		sockaddr_internet address, interface;
		time_t expires;
	};

	class __LOCAL pattern : public LinkedObject
	{
	public:
		MappedRegistry *registry;
		unsigned priority;
		char text[16];
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
	unsigned calls;

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

	inline static unsigned getCalls(void)
		{return reg.calls;};

	inline void access(void)
		{MappedReuse::access();};

	inline void release(void)
		{MappedReuse::release();};

	__EXPORT static unsigned getIndex(MappedRegistry *rr);
	__EXPORT static unsigned setTargets(MappedRegistry *rr, stack::address *addr);
	__EXPORT static unsigned addTarget(MappedRegistry *rr, stack::address *addr, time_t expires);
	__EXPORT static unsigned setTarget(MappedRegistry *rr, stack::address *addr, time_t expires);
	__EXPORT static MappedRegistry *extension(const char *id);
	__EXPORT static MappedRegistry *create(const char *id);
	__EXPORT static MappedRegistry *access(const char *id);
	__EXPORT static MappedRegistry *modify(const char *id);
	__EXPORT static void release(MappedRegistry *m);
	__EXPORT static void update(MappedRegistry *m);
	__EXPORT static bool remove(const char *id);
	__EXPORT static void cleanup(void); 
public:
//	__EXPORT static ...
};

class __LOCAL thread : private DetachedThread
{
private:
	friend class stack;

	unsigned instance;
	time_t current;
	const char *identity;
	service::keynode *config;
	MappedRegistry *registry;
	eXosip_event_t *sevent;
	char buffer[256];	

	thread();

	bool authenticate(void);
	bool authorize(void);
	void registration(void);
	void reregister(time_t interval, stack::address *addr);
	void deregister(stack::address *addr);
	void challenge(void);
	void options(void);
	void run(void);

public:
	__EXPORT static void shutdown(void);
};

END_NAMESPACE

