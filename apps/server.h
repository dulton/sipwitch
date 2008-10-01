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

#include <sipwitch/sipwitch.h>
#include <eXosip2/eXosip.h>
#include <ccscript.h>
#include <config.h>

#ifdef	_MSWINDOWS_
#undef	USES_COMMANDS
#endif

#ifndef	SESSION_EXPIRES
#define	SESSION_EXPIRES	"session-expires"
#endif

#ifndef	ALLOW_EVENTS
#define	ALLOW_EVENTS	"allow-events"
#endif

#define	SECOND_TIMEOUT	(1000l)
#define	MINUTE_TIMEOUT	(SECOND_TIMEOUT * 60l)
#define	HOUR_TIMEOUT	(MINUTE_TIMEOUT * 60l)
#define	DAY_TIMEOUT		(HOUR_TIMEOUT * 24l)

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	CONFIG_KEY_SIZE 177
#define	PAGING_SIZE	(2048 * sizeof(void *))

class thread;

class __LOCAL stack : private service::callback, private mapped_reuse<MappedCall>
{
public:
	class __LOCAL session : public LinkedObject, public script::interp
	{
	public:

	private:
		friend class stack;

		int cid, did, tid;

	public:
		inline int getId(void)
			{return cid;};
	};

private:
	class __LOCAL thread : public DetachedThread
	{
	public:

	};

	class __LOCAL background : public DetachedThread, public Conditional
	{
	public:
		static void create(timeout_t interval);
		static void cancel(void);

		static background *thread;

		static void notify(void);
	
	private:
		bool cancelled;
		bool signalled;
		timeout_t interval;
		Timer expires;

		background(timeout_t sync);
		void run(void);
	};

	bool reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);
	bool check(void);

	unsigned threading, priority;
	size_t stacksize;

	volatile int timing;

	const char *volatile localnames;
	const char *volatile restricted;
	const char *volatile trusted;
	const char *volatile published;
	const char *volatile proxy;
	const char *iface;
	String agent;
	String system;
	String anon;
	unsigned short port;
	bool incoming, outgoing, dumping;
	int send101;
	timeout_t ring_timer, cfna_timer, reset_timer;
	unsigned invite_expires;

	int family, tlsmode, protocol;

	static stack sip;

public:
	stack();

	static const char *getScheme(void);
	static void getInterface(struct sockaddr *iface, struct sockaddr *dest);
	static session *create(int cid, int did, int tid);
	static void destroy(session *s);
	static void detach(session *s);
	static void clear(session *s);
	static void close(session *s);
	static session *access(int cid);
	static char *sipHostid(const char *uri, char *buf, size_t size);
	static char *sipUserid(const char *uri, char *buf, size_t size);
	static char *sipAddress(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_URI_SIZE);
	static char *sipPublish(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_URI_SIZE);
	static char *sipIdentity(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_IDENT_SIZE);
	static char *sipContact(struct sockaddr_internet *addr, char *buf, const char *user = NULL, const char *display = NULL, size_t size = MAX_URI_SIZE);
	static Socket::address *getAddress(const char *uri, Socket::address *addr = NULL);
	static void siplog(osip_message_t *msg);
	static void enableDumping(void);
	static void infomsg(session *session, eXosip_event_t *sevent);
	static void setDialog(session *session, int did);
	static int getDialog(session *session);

	inline static timeout_t ringTimeout(void)
		{return stack::sip.ring_timer;};

	inline static timeout_t cfnaTimeout(void)
		{return stack::sip.cfna_timer;};

	inline static timeout_t resetTimeout(void)
		{return stack::sip.reset_timer;};

	inline static unsigned inviteExpires(void)
		{return stack::sip.invite_expires;};
};

class __LOCAL server : public service
{
public:
	class __LOCAL image : public LinkedObject
	{
	public:
		script *image;
		const char *id;
	};

private:
	class __LOCAL methods : public stack::session
	{
	public:
	};

	class __LOCAL checks: public script::checks
	{
	public:
	};

	image *images;
	script *definitions;

	bool confirm(const char *user);
	void dump(FILE *fp);

public:
	server(const char *id);
	~server();

	static bool check(void);
	static void reload(const char *uid);
	static void utils(const char *uid);
	static void plugins(const char *argv0, const char *names);
	static void usage(void);
	static void version(void);
	static void run(const char *user);
	static void stop(void);
	static caddr_t allocate(size_t size, LinkedObject **list, volatile unsigned *count = NULL);
	static unsigned allocate(void);

	static script *getScript(const char *id);
	static image *getImages(void);
	static void release(image *img);
	static void release(script *scr);
};

END_NAMESPACE

