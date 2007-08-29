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

#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile unsigned allocated_segments = 0;
static volatile unsigned active_segments = 0;
static volatile unsigned allocated_calls = 0;
static volatile unsigned active_calls = 0;
static unsigned mapped_calls = 0;
static LinkedObject *freesegs = NULL;
static LinkedObject *freecalls = NULL;
static LinkedObject *freemaps = NULL;
static LinkedObject *active = NULL;

stack::background *stack::background::thread = NULL;

static bool tobool(const char *s)
{
	switch(*s)
	{
	case 'n':
	case 'N':
	case 'f':
	case 'F':
	case '0':
		return false;
	}
	return true;
}

stack stack::sip;

stack::call::call() : LinkedObject(), segments()
{
}

stack::background::background(timeout_t iv) : DetachedThread(), Conditional()
{
	cancelled = false;
	signalled = false;
	interval = iv;
}

void stack::background::create(timeout_t iv)
{
	thread = new background(iv);
	thread->start();
}

void stack::background::cancel(void)
{
	thread->Conditional::lock();
	thread->cancelled = true;
	thread->Conditional::signal();
	thread->Conditional::unlock();
}

void stack::background::signal(void)
{
	thread->Conditional::lock();
	thread->signalled = true;
	thread->Conditional::signal();
	thread->Conditional::unlock();
}

void stack::background::run(void)
{
	process::errlog(DEBUG1, "starting background thread");

	for(;;) {
		Conditional::lock();
		if(cancelled) {
			Conditional::unlock();
			process::errlog(DEBUG1, "stopping background thread");
			thread = NULL;
			DetachedThread::exit();
		}
		if(!signalled)
			Conditional::wait(interval);
		signalled = false;
		Conditional::unlock();
		messages::automatic();
		eXosip_lock();		
		eXosip_automatic_action();
		eXosip_unlock();
	}
}

stack::stack() :
service::callback(1), mapped_reuse<MappedCall>()
{
	stacksize = 0;
	threading = 2;
	priority = 1;
	timing = 500;
	interface = NULL;
	protocol = IPPROTO_UDP;
	port = 5060;
	family = AF_INET;
	tlsmode = 0;
	send101 = 1;
	agent = "sipwitch";
	restricted = trusted = NULL;
}

void stack::destroy(session *s)
{
	linked_pointer<segment> sp;
	LinkedObject *lo;

	if(!s || !s->parent)
		return;

	call *cr = s->parent;
	sp = cr->segments.begin();
	while(sp) {
		--active_segments;
		segment *next = sp.getNext();
		if(sp->sid.cid != -1)
			sp->sid.delist(&sip.hash[sp->sid.cid]);
		lo = static_cast<LinkedObject*>(*sp);
		lo->enlist(&freesegs);
		sp = next;
	}
	if(cr->map)
		cr->map->enlist(&freemaps);
	cr->delist(&active);
	cr->enlist(&freecalls);
	--active_calls;
	sip.release();
}

stack::session *stack::createSession(call *cr, int cid)
{
	volatile static unsigned ref = 0;
	segment *sp;

	if(freesegs) {
		sp = static_cast<segment *>(freesegs);
		freesegs = sp->getNext();
	}
	else {
		++allocated_segments;
		sp = static_cast<segment *>(config::allocate(sizeof(segment)));
	}
	memset(sp, 0, sizeof(session));
	sp->enlist(&cr->segments);
	sp->sid.enlist(&sip.hash[cid / CONFIG_KEY_SIZE]);
	sp->sid.cid = cid;
	sp->sid.sequence = ++ref;
	return &sp->sid;
}

stack::session *stack::create(MappedRegistry *rr, int cid)
{
	call *cr;
	caddr_t mp;

	sip.exlock();
	if(freecalls) {
		mp = reinterpret_cast<caddr_t>(freecalls);
		freecalls = freecalls->getNext();
	}
	else {
		++allocated_calls;
		mp = static_cast<caddr_t>(config::allocate(sizeof(call)));
	}
	memset(mp, 0, sizeof(call));
	cr = new(mp) call();
	++active_calls;
	cr->source = createSession(cr, cid);
	cr->target = NULL;
	cr->enlist(&active);
	cr->count = 0;
	return cr->source;
}

stack::session *stack::modify(int cid)
{
	linked_pointer<session> sp;

	sip.exlock();
	sp = sip.hash[cid / CONFIG_KEY_SIZE];
	while(sp) {
		if(sp->cid == cid)
			break;
		sp.next();
	}
	if(!sp) {
		sip.unlock();
		return NULL;
	}
	return *sp;
}

stack::session *stack::find(int cid)
{
	linked_pointer<session> sp;

	sip.access();
	sp = sip.hash[cid / CONFIG_KEY_SIZE];
	while(sp) {
		if(sp->cid == cid)
			break;
		sp.next();
	}
	if(!sp) {
		sip.release();
		return NULL;
	}
	sp->parent->mutex.lock();
	return *sp;
}

void stack::commit(session *s)
{
	if(s)
		sip.unlock();
}

void stack::release(session *s)
{
	if(s) {
		s->parent->mutex.release();
		sip.release();
	}
}
	
void stack::start(service *cfg)
{
	thread *thr;
	unsigned thidx = 0;
	process::errlog(DEBUG1, "sip stack starting; creating %d threads at priority %d", threading, priority);
	eXosip_init();

	memset(hash, 0, sizeof(hash));

	MappedReuse::create("sipwitch.callmap", mapped_calls);
	if(!sip)
		process::errlog(FAILURE, "calls could not be mapped");

#ifdef	AF_INET6
	if(protocol == AF_INET6)
		eXosip_enable_ipv6(1);
#endif

	if(eXosip_listen_addr(protocol, interface, port, family, tlsmode)) {
#ifdef	AF_INET6
		if(!interface && protocol == AF_INET6)
			interface = "::*";
#endif
		if(!interface)
			interface = "*";
		process::errlog(FAILURE, "sip cannot bind interface %s, port %d", interface, port);
	}

	osip_trace_initialize_syslog(TRACE_LEVEL0, "sipwitch");
	eXosip_set_user_agent(agent);

#ifdef	EXOSIP2_OPTION_SEND_101
	eXosip_set_option(EXOSIP_OPT_DONT_SEND_101, &send101); 
#endif

	while(thidx++ < threading) {
		thr = new thread();
		thr->start();
	}
	
	background::create(timing);
}

void stack::stop(service *cfg)
{
	process::errlog(DEBUG1, "sip stack stopping");
	background::cancel();
	thread::shutdown();
	Thread::yield();
	eXosip_quit();
	MappedMemory::release();
	MappedMemory::remove("sipwitch.callmap");

}

bool stack::check(void)
{
	process::errlog(INFO, "checking sip stack...");
	eXosip_lock();
	eXosip_unlock();
	return true;
}

void stack::snapshot(FILE *fp) 
{ 
	linked_pointer<call> cp;
	fprintf(fp, "SIP Stack:\n"); 
	access();
	fprintf(fp, "  mapped calls: %d\n", mapped_calls);
	fprintf(fp, "  active calls: %d\n", active_calls);
	fprintf(fp, "  active segments: %d\n", active_segments);
	fprintf(fp, "  allocated calls: %d\n", allocated_calls);
	fprintf(fp, "  allocated segments: %d\n", allocated_segments);
	cp = active;
	while(cp) {
		cp.next();
	}
	release();
} 

bool stack::reload(service *cfg)
{
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("stack");
	int val;

	while(sp) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			if(!stricmp(key, "threading") && !isConfigured())
				threading = atoi(value);
			else if(!stricmp(key, "priority") && !isConfigured())
				priority = atoi(value);
			else if(!stricmp(key, "timing"))
				timing = atoi(value);
			else if(!stricmp(key, "interface") && !isConfigured()) {
#ifdef	AF_INET6
				if(strchr(value, ':') != NULL)
					family = AF_INET6;
#endif
				if(!strcmp(value, ":::") || !strcmp(value, "::*") || !stricmp(value, "*") || !*value)
					value = NULL;
				if(value)
					value = strdup(value);
				interface = value;
			}
			else if(!stricmp(key, "send101") && !isConfigured() && tobool(value))
				send101 = 0;
			else if(!stricmp(key, "keepalive") && !isConfigured()) {
				val = atoi(value);
				eXosip_set_option(EXOSIP_OPT_UDP_KEEP_ALIVE, &val);
			} 
			else if(!stricmp(key, "learn") && !isConfigured()) {
				val = tobool(value);
				eXosip_set_option(EXOSIP_OPT_UDP_LEARN_PORT, &val);
			}
			else if(!stricmp(key, "restricted"))
				restricted = cfg->dup(value);
			else if(!stricmp(key, "trusted"))
				trusted = cfg->dup(value);
			else if(!stricmp(key, "agent") && !isConfigured())
				agent = strdup(value);
			else if(!stricmp(key, "port") && !isConfigured())
				port = atoi(value);
			else if(!stricmp(key, "mapped") && !isConfigured())
				mapped_calls = atoi(value);
			else if(!stricmp(key, "transport") && !isConfigured()) {
				if(!stricmp(value, "tcp") || !stricmp(value, "tls"))
					protocol = IPPROTO_TCP;
				else if(!stricmp(value, "tls"))
					tlsmode = 1;
			}
		}
		sp.next();
	}
	if(!mapped_calls)
		mapped_calls = registry::getEntries();
	return true;
}

char *stack::sipAddress(struct sockaddr_internet *addr, char *buf, const char *user, size_t size)
{
	char pbuf[8];
	unsigned port;
	*buf = 0;
	size_t len;

	if(!size)
		size = MAX_URI_SIZE;

	if(!addr)
		return NULL;

	switch(addr->sa_family) {
	case AF_INET:
		port = ntohs(addr->ipv4.sin_port);
		break;
#ifdef	AF_INET6
	case AF_INET6:
		port = ntohs(addr->ipv6.sin6_port);
		break;
#endif
	default:
		return NULL;
	}
	if(!port)
		port = sip.port;

	if(sip.tlsmode)
		string::set(buf, sizeof(buf), "sips:");
	else 
		string::set(buf, sizeof(buf), "sip:");

	if(user) {
		string::add(buf, sizeof(buf), user);
		string::add(buf, sizeof(buf), "@");
	}

	len = strlen(buf);
	Socket::getaddress((struct sockaddr *)addr, buf + len, size - len);
	snprintf(pbuf, sizeof(buf), ":%u", port);
	string::add(buf, size, pbuf);
	return buf;
}
	
stack::address *stack::getAddress(const char *addr)
{
	char buffer[MAX_URI_SIZE];
	char *svc;
	address *ap;
	int proto = SOCK_DGRAM;
	if(sip.protocol == IPPROTO_TCP)
		proto = SOCK_STREAM;

	if(!strnicmp(addr, "sip:", 4))
		addr += 4;
	else if(!strnicmp(addr, "sips:", 5))
		addr += 5;

	if(strchr(addr, '@'))
		addr = strchr(addr, '@') + 1;	

	if(*addr == '[') {
		svc = strchr(addr, ']');
		if(svc)
			++svc;
		if(!svc || !*svc) {
			snprintf(buffer, sizeof(buffer), "%s:5060", addr);
			addr = buffer;
		}
	} 
	else if(strchr(addr, ':') != strrchr(addr, ':')) {
		snprintf(buffer, sizeof(buffer), "[%s]:5060", addr);
		addr = buffer;
	}
	else if(!strchr(addr, ':')) {
		snprintf(buffer, sizeof(buffer), "%s:5060", addr);
		addr = buffer;
	}

	ap = new address(addr, sip.family, proto);
	if(ap && !ap->getList()) {
		delete ap;
		addr = NULL;
	}
	return ap;
}

END_NAMESPACE
