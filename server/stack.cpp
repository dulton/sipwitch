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

#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile unsigned allocated_segments = 0;
static volatile unsigned active_segments = 0;
static volatile unsigned allocated_calls = 0;
static volatile unsigned allocated_maps = 0;
static volatile unsigned active_calls = 0;
static unsigned mapped_calls = 0;
static LinkedObject *freesegs = NULL;
static LinkedObject *freecalls = NULL;
static LinkedObject *freemaps = NULL;
static LinkedObject **hash = NULL;
static unsigned keysize = 177;
static condlock_t locking;
static mutex_t mapping;

stack::background *stack::background::thread = NULL;

static bool tobool(const char *s)
{
	assert(s != NULL);

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

stack::segment::segment(call *cr, int cid, int did, int tid) : OrderedObject()
{
	assert(cr != NULL);
	assert(cid > 0);

	time_t now;

	++cr->count;
	time(&now);
	enlist(&(cr->segments));
	sid.enlist(&hash[cid % keysize]);
	sid.sequence = (uint32_t)now;
	sid.sequence &= 0xffffffffl;
	sid.expires = 0l;
	sid.cid = cid;
	sid.did = did;
	sid.tid = tid;
	sid.parent = cr;
	sid.state = session::OPEN;
	sid.sdp[0] = 0;
	sid.reg = NULL;
	sid.closed = false;

	static unsigned short sequence = 0;
	Mutex::protect(&sequence);
	process::uuid(sid.uuid, sizeof(sid.uuid), ++sequence, cid);
	Mutex::release(&sequence);
}

void *stack::segment::operator new(size_t size)
{
	assert(size == sizeof(stack::segment));

	return server::allocate(size, &freesegs, &allocated_segments);
}

void stack::segment::operator delete(void *obj)
{
	assert(obj != NULL);

	((LinkedObject*)(obj))->enlist(&freesegs);
}

void *stack::call::operator new(size_t size)
{
	assert(size == sizeof(stack::call));

	++active_calls;
	return server::allocate(size, &freecalls, &allocated_calls);
}

void stack::call::operator delete(void *obj)
{
	assert(obj != NULL);

	((LinkedObject*)(obj))->enlist(&freecalls);
	--active_calls;
}

stack::background::background(timeout_t iv) : DetachedThread(), Conditional(), expires(Timer::inf)
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

void stack::background::modify(void)
{
	thread->Conditional::lock();
}

void stack::background::signal(void)
{
	thread->signalled = true;
	thread->Conditional::signal();
	thread->Conditional::unlock();
}

void stack::background::run(void)
{
	process::errlog(DEBUG1, "starting background thread");
	timeout_t timeout;

	for(;;) {
		Conditional::lock();
		if(cancelled) {
			Conditional::unlock();
			process::errlog(DEBUG1, "stopping background thread");
			thread = NULL;
			return;	// exits thread...
		}
		timeout = expires.get();
		if(!signalled && timeout) {
			if(timeout > interval) 
				timeout = interval;
			Conditional::wait(timeout);
		}
		timeout = expires.get();
		if(signalled || !timeout) {
			signalled = false;
			// release lock in case expire calls update timer methods...
			Conditional::unlock();
			if(!timeout)
				debug(4, "background timer signalled, %d remaining\n", timeout);
			// expire() must be in the shared session lock, and may be made
			// exclusive when an expired call is destroyed.  This cannot
			// be in the conditional::lock because the event dispatch may
			// call something that arms or clears a timer and doing so
			// will callback modify to acquire the conditional mutex, 
			// otherwise the conditional mutex will be accessed recursivily...
			locking.access();
			expires = stack::sip.expire();
			locking.release();
		}
		else {
			signalled = false;
			Conditional::unlock();
		}
		messages::automatic();
		eXosip_lock();		
		eXosip_automatic_action();
		eXosip_unlock();
	}
}

stack::stack() :
service::callback(1), mapped_array<MappedCall>(), TimerQueue()
{
	stacksize = 0;
	threading = 2;
	priority = 1;
	timing = 500;
	iface = NULL;
	send101 = 1;
	dumping = false;
	incoming = false;
	outgoing = false;
	agent = "sipwitch-" VERSION "/eXosip";
	system = "sipwitch";
	anon = "anonymous";
	restricted = trusted = published = proxy = NULL;
	localnames = "localhost, localhost.localdomain";
	ring_timer = 4000;
	cfna_timer = 16000;
	reset_timer = 6000;
	invite_expires = 120;
}

void stack::enableDumping(void)
{
	char buf[128];
	const char *uid = NULL;
	service::keynode *env = service::getEnviron();

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/log/sipdump.log");
	fsys::remove(buf);
	if(env)
		uid = service::getValue(env, "USER");
	if(uid) {
		snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s/sipdump", uid);
		fsys::remove(buf);

	}
	service::release(env);
	stack::sip.dumping = true;
}

void stack::siplog(osip_message_t *msg)
{
    fsys_t log;
    const char *uid;
    service::keynode *env = service::getEnviron();
	char buf[128];
	char *text = NULL;
	size_t tlen;

	if(!msg || !stack::sip.dumping)
		return;

	osip_message_to_str(msg, &text, &tlen);
	if(text) {
	
		uid = service::getValue(env, "USER");

		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/log/sipdump.log");
		fsys::create(log, buf, fsys::ACCESS_APPEND, 0660);
		if(!is(log)) {
			snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s/sipdump", uid);
			fsys::create(log, buf, fsys::ACCESS_APPEND, 0660);
		}

		service::release(env);
		if(is(log)) {
			Mutex::protect(&stack::sip.dumping);
			fsys::write(log, text, tlen);
			fsys::write(log, "---\n\n", 5);
			Mutex::release(&stack::sip.dumping);
			fsys::close(log);
		}
		osip_free(text);
	}
}

void stack::modify(void)
{
	background::modify();
}

void stack::update(void)
{
	background::signal();
}

void stack::close(session *s)
{
	assert(s != NULL);

	call *cr;

	if(!s)
		return;

	cr = s->parent;

	if(!s->closed) {
		if(s == cr->source)
			registry::decUse(s->reg, stats::INCOMING);
		else
			registry::decUse(s->reg, stats::OUTGOING);
		s->closed = true;
	}

	Mutex::protect(cr);
	if(s->state != session::CLOSED) {
		s->state = session::CLOSED;
		if(s == cr->source)
			cr->terminateLocked();
		else
			cr->closingLocked(s);
	}
	Mutex::release(cr);
}
	
void stack::clear(session *s)
{
	assert(s != NULL);

	call *cr;

	if(!s)
		return;

	cr = s->parent;

	if(!s->closed) {
		if(s == cr->source)
			registry::decUse(s->reg, stats::INCOMING);
		else
			registry::decUse(s->reg, stats::OUTGOING);
		s->closed = true;
	}

	Mutex::protect(cr);

	if(--cr->count == 0) {
		debug(4, "clearing call %08x:%u\n", 
			cr->source->sequence, cr->source->cid);
		Mutex::release(cr);
		destroy(cr);
		return;
	}

	if(s->cid > 0) {
		Mutex::release(cr);
		locking.exclusive();
		debug(4, "clearing call %08x:%u session %08x:%u\n", 
			cr->source->sequence, cr->source->cid, s->sequence, s->cid); 
		if(s->state != session::CLOSED) {
			s->state = session::CLOSED;
			eXosip_call_terminate(s->cid, s->did);
		}
		s->delist(&hash[s->cid % keysize]);
		s->cid = 0;
		s->did = -1;
		locking.share();
	}
	else
		Mutex::release(cr);
}

void stack::destroy(session *s)
{
	assert(s != NULL);

	if(!s || !s->parent)
		return;

	destroy(s->parent);
}

void stack::setDialog(session *s, int did)
{
	assert(s != NULL && s->parent != NULL);
	Mutex::protect(s->parent);
	s->did = did;
	Mutex::release(s->parent);
}

int stack::getDialog(session *s)
{
	int did = -1;

	if(s && s->parent) {
		Mutex::protect(s->parent);
		did = s->did;
		Mutex::release(s->parent);
	}
	return did;
}

void stack::infomsg(session *source, eXosip_event_t *sevent)
{
	assert(source);
	assert(sevent);

	char type[128];
	osip_content_type_t *ct;
	osip_message_t *msg = NULL;
	osip_body_t *body = NULL;
	session *target = NULL;
	call *cr = source->parent;

	if(cr->source == source)
		target = cr->target;
	else if(cr->target == source)
		target = cr->source;

	int did = getDialog(target);
	if(did < 1)
		return;

	ct = sevent->request->content_type;
	if(!ct || !ct->type)
		return;

	osip_message_get_body(sevent->request, 0, &body);
	eXosip_lock();
	eXosip_call_build_info(did, &msg);
	if(!msg) {
		eXosip_unlock();
		return;
	}
	if(ct->subtype)
		snprintf(type, sizeof(type), "%s/%s", ct->type, ct->subtype);
	else
		snprintf(type, sizeof(type), "%s", ct->type);
	osip_message_set_content_type(msg, type);
	osip_message_set_body(msg, body->body, strlen(body->body));
	osip_message_set_header(msg, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
	osip_message_set_header(msg, ALLOW_EVENTS, "talk, hold, refer");
	eXosip_call_send_request(did, msg);
	eXosip_unlock();		
}

void stack::disjoin(call *cr)
{
	assert(cr != NULL);

	linked_pointer<segment> sp = cr->segments.begin();
	while(sp) {
		session *s = sp->get();
		if(s != cr->source) {
			if(!s->closed) {
				registry::decUse(s->reg, stats::OUTGOING);
				s->closed = true;
			}
			if(s->cid > 0 && s->state != session::CLOSED) {
				eXosip_lock();
				eXosip_call_terminate(s->cid, s->did);
				eXosip_unlock();
				s->state = session::CLOSED;
			}
		}
		sp.next();
	}
}

void stack::destroy(call *cr)
{
	assert(cr != NULL);
	MappedCall *map;

	linked_pointer<segment> sp;
	rtpproxy *rtp = NULL;

	cr->log();

	// we assume access lock was already held when we call this...

	locking.exclusive();
	sp = cr->segments.begin();
	while(sp) {
		--active_segments;
		segment *next = sp.getNext();
		
		if(!sp->sid.closed) {
			if(&(sp->sid) == cr->source)
				registry::decUse(sp->sid.reg, stats::INCOMING);
			else
				registry::decUse(sp->sid.reg, stats::OUTGOING);
			sp->sid.closed = true;
		}

		if(sp->sid.cid > 0) {
			if(sp->sid.state != session::CLOSED) {
				eXosip_lock();
				eXosip_call_terminate(sp->sid.cid, sp->sid.did);
				eXosip_unlock();
			}
			sp->sid.delist(&hash[sp->sid.cid % keysize]);
		}
		delete *sp;
		sp = next;
	}
	rtp = cr->rtp;
	map = cr->map;
	cr->delist();
	delete cr;
	locking.share();
	release(map);
	if(rtp)
		rtp->release();	
}

void stack::release(MappedCall *map)
{
	if(map) {
		String::set(map->state, sizeof(map->state), "-");
		map->created = map->active = 0;
		mapping.lock();
		map->enlist(&freemaps);
		mapping.release();
	}
}

MappedCall *stack::get(void)
{
	MappedCall *map = NULL;

	mapping.lock();
	if(freemaps) {
		map = (MappedCall *)freemaps;
		freemaps = map->getNext();
	}
	else if(allocated_maps < mapped_calls)
		map = sip(allocated_maps++);
	mapping.release();
	if(!map)
		return NULL;

	String::set(map->state, sizeof(map->state), "iinit");
	map->active = 0;
	map->authorized[0] = 0;
	map->source[0] = 0;
	map->target[0] = 0;

	time(&map->created);
	return map;
}

void stack::getInterface(struct sockaddr *iface, struct sockaddr *dest)
{
	assert(iface != NULL && dest != NULL);

	Socket::getinterface(iface, dest);
	switch(iface->sa_family) {
	case AF_INET:
		((struct sockaddr_in*)(iface))->sin_port = htons(sip_port);
		break;
#ifdef	AF_INET6
	case AF_INET6:
		((struct sockaddr_in6*)(iface))->sin6_port = htons(sip_port);
		break;
#endif
	}
}

stack::session *stack::create(call *cr, int cid)
{
	assert(cr != NULL);
	assert(cid > 0);

	locking.exclusive();
	segment *sp = new segment(cr, cid);
	++cr->invited;
	locking.share();
	return &sp->sid;
}
		
stack::session *stack::create(int cid, int did, int tid)
{
	assert(cid > 0);

	MappedCall *map = get();

	if(!map)
		return NULL;

	call *cr;
	segment *sp;

	locking.modify();
	cr = new call;
	sp = new segment(cr, cid, did, tid);	// after count set to 0!
	cr->source = &(sp->sid);
	cr->map = map;

	locking.share();
	return cr->source;
}

stack::session *stack::access(int cid)
{
	assert(cid > 0);

	linked_pointer<session> sp;

	locking.access();
	sp = hash[cid % keysize];
	while(sp) {
		if(sp->cid == cid)
			break;
		sp.next();
	}
	if(!sp) {
		locking.release();
		return NULL;
	}
	return *sp;
}

void stack::detach(session *s)
{
	if(s)
		locking.release();
}
	
void stack::start(service *cfg) 
{
	assert(cfg != NULL);
	 
	thread *thr; 
	unsigned thidx = 0;
	process::errlog(DEBUG1, "stack starting; %d maps and %d threads at priority %d", mapped_calls, threading, priority); 
	eXosip_init();

	mapped_array<MappedCall>::create(CALL_MAP, mapped_calls);
	if(!sip)
		process::errlog(FAILURE, "calls could not be mapped");
	initialize();
#ifdef	AF_INET6
	if(sip_family == AF_INET6) {
		eXosip_enable_ipv6(1);
		if(!iface)
			iface = "::0";
	}
#endif

	Socket::family(sip_family);
	if(eXosip_listen_addr(sip_protocol, iface, sip_port, sip_family, sip_tlsmode)) {
#ifdef	AF_INET6
		if(!iface && sip_family == AF_INET6)
			iface = "::0";
#endif
		if(!iface)
			iface = "*";
		process::errlog(FAILURE, "sip cannot bind interface %s, port %d", iface, sip_port);
	}

	osip_trace_initialize_syslog(TRACE_LEVEL0, (char *)"sipwitch");
	eXosip_set_user_agent(agent);

#ifdef	EXOSIP2_OPTION_SEND_101
	eXosip_set_option(EXOSIP_OPT_DONT_SEND_101, &send101); 
#endif

	while(thidx++ < threading) {
		thr = new thread();
		thr->start(priority);
	}

	thread::wait(threading);
	background::create(timing);
}

void stack::stop(service *cfg)
{
	assert(cfg != NULL);

	process::errlog(DEBUG1, "stopping sip stack");
	background::cancel();
	thread::shutdown();
	Thread::yield();
	MappedMemory::release();
	MappedMemory::remove(CALL_MAP);
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
	assert(fp != NULL);

	linked_pointer<call> cp;
	fprintf(fp, "SIP:\n"); 
	locking.access();
	fprintf(fp, "  mapped calls: %d\n", mapped_calls);
	fprintf(fp, "  active calls: %d\n", active_calls);
	fprintf(fp, "  active sessions: %d\n", active_segments);
	fprintf(fp, "  allocated calls: %d\n", allocated_calls);
	fprintf(fp, "  allocated sessions: %d\n", allocated_segments);
	cp = begin();
	while(cp) {
		cp.next();
	}
	locking.release();
} 

void stack::reload(service *cfg)
{
	assert(cfg != NULL);	

	const char *new_proxy = NULL;
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("stack");
	linked_pointer<service::keynode> tp = cfg->getList("timers");
	int val;
	const char *localhosts = "localhost, localhost.localdomain";

	unsigned cfna_value = 0;
	unsigned ring_value = 0;
	unsigned reset_value = 0;

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
			else if(!stricmp(key, "incoming"))
				incoming = tobool(value);
			else if(!stricmp(key, "outgoing"))
				outgoing = tobool(value);
			else if(!stricmp(key, "trace") || !stricmp(key, "dumping"))
				dumping = tobool(value);
			else if(!stricmp(key, "keysize") && !isConfigured())
				keysize = atoi(value);
			else if(!stricmp(key, "interface") && !isConfigured()) {
#ifdef	AF_INET6
				if(strchr(value, ':') != NULL)
					sip_family = AF_INET6;
#endif
				if(!strcmp(value, ":::") || !strcmp(value, "::0") || !strcmp(value, "::*") || !stricmp(value, "*") || !*value)
					value = NULL;
				if(value)
					value = strdup(value);
				iface = value;
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
			else if(!stricmp(key, "restricted")) {
				if(String::equal(value, "none"))
					restricted = NULL;
				else
					restricted = cfg->dup(value);
			}
			else if(!stricmp(key, "localnames"))
				localhosts = cfg->dup(value);
			else if(!stricmp(key, "trusted")) {
				if(String::equal(value, "none"))
					trusted = NULL;
				else
					trusted = cfg->dup(value);
			}
			else if(!stricmp(key, "system"))
				system = value;
			else if(!stricmp(key, "anon"))
				anon = value;
			else if(!stricmp(key, "published") || !stricmp(key, "public"))
				published = cfg->dup(value);
			else if(!stricmp(key, "proxy") || !stricmp(key, "outbound"))
				new_proxy = cfg->dup(value);
			else if(!stricmp(key, "agent") && !isConfigured())
				agent = value;
			else if(!stricmp(key, "port") && !isConfigured())
				sip_port = atoi(value);
			else if(!stricmp(key, "mapped") && !isConfigured())
				mapped_calls = atoi(value);
			else if(!stricmp(key, "transport") && !isConfigured()) {
				if(!stricmp(value, "tcp") || !stricmp(value, "tls"))
					sip_protocol = IPPROTO_TCP;
				else if(!stricmp(value, "tls"))
					sip_tlsmode = 1;
			}
		}
		sp.next();
	}

	while(is(tp)) {
		key = tp->getId();
		value = tp->getPointer();
		if(key && value) {
			if(!stricmp(key, "ring"))
				ring_value = atoi(value);
			else if(!stricmp(key, "cfna"))
				cfna_value = atoi(value); 
			else if(!stricmp(key, "reset"))
				reset_value = atoi(value);
			else if(!stricmp(key, "invite"))
				invite_expires = atoi(value);
		}
		tp.next();
	}

	localnames = localhosts;
	proxy = new_proxy;

	if(sip_family != AF_INET)
		rtpproxy::enableIPV6();

	if(ring_value && ring_value < 100)
		ring_timer = ring_value * 1000l;
	else if(ring_value >= 100)
		ring_timer = ring_value;
	
	if(cfna_value && cfna_value < 1000)
			cfna_timer = ring_timer *cfna_value;
	else if(cfna_value >= 1000)
		cfna_timer = cfna_value;

	if(reset_value && reset_value < 100)
		reset_timer = reset_value * 1000l;
	else if(reset_value >= 100)
		reset_timer = reset_value;

	if(!mapped_calls) 
		mapped_calls = registry::getEntries();
	if(!hash) {
		hash = new LinkedObject*[keysize];
		memset(hash, 0, sizeof(LinkedObject *) * keysize);
	}
}

const char *stack::getScheme(void)
{
	if(sip_tlsmode)
		return "sips";
	return "sip";
}

char *stack::sipPublish(struct sockaddr_internet *addr, char *buf, const char *user, size_t size)
{
	assert(addr != NULL);
	assert(buf != NULL);
	assert(user == NULL || *user != 0);
	assert(size > 0);

	char pbuf[10];
	bool ipv6 = false;

	if(sip.published == NULL)
		return sipAddress(addr, buf, user, size);

	if(sip_tlsmode)
		String::set(buf, size, "sips:");
	else 
		String::set(buf, size, "sip:");

	if(strchr(sip.published, ':'))
		ipv6 = true;

	if(user) {
		String::add(buf, size, user);
		if(ipv6)
			String::add(buf, size, "@[");
		else			
			String::add(buf, size, "@");
	}
	else if(ipv6)
		String::add(buf, size, "[");

	String::add(buf, size, sip.published);
	if(ipv6)
		snprintf(pbuf, sizeof(pbuf), "]:%u", sip_port);
	else
		snprintf(pbuf, sizeof(pbuf), ":%u", sip_port);
	String::add(buf, size, pbuf);
	return buf;
}

char *stack::sipAddress(struct sockaddr_internet *addr, char *buf, const char *user, size_t size)
{
	assert(addr != NULL);
	assert(buf != NULL);
	assert(user == NULL || *user != 0);
	assert(size > 0);

	char pbuf[10];
	unsigned port;
	bool ipv6 = false;

	*buf = 0;
	size_t len;

	if(!size)
		size = MAX_URI_SIZE;

	if(!addr)
		return NULL;

	switch(addr->address.sa_family) {
	case AF_INET:
		port = ntohs(addr->ipv4.sin_port);
		break;
#ifdef	AF_INET6
	case AF_INET6:
		ipv6 = true;
		port = ntohs(addr->ipv6.sin6_port);
		break;
#endif
	default:
		return NULL;
	}
	if(!port)
		port = sip_port;

	if(sip_tlsmode)
		String::set(buf, size, "sips:");
	else 
		String::set(buf, size, "sip:");

	if(user) {
		String::add(buf, size, user);
		if(ipv6)
			String::add(buf, size, "@[");
		else			
			String::add(buf, size, "@");
	}
	else if(ipv6)
		String::add(buf, size, "[");

	len = strlen(buf);
	Socket::getaddress((struct sockaddr *)addr, buf + len, size - len);
	if(ipv6)
		snprintf(pbuf, sizeof(pbuf), "]:%u", port);
	else
		snprintf(pbuf, sizeof(pbuf), ":%u", port);
	String::add(buf, size, pbuf);
	return buf;
}
	
Socket::address *stack::getAddress(const char *addr, Socket::address *ap)
{
	assert(addr != NULL && *addr != 0);

	char buffer[MAX_URI_SIZE];
	int family = sip_family;
	const char *svc = "sip";
	const char *sp;
	char *ep;
	int proto = SOCK_DGRAM;
	if(sip_protocol == IPPROTO_TCP)
		proto = SOCK_STREAM;

	sp = strchr(addr, '<');
	if(sp)
		addr = ++sp;

	if(!strnicmp(addr, "sip:", 4))
		addr += 4;
	else if(!strnicmp(addr, "sips:", 5))
		addr += 5;

	if(strchr(addr, '@'))
		addr = strchr(addr, '@') + 1;	

#ifdef	AF_INET6
	if(*addr == '[') {
		String::set(buffer, sizeof(buffer), ++addr);
		if(sp) {
			ep = strchr(buffer, '>');
			if(ep)
				*ep = 0;
		}
		family = AF_INET6;
		ep = strchr(buffer, ']');
		if(ep)
			*(ep++) = 0;
		if(*ep == ':')
			svc = ++ep;
		goto set;
	} 
#endif
	String::set(buffer, sizeof(buffer), addr);
	if(sp) {
		ep = (char *)strchr(buffer, '>');
		if(ep)
			*ep = 0;
	}
	ep = strchr(buffer, ':');
	if(ep) {
		*(ep++) = 0;
		svc = ep;
	}

set:
	if(svc) {
		ep = (char *)strchr(svc, ';');
		if(ep)
			*ep = 0;
	}

	if(ap)
		ap->add(buffer, svc, family);
	else
		ap = new Socket::address(family, buffer, svc);

	if(ap && !ap->getList()) {
		delete ap;
		ap = NULL;
	}
	return ap;
}

END_NAMESPACE
