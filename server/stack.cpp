#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile unsigned allocated_segments = 0;
static volatile unsigned active_segments = 0;
static volatile unsigned allocated_calls = 0;
static volatile unsigned active_calls = 0;
static LinkedObject *freesegs = NULL;
static LinkedObject *freecalls = NULL;
static LinkedObject *freemaps = NULL;
static LinkedObject *active = NULL;

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
}

void stack::destroy(session *s)
{
	linked_pointer<segment> sp;

	if(!s || !s->parent)
		return;

	call *cr = s->parent;
	sp = cr->segments;
	while(sp) {
		--active_segments;
		segment *next = sp.getNext();
		if(sp->sid.cid != -1)
			sp->sid.delist(&sip.hash[sp->sid.cid]);
		sp->enlist(&freesegs);
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
	segment *sp;

	if(freesegs) {
		sp = static_cast<segment *>(freesegs);
		freesegs = sp->getNext();
	}
	else {
		++allocated_segments;
		sp = static_cast<segment *>(config::allocate(sizeof(segment)));
	}
	sp->enlist(&cr->segments);
	sp->sid.enlist(&sip.hash[cid / CONFIG_KEY_SIZE]);
	sp->sid.cid = cid;
	return &sp->sid;
}

stack::session *stack::create(MappedRegistry *rr, int cid)
{
	MappedCall *map;
	call *cr;

	sip.exlock();
	if(freemaps) {
		map = static_cast<MappedCall*>(freemaps);
		freemaps = map->getNext();
	}
	else
		map = sip.getLocked();
	if(!map) {
		sip.unlock();
		return NULL;
	}
	if(freecalls) {
		cr = static_cast<call*>(freecalls);
		freecalls = cr->getNext();
	}
	else {
		++allocated_calls;
		cr = static_cast<call*>(config::allocate(sizeof(call)));
	}
	++active_calls;
	time(&cr->map->created);
	cr->map->active = 0;
	cr->map->target[0] = 0;
	cr->map->count = 0;
	cr->source = createSession(cr, cid);
	cr->target = NULL;
	cr->segments = NULL;
	cr->enlist(&active);
	cr->count = 0;
	cr->map = map;
	strcpy(map->source, rr->userid); 
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
	service::errlog(service::DEBUG, "sip stack starting; creating %d threads at priority %d", threading, priority);
	eXosip_init();

	memset(hash, 0, sizeof(hash));

	MappedReuse::create("sipwitch.callmap", registry::getCalls());
	if(!sip)
		service::errlog(service::FAILURE, "calls could not be mapped");

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
		service::errlog(service::FAILURE, "sip cannot bind interface %s, port %d", interface, port);
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
}

void stack::stop(service *cfg)
{
	service::errlog(service::DEBUG, "sip stack stopping");
	thread::shutdown();
	Thread::yield();
	eXosip_quit();
	MappedMemory::release();
	MappedMemory::remove("sipwitch.callmap");

}

bool stack::check(void)
{
	service::errlog(service::INFO, "checking sip stack...");
	eXosip_lock();
	eXosip_unlock();
	return true;
}

void stack::snapshot(FILE *fp) 
{ 
	linked_pointer<call> cp;
	fprintf(fp, "SIP Stack:\n"); 
	access();
	fprintf(fp, "  mapped calls: %d\n", registry::getCalls());
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
	linked_pointer<service::keynode> sp = cfg->getList("sip");

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
			else if(!stricmp(key, "agent") && !isConfigured())
				agent = strdup(value);
			else if(!stricmp(key, "port") && !isConfigured())
				port = atoi(value);
			else if(!stricmp(key, "transport") && !isConfigured()) {
				if(!stricmp(value, "tcp") || !stricmp(value, "tls"))
					protocol = IPPROTO_TCP;
				if(!stricmp(value, "tls"))
					tlsmode = 1;
			}
		}
		sp.next();
	}
	return true;
}

char *stack::sipAddress(struct sockaddr_internet *addr, char *buf, size_t size)
{
	char pbuf[8];
	unsigned port;
	*buf = 0;

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
	if(sip.tlsmode) {
		string::set(buf, sizeof(buf), "sips:");
		Socket::getaddress((struct sockaddr *)addr, buf + 5, size - 5);
	}
	else {
		string::set(buf, sizeof(buf), "sip:");
		Socket::getaddress((struct sockaddr *)addr, buf + 4, size - 4);
	}
	snprintf(pbuf, sizeof(buf), ":%u", port);
	string::add(buf, size, pbuf);
	return buf;
}

stack::address *stack::getAddress(const char *addr)
{
	char buffer[256];
	char *svc;
	address *ap;
	int proto = SOCK_DGRAM;
	if(sip.protocol == IPPROTO_TCP)
		proto = SOCK_STREAM;

	if(!strnicmp(addr, "sip:", 4))
		addr += 4;

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
