#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

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
service::callback(1)
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

void stack::start(service *cfg)
{
	thread *thr;
	unsigned thidx = 0;
	service::errlog(service::DEBUG, "sip stack starting; creating %d threads at priority %d", threading, priority);
	eXosip_init();

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
	fprintf(fp, "SIP Stack:\n"); 
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
