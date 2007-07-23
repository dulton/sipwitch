#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile bool warning_registry = false;
static bool shutdown_flag = false;
static unsigned shutdown_count = 0;
static unsigned startup_count = 0;

static char *remove_quotes(char *c)
{
	char *o = c;
	char *d = c;
	if(*c != '\"')
		return c;

	++c;

	while(*c)
		*(d++) = *(c++); 

	*(--d) = 0;
	return o;
}

thread::thread() : DetachedThread(stack::sip.stacksize)
{
	config = NULL;
	registry = NULL;
}

bool thread::authorize(void)
{
	osip_message_t *reply = NULL;
	int error = 401;

	if(!authenticate())
		return false;

	registry = registry::access(identity);
	if(registry) {
		warning_registry = false;
		if(!registry->expires)
			return true;
		time(&current);
		if(registry->expires < current)
			return true;
	}
	else {
		if(!warning_registry) {
			warning_registry = true;
			service::errlog(service::WARN, "registry capacity reached");
		}
		error = 480;
	}

	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, error, &reply);
	eXosip_message_send_answer(sevent->tid, error, reply);
	eXosip_unlock();		
	return false;
}

bool thread::authenticate(void)
{
	osip_message_t *reply = NULL;
	osip_authorization_t *auth = NULL;
	service::keynode *node = NULL, *leaf;
	stringbuf<64> digest;
	int error = 407;

	auth = NULL;
	if(!sevent->request || osip_message_get_authorization(sevent->request, 0, &auth) != 0 || !auth || !auth->username || !auth->response) {
		service::errlog(service::DEBUG, "challenge request required");
		challenge();
		return false;
	}

	remove_quotes(auth->username);
	remove_quotes(auth->uri);
	remove_quotes(auth->nonce);
	remove_quotes(auth->response);

	node = config::getProvision(auth->username);
	if(!node) {
		service::errlog(service::NOTICE, "rejecting unknown %s", auth->username);
		error = 404;
		goto failed;
	}

	leaf = node->leaf("digest");
	if(!leaf || !leaf->getPointer()) {
		service::errlog(service::NOTICE, "rejecting unsupported %s", auth->username);
		error = 403;
		goto failed;
	}

	snprintf(buffer, sizeof(buffer), "%s:%s", sevent->request->sip_method, auth->uri);
	if(!stricmp(registry::getDigest(), "sha1"))
		digest::sha1(digest, buffer);
	else if(!stricmp(registry::getDigest(), "rmd160"))
		digest::rmd160(digest, buffer);
	else
		digest::md5(digest, buffer);
	snprintf(buffer, sizeof(buffer), "%s:%s:%s", leaf->getPointer(), auth->nonce, *digest);
	if(!stricmp(registry::getDigest(), "sha1"))
		digest::sha1(digest, buffer);
	else if(!stricmp(registry::getDigest(), "rmd160"))
		digest::rmd160(digest, buffer);
	else
		digest::md5(digest, buffer);
 
	if(stricmp(*digest, auth->response)) {
		service::errlog(service::NOTICE, "rejecting unauthorized %s", auth->username);
		goto failed;
	}
	config = node;
	identity = auth->username;
	return true;

failed:
	config::release(node);
	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, error, &reply);
	eXosip_message_send_answer(sevent->tid, error, reply);
	eXosip_unlock();		
	return false;
}

void thread::challenge(void)
{
	osip_message_t *reply = NULL;
	char nonce[32];
	time_t now;

	time(&now);
	snprintf(nonce, sizeof(nonce), "%08lx", now);
	snprintf(buffer, sizeof(buffer), 
		"Digest realm=\"%s\", nonce=\"%s\", algorithm=%s", 
				registry::getRealm(), nonce, registry::getDigest());

	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, 407, &reply);
	osip_message_set_header(reply, "WWW-Authenticate", buffer);
	eXosip_message_send_answer(sevent->tid, 407, reply);
	eXosip_unlock();
}

void thread::registration(void)
{	
	osip_header_t *header = NULL;
	osip_contact_t *contact = NULL;
	osip_uri_param_t *param = NULL;
	int interval = -1;
	int pos = 0;

	osip_message_get_expires(sevent->request, 0, &header);
	while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
		contact = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos++);
		if(contact && contact->url) {
			osip_contact_param_get_byname(contact, "expires", &param);
			if(param && param->gvalue)
				interval = osip_atoi(param->gvalue);
			break;
		}
	}
	if(!contact) {
		deregister(NULL);
		return;
	}

	stack::address addr(contact->url->host, contact->url->port);

	if(interval < 0 && header && header->hvalue)
		interval = atoi(header->hvalue);
	if(interval < 0)
		interval = registry::getExpires();
	if(!interval || !contact) {
		deregister(&addr);
		return;
	}
	reregister(interval, &addr);
}

void thread::reregister(time_t interval, stack::address *addr)
{
	int answer = 200;
	osip_message_t *reply = NULL;
	time_t expire;
	unsigned count;

	registry = registry::create(identity);
	if(!registry) {
		if(!warning_registry) {
			warning_registry = true;
			service::errlog(service::ERROR, "registry capacity reached");
		}
		answer = 480;
		interval = 0;
		goto reply;
	}
	warning_registry = false;
	time(&expire);
	expire += interval + 3;	// overdraft 3 seconds...
	if(registry->type == REG_USER && (registry->profile.features & USER_PROFILE_MULTITARGET))
		count = registry::addTarget(registry, addr, expire);
	else
		count = registry::setTarget(registry, addr, expire);

	Socket::getaddress(addr->getAddr(), buffer, sizeof(buffer));
	if(count)
		service::errlog(service::DEBUG, "authorizing %s for %ld seconds from %s", identity, interval, buffer);
	else {
		service::errlog(service::ERROR, "cannot authorize %s from %s", identity, buffer);
		answer = 403;
	}		

reply:
	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, answer, &reply);
	eXosip_message_send_answer(sevent->tid, answer, reply);
	eXosip_unlock();
}

void thread::deregister(stack::address *addr)
{
	service::errlog(service::DEBUG, "deauthorize %s", identity);
}

void thread::options(void)
{
    osip_message_t *reply = NULL;

    eXosip_lock();
    if(eXosip_options_build_answer(sevent->tid, 200, &reply) == 0) {
		osip_message_set_header(reply, "Accept", "application/sdp, text/plain");
		osip_message_set_header(reply, "Allow", "INVITE,ACK,CANCEL,OPTIONS,INFO,REFER,MESSAGE,SUBSCRIBE,NOTIFY,REGISTER,PRACK"); 
        eXosip_options_send_answer(sevent->tid, 200, reply);
	}
	eXosip_unlock();
}

void thread::shutdown(void)
{
	shutdown_flag = true;
	while(shutdown_count < startup_count)
		Thread::sleep(50);
}

void thread::run(void)
{
	static volatile time_t last = 0;
	time_t now;

	instance = ++startup_count;
	service::errlog(service::DEBUG, "starting thread %d", instance);

	for(;;) {
		sevent = eXosip_event_wait(0, stack::sip.timing);
		if(shutdown_flag) {
			++shutdown_count;
			service::errlog(service::DEBUG, "stopping thread %d", instance);
			delete this;
			pthread_exit(NULL);
		}

		if(!sevent)
		{
			time(&now);
			if(now != current) {
				current = now;
				eXosip_lock();
				if(now != last) {
					eXosip_automatic_action();
					last = current;
				}
				eXosip_unlock();
			}
			continue;
		}

		service::errlog(service::DEBUG, "sip: event %d; cid=%d, did=%d, rid=%d, instance=%d",
			sevent->type, sevent->cid, sevent->did, sevent->rid, instance);

		switch(sevent->type) {
		case EXOSIP_MESSAGE_NEW:
			if(!sevent->request)
				break;
			if(MSG_IS_OPTIONS(sevent->request))
				options();
			else if(MSG_IS_REGISTER(sevent->request) && authenticate())
				registration();
			break;
		default:
			service::errlog(service::WARN, "unknown message");
		}
		if(registry) {
			registry::release(registry);
			registry = NULL;
		}
		if(config) {
			config::release(config);
			config = NULL;
		}
		eXosip_event_free(sevent);
	}
}

END_NAMESPACE
