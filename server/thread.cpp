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
	to = NULL;
	from = NULL;
	access = NULL;
	dialed = NULL;
	authorized = NULL;
	registry = NULL;
	via_address = from_address = to_address = NULL;
	local_uri = remote_uri = NULL;
}

void thread::invite()
{
	osip_message_t *reply = NULL;
	const char *target = dialing;

	if(dialed)
		target = service::getValue(dialed, "id");
	else if(registry)
		target = registry->userid;

	switch(destination) {
	case LOCAL:
		debug(1, "local call for %s from %s\n", target, identity);
		break;
	case PUBLIC:
		debug(1, "incoming call for %s from %s@%s\n", target, from->url->username, from->url->host);
		break;
	case REMOTE:
		debug(1, "outgoing call from %s to %s@%s\n", identity, to->url->username, to->url->host);
		break;
	case ROUTED:
		debug(1, "dialed call for %s from %s, dialing=%s\n", target, identity, dialing);
		break;  	
	case FORWARD:
		debug(1, "forwarding call for %s from %s, forward=%s\n", dialing, identity, target);
		break;
	}

	eXosip_lock();
	eXosip_call_build_answer(sevent->tid, SIP_NOT_FOUND, &reply);
	eXosip_call_send_answer(sevent->tid, SIP_NOT_FOUND, reply);
	eXosip_unlock();		

}

void thread::identify(void)
{
	MappedRegistry *rr = NULL;

	if(!stack::sip.trusted || !getsource() || !access)
		return;

	if(!string::ifind(stack::sip.trusted, access->getName(), ",; \t\n"))
		return;

	rr = registry::address(via_address->getAddr());
	if(!rr)
		return;

	string::set(identity, sizeof(identity), rr->userid);
	authorized = config::getProvision(identity);
	registry::release(rr);
}

bool thread::unauthenticated(void)
{
	MappedRegistry *rr = NULL;

	if(!stack::sip.trusted || !getsource() || !access)
		goto untrusted;

	if(!string::ifind(stack::sip.trusted, access->getName(), ",; \t\n"))
		goto untrusted;

	rr = registry::address(via_address->getAddr());
	if(!rr)
		goto untrusted;

	string::set(identity, sizeof(identity), rr->userid);
	authorized = config::getProvision(identity);
	registry::release(rr);
	if(authorized)
		return true;

untrusted:
	debug(2, "challenge request required");
	challenge();
	return false;
}

bool thread::authorize(void)
{
	int error = SIP_UNDECIPHERABLE;
	const char *scheme = "sip";
	const char *from_port, *to_port;
	struct sockaddr_internet iface;
	const char *cp;
	time_t now;
	unsigned level;
	profile_t *pro;
	const char *target;
	char dbuf[MAX_USERID_SIZE];
	registry::pattern *pp;
	service::keynode *fwd;

	if(!sevent->request || !sevent->request->to || !sevent->request->from)
		goto invalid;

	error = SIP_ADDRESS_INCOMPLETE;

	osip_to_to_str(sevent->request->to, &local_uri);

	if(!local_uri)
		goto invalid;

	osip_from_to_str(sevent->request->from, &remote_uri);
	if(!remote_uri)
		goto invalid;

	osip_to_init(&to);
	osip_to_parse(to, local_uri);
	if(!to)
		goto invalid;

	osip_from_init(&from);
	osip_from_parse(from, remote_uri);		
	if(!from)
		goto invalid;

	if(stack::sip.tlsmode)
		scheme = "sips";

	if(!from->url->host || !to->url->host)
		goto invalid;

	if(!from->url->username || !to->url->username)
		goto invalid;

	if(!from->url->scheme || !to->url->scheme)
		goto invalid;

	error = SIP_UNSUPPORTED_URI_SCHEME;
	if(stricmp(from->url->scheme, scheme) || stricmp(to->url->scheme, scheme))
		goto invalid;

	from_port = from->url->port;
	to_port = to->url->port;
	if(!from_port || !atoi(from_port))
		from_port = "5060";
	if(!to_port || !atoi(to_port))
		to_port = "5060";

	from_address = new stack::address(from->url->host, from_port);
	to_address = new stack::address(to->url->host, to_port);

	if(!from_address->getAddr() || !to_address->getAddr())
		goto invalid;

	if(atoi(to_port) != stack::sip.port)
		goto remote;

	if(string::ifind(stack::sip.localnames, to->url->host, " ,;:\t\n"))
		goto local;

	stack::getInterface((struct sockaddr *)&iface, to_address->getAddr());
	if(Socket::equal((struct sockaddr *)&iface, to_address->getAddr()))
		goto local;

	goto remote;

local:
	debug(2, "authorizing local; target=%s\n", to->url->username);
	target = to->url->username;
	destination = LOCAL;
	string::set(dialing, sizeof(dialing), target);

rewrite:
	debug(3, "rewrite process; target=%s, dialing=%s\n", target, dialing);
	error = SIP_NOT_FOUND;
	if(!target || !*target || strlen(target) >= MAX_USERID_SIZE)
		goto invalid;

	registry = registry::access(target);
	dialed = config::getProvision(target);

	debug(4, "rewrite process; registry=%p, dialed=%p\n", registry, dialed);

	if(!registry && !dialed)
		goto routing;

	// reject nodes with defined errors
	if(dialed && !stricmp(dialed->getId(), "reject")) {
		cp = service::getValue(dialed, "error");
		if(cp)
			error = atoi(cp);
		goto invalid;
	}

	fwd = NULL;
	if(dialed)
		fwd = dialed->leaf("forwarding");

	if(fwd) {
		cp = service::getValue(fwd, "all");
		if(registry::isUserid(cp))
			goto forwarding;
	}

	if(!registry && dialed) {
		if(fwd) {
			cp = service::getValue(fwd, "offline");
			if(registry::isUserid(cp))
				goto forwarding;
		}
		if(!stricmp(dialed->getId(), "group"))
			return authenticate();
		if(!stricmp(dialed->getId(), "refer"))
			return authenticate();
		if(!stricmp(dialed->getId(), "test"))
			return authenticate();
		if(!stricmp(dialed->getId(), "queue"))
			goto anonymous;
		process::errlog(ERROR, "unknown or invalid destination %s, type=%s\n", target, dialed->getId());
		goto invalid;
	}

	time(&now);
	if(registry && registry->expires && registry->expires < now) {
		if(!dialed)
			goto invalid;
		if(fwd)
			cp = service::getValue(fwd, "offline");
		if(fwd && registry::isUserid(cp)) {
forwarding:
			string::set(dbuf, sizeof(dbuf), cp);
			config::release(dialed);
			registry::release(registry);
			destination = FORWARD;
			string::set(dialing, sizeof(dialing), target);
			dialed = NULL;
			registry = NULL;
			target = dbuf;
			goto rewrite;
		}
	}

	if(registry && registry->status == MappedRegistry::DND) {
		error = SIP_BUSY_HERE;
		if(fwd) {
			cp = service::getValue(fwd, "dnd");
			if(registry::isUserid(cp))
				goto forwarding;
		}
		goto invalid;
	}

	// extension references always require authentication
	if(registry::isExtension(target)) {
		if(!authenticate())
			return false;
		if(!registry)
			goto invalid;
		return true;
	}

	if(registry && registry->type == MappedRegistry::USER && (registry->profile.features & USER_PROFILE_INCOMING))
		goto anonymous;

	return authenticate();

routing:
	// cannot re-route extension #s...
	if(registry::isExtension(target))
		goto invalid;

	destination = ROUTED;
	if(!authenticate() || !authorized)
		return false;

	if(!stricmp(authorized->getId(), "user")) {
		cp = service::getValue(authorized, "profile");
		if(!cp)
			cp = "*";
		pro = config::getProfile(cp);
		level = pro->level;
	}
	else
		level = registry::getRoutes();
	cp = service::getValue(authorized, "trs");
	if(cp)
		level = atoi(cp);

	if(!level)
		goto invalid;

	pp = registry::getRouting(level, target);
	if(!pp)
		goto static_routing;

	registry = pp->registry;
	dialing[0] = 0;
	if(pp->prefix[0] == '-') {
		if(!strnicmp(target, pp->prefix + 1, strlen(pp->prefix) - 1))
			target += strlen(pp->prefix) - 1;
	} else if(pp->prefix[0]) {
		if(strnicmp(target, pp->prefix, strlen(pp->prefix)))
			string::set(dialing, sizeof(dialing), pp->prefix);
	}
	string::add(dialing, sizeof(dialing), target);
	if(pp->suffix[0] == '-') {
		if(strlen(dialing) > strlen(pp->suffix) && !stricmp(dialing + strlen(dialing) - strlen(pp->suffix) + 1, pp->suffix + 1))	
			dialing[strlen(dialing) - strlen(pp->suffix) + 1] = 0;
	} else
		string::add(dialing, sizeof(dialing), pp->suffix);
	return true;

static_routing:
	dialed = config::getRouting(target);
	if(!dialed)
		goto invalid;

	if(!stricmp(dialed->getId(), "refuse")) {
		cp = service::getValue(dialed, "error");
		if(cp)
			error = atoi(cp);
		goto invalid;
	}

	// adjust dialing & processing based on routing properties
	dialing[0] = 0;
	cp = service::getValue(dialed, "prefix");
	if(cp && *cp == '-') {
		--cp;
		if(!strnicmp(target, cp, strlen(cp)))
			target += strlen(cp);
	} else if(cp) {
		if(strnicmp(target, cp, strlen(cp)))
			string::set(dialing, sizeof(dialing), cp);
	}
	string::add(dialing, sizeof(dialing), target);
	cp = service::getValue(dialed, "suffix");
	if(cp && *cp == '-') {
		--cp;
		if(strlen(dialing) >= strlen(cp) && !stricmp(dialing + strlen(dialing) - strlen(cp), cp))	
			dialing[strlen(dialing) - strlen(cp)] = 0;
	} else if(cp)
		string::add(dialing, sizeof(dialing), cp);
	if(!stricmp(dialed->getId(), "rewrite")) {
		string::set(dbuf, sizeof(dbuf), dialing);
		target = dbuf;
		config::release(dialed);
		if(registry)
			registry::release(registry);
		dialed = NULL;
		registry = NULL;
		destination = LOCAL;
		goto rewrite;
	}
	return true;
		
anonymous:
	destination = PUBLIC;
	return true;

remote:
	destination = REMOTE;
	if(!authenticate())
		return false;

	// must be active registration to dial out...
	error = SIP_FORBIDDEN;
	registry = registry::access(identity);
	time(&now);
	if(!registry || (registry->expires && registry->expires < now))
		goto invalid;

	if(registry->type == MappedRegistry::USER && !(registry->profile.features & USER_PROFILE_OUTGOING))
		goto invalid;

	return true;

invalid:
	if(authorized)
		debug(1, "rejecting invite from %s; error=%d\n", identity, error);
	else if(from->url && from->url->host && from->url->username)
		debug(1, "rejecting invite from %s@%s; error=%d\n", from->url->username, from->url->host, error);
	else
		debug(1, "rejecting unknown invite; error=%d\n", error);

	send_reply(error);
	return false;
}

void thread::send_reply(int error)
{
	osip_message_t *reply = NULL;

	eXosip_lock();
	switch(authorizing) {
	case CALL:
		eXosip_call_build_answer(sevent->tid, error, &reply);
		eXosip_call_send_answer(sevent->tid, error, reply);
		break;
	case MESSAGE:
		eXosip_message_build_answer(sevent->tid, error, &reply);
		eXosip_message_send_answer(sevent->tid, error, reply);
		break;
	}
	eXosip_unlock();
}

bool thread::authenticate(void)
{
	osip_message_t *reply = NULL;
	osip_authorization_t *auth = NULL;
	service::keynode *node = NULL, *leaf;
	stringbuf<64> digest;
	int error = SIP_PROXY_AUTHENTICATION_REQUIRED;
	const char *cp;

	if(authorized != NULL)
		return true;

	extension = 0;
	auth = NULL;

	if(!sevent->request || osip_message_get_authorization(sevent->request, 0, &auth) != 0 || !auth || !auth->username || !auth->response) 
		return unauthenticated();

	remove_quotes(auth->username);
	remove_quotes(auth->uri);
	remove_quotes(auth->nonce);
	remove_quotes(auth->response);

	// if subnet restrictions and authenticated from outside, reject

	if(stack::sip.restricted) {
		if(!getsource() || !access || !string::ifind(stack::sip.restricted, access->getName(), ",; \t\n")) {
			process::errlog(NOTICE, "rejecting restricted %s", auth->username);
			error = SIP_FORBIDDEN;
			goto failed;
		}
	}

	node = config::getProvision(auth->username);
	if(!node) {
		process::errlog(NOTICE, "rejecting unknown %s", auth->username);
		error = SIP_NOT_FOUND;
		goto failed;
	}

	// reject can be used as a placeholder when manually editing
	// provisioning records for a user that is being disabled but which
	// one doesn't want to loose configuration info

	if(!stricmp(node->getId(), "reject")) {
		process::errlog(NOTICE, "rejecting unauthorized %s", auth->username);
		error = SIP_FORBIDDEN;
		cp = service::getValue(node, "error");
		if(cp)
			error = atoi(cp);
		goto failed;
	}

	leaf = node->leaf("extension");
	if(leaf && leaf->getPointer())
		extension = atoi(leaf->getPointer());

	leaf = node->leaf("digest");
	if(!leaf || !leaf->getPointer()) {
		process::errlog(NOTICE, "rejecting unsupported %s", auth->username);
		error = SIP_FORBIDDEN;
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
		process::errlog(NOTICE, "rejecting unauthorized %s", auth->username);
		goto failed;
	}
	authorized = node;
	string::set(identity, sizeof(identity), auth->username);
	return true;

failed:
	config::release(node);
	send_reply(error);
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
	switch(authorizing) {
	case MESSAGE:
		eXosip_message_build_answer(sevent->tid, SIP_PROXY_AUTHENTICATION_REQUIRED, &reply);
		osip_message_set_header(reply, WWW_AUTHENTICATE, buffer);
		eXosip_message_send_answer(sevent->tid, SIP_PROXY_AUTHENTICATION_REQUIRED, reply);
		break;
	case CALL:
		eXosip_call_build_answer(sevent->tid, SIP_PROXY_AUTHENTICATION_REQUIRED, &reply);
		osip_message_set_header(reply, WWW_AUTHENTICATE, buffer);
		eXosip_call_send_answer(sevent->tid, SIP_PROXY_AUTHENTICATION_REQUIRED, reply);
		break;
	}
	eXosip_unlock();
}

bool thread::getsource(void)
{
	int vpos = 0;

	if(via_address)
		return true;

	via_header = NULL;
	origin_header = NULL;
	while(sevent->request && osip_list_eol(OSIP2_LIST_PTR sevent->request->vias, vpos) == 0) {
		via_header = (osip_via_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->vias, vpos++);
		if(!origin_header)
			origin_header = via_header;
	}

	if(!via_header)
		return false;

	via_address = new stack::address(via_header->host, via_header->port);
	access = config::getPolicy(via_address->getAddr());
	return true;
}

void thread::registration(void)
{	
	osip_header_t *header = NULL;
	osip_contact_t *contact = NULL;
	osip_uri_param_t *param = NULL;
	osip_uri_t *uri;
	int interval = -1;
	int pos = 0;

	if(!getsource()) {
		process::errlog(ERROR, "cannot determine origin for registration");
		return;
	}

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

	if(contact) {
		uri = contact->url;
		snprintf(buffer, sizeof(buffer), "%s:%s@%s:%s", 
			uri->scheme, uri->username, uri->host, uri->port);
	}
	else
		snprintf(buffer, sizeof(buffer), "sip:%s:%s", 
			origin_header->host, origin_header->port);

	if(interval < 0 && header && header->hvalue)
		interval = atoi(header->hvalue);
	if(interval < 0)
		interval = registry::getExpires();
	if(!interval || !contact) {
		deregister();
		return;
	}
	reregister(buffer, interval);
}

void thread::reregister(const char *contact, time_t interval)
{
	int answer = SIP_OK;
	osip_message_t *reply = NULL;
	time_t expire;
	unsigned count = 1;
	osip_contact_t *c = NULL;
	int pos = 0;
	bool refresh;

	if(extension && (extension < registry::getPrefix() || extension >= registry::getPrefix() + registry::getRange())) {
		answer = SIP_NOT_ACCEPTABLE_HERE;
		interval = 0;
		goto reply;
	}

	registry = registry::create(identity);
	if(!registry) {
		if(!warning_registry) {
			warning_registry = true;
			process::errlog(ERROR, "registry capacity reached");
		}
		answer = SIP_TEMPORARILY_UNAVAILABLE;
		interval = 0;
		goto reply;
	}
	warning_registry = false;
	time(&expire);
	if(registry->expires < expire) {
		registry->created = expire;
		getDevice(registry);
	}

	expire += interval + 3;	// overdraft 3 seconds...

	refresh = registry::refresh(registry, via_address, expire);
	if(!refresh) {
		if(registry->type == MappedRegistry::USER && (registry->profile.features & USER_PROFILE_MULTITARGET))
			count = registry::addTarget(registry, via_address, expire, contact);
		else
			count = registry::setTarget(registry, via_address, expire, contact);
	}
	if(refresh) 
		debug(2, "refreshing %s for %ld seconds from %s:%s", identity, interval, via_header->host, via_header->port);
	else if(count)
			process::errlog(DEBUG1, "registering %s for %ld seconds from %s:%s", identity, interval, via_header->host, via_header->port);
	else {
		process::errlog(ERROR, "cannot register %s from %s", identity, buffer);
		answer = SIP_FORBIDDEN;
		goto reply;
	}		

	if(registry->type != MappedRegistry::SERVICE || registry->routes)
		goto reply;

	while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
		c = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos++);
		if(c && c->url && c->url->username) {
			registry::addContact(registry, c->url->username);
			process::errlog(INFO, "registering service %s:%s@%s:%s",
				c->url->scheme, c->url->username, c->url->host, c->url->port);
		}
	}

reply:
	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, answer, &reply);
	eXosip_message_send_answer(sevent->tid, answer, reply);
	eXosip_unlock();
	if(registry && registry->type == MappedRegistry::USER && answer == SIP_OK)
		messages::update(identity);
}

void thread::deregister()
{
	process::errlog(DEBUG1, "unregister %s", identity);
}

void thread::getDevice(MappedRegistry *rr)
{
	linked_pointer<service::keynode> device = config::list("devices");

	while(device) {
		linked_pointer<service::keynode> node = device->getFirst();
		const char *id, *value;
		while(node) {
			id = node->getId();
			value = node->getPointer();
			if(id && value && !stricmp(id, "match")) {
			}
			node.next();
		}
		device.next();
	}		
}

void thread::options(void)
{
    osip_message_t *reply = NULL;

    eXosip_lock();
    if(eXosip_options_build_answer(sevent->tid, SIP_OK, &reply) == 0) {
		osip_message_set_header(reply, ACCEPT, "application/sdp, text/plain");
		osip_message_set_header(reply, ALLOW, "INVITE,ACK,CANCEL,OPTIONS,INFO,REFER,MESSAGE,SUBSCRIBE,NOTIFY,REGISTER,PRACK"); 
        eXosip_options_send_answer(sevent->tid, SIP_OK, reply);
	}
	eXosip_unlock();
}

void thread::shutdown(void)
{
	shutdown_flag = true;
	while(shutdown_count < startup_count)
		Thread::sleep(50);
}

void thread::wait(unsigned count) {
	while(startup_count < count)
		Thread::sleep(50);
}

void thread::run(void)
{
	instance = ++startup_count;
	process::errlog(DEBUG1, "starting thread %d", instance);

	raisePriority(stack::sip.priority);

	for(;;) {
		sevent = eXosip_event_wait(0, stack::sip.timing);
		via_header = NULL;
		origin_header = NULL;

		if(shutdown_flag) {
			++shutdown_count;
			process::errlog(DEBUG1, "stopping thread %d", instance);
			DetachedThread::exit();
		}

		if(!sevent)
			continue;

		debug(2, "sip: event %d; cid=%d, did=%d, instance=%d",
			sevent->type, sevent->cid, sevent->did, instance);

		switch(sevent->type) {
		case EXOSIP_CALL_INVITE:
			authorizing = CALL;
			if(!sevent->request)
				break;
			if(sevent->cid < 1 && sevent->did < 1)
				break;
			if(authorize())
				invite();
			break;
		case EXOSIP_MESSAGE_NEW:
			authorizing = MESSAGE;
			if(!sevent->request)
				break;
			if(MSG_IS_OPTIONS(sevent->request))
				options();
			else if(MSG_IS_REGISTER(sevent->request) && authenticate())
				registration();
			break;
		default:
			process::errlog(WARN, "unknown message");
		}
		if(via_address) {
			delete via_address;
			via_address = NULL;
		}
		if(from_address) {
			delete from_address;
			from_address = NULL;
		}
		if(to_address) {
			delete to_address;
			to_address = NULL;
		}

		if(registry) {
			registry::release(registry);
			registry = NULL;
		}
		if(access) {
			config::release(access);
			access = NULL;
		}

		if(dialed) {
			config::release(dialed);
			dialed = NULL;
		}

		if(authorized) {
			config::release(authorized);
			authorized = NULL;
		}

		if(from) {
			osip_from_free(from);
			from = NULL;
		}

		if(to) {
			osip_to_free(to);
			to = NULL;
		}

		if(remote_uri) {
			osip_free(remote_uri);
			remote_uri = NULL;
		}

		if(local_uri) {
			osip_free(local_uri);
			local_uri = NULL;
		}

		eXosip_event_free(sevent);
	}
}

END_NAMESPACE
