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
static unsigned active_count = 0;

static char *remove_quotes(char *c)
{
	assert(c != NULL);

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
	reginfo = NULL;
	session = NULL;
}

void thread::invite()
{
	const char *target = dialing;
	osip_body_t *body = NULL;
	stack::call *call = session->parent;
	unsigned toext = 0;

	printf("******* INVITING!\n");

	osip_message_get_body(sevent->request, 0, &body);
	if(body && body->body)
		String::set(session->sdp, sizeof(session->sdp), body->body);

	if(dialed) {
		target = service::getValue(dialed, "extension");
		if(target)
			toext = atoi(target);
		target = service::getValue(dialed, "id");
	}
	else if(reginfo) {
		target = reginfo->userid;
		toext = reginfo->ext;
	}

	switch(destination) {
	case LOCAL:
		time(&call->starting);
		call->type = stack::call::LOCAL;
		if(extension)
			snprintf(session->sysident, sizeof(session->sysident), "%u", extension);
		else
			String::set(session->sysident, sizeof(session->sysident), identity);
		if(display[0])
			String::set(session->display, sizeof(session->display), display);
		else
			String::set(session->display, sizeof(session->display), session->sysident);
		String::set(call->dialed, sizeof(call->dialed), dialing);
		stack::sipAddress(&iface, session->identity, identity, sizeof(session->identity));

		if(toext)
			snprintf(call->dialed, sizeof(call->dialed), "%u", toext);
		else
			String::set(call->dialed, sizeof(call->dialed), target);

		if(!stricmp(session->sysident, call->dialed)) {
			debug(1, "calling self %08x:%u, id=%s\n", 
				session->sequence, session->cid, getIdent());

			String::set(call->subject, sizeof(call->subject), "calling self");
			stack::setBusy(sevent->tid, session);
			return;
		}

		session->reg = registry::invite(session->sysident);
		debug(1, "local call %08x:%u for %s from %s\n", 
			session->sequence, session->cid, call->dialed, session->sysident);
		break;
	case PUBLIC:
		time(&call->starting);
		call->type = stack::call::INCOMING;
		String::set(call->dialed, sizeof(call->dialed), target);
		stack::sipAddress((struct sockaddr_internet *)from_address.getAddr(), session->identity, from->url->username, sizeof(session->identity)); 
		stack::sipIdentity((struct sockaddr_internet *)from_address.getAddr(), session->sysident, from->url->username,  sizeof(session->sysident));
		if(from->displayname)
			String::set(session->display, sizeof(session->display), from->displayname);
		else
			String::set(session->display, sizeof(session->display), from->url->username);
		debug(1, "incoming call %08x:%u for %s from %s\n", 
			session->sequence, session->cid, call->dialed, session->sysident);
		break;
	case EXTERNAL:
		time(&call->starting);
		call->type = stack::call::OUTGOING;
		if(extension)
			snprintf(session->sysident, sizeof(session->sysident), "%u", extension);
		else
			String::set(session->sysident, sizeof(session->sysident), identity);
		session->reg = registry::invite(session->sysident);
		if(display[0])
			String::set(session->display, sizeof(session->display), display);
		else
			String::set(session->display, sizeof(session->display), identity);
		stack::sipAddress(&iface, session->identity, identity, sizeof(session->identity));
		stack::sipIdentity((struct sockaddr_internet *)request_address.getAddr(), call->dialed, uri->username, sizeof(call->dialed));
		debug(1, "outgoing call %08x:%u from %s to %s", 
			session->sequence, session->cid, getIdent(), call->dialed);
		break;
	case ROUTED:
		session->reg = registry::invite(identity);
		debug(1, "dialed call %08x:%u for %s from %s, dialing=%s\n", 
			session->sequence, session->cid, target, getIdent(), dialing);
		break;  	
	}

	if(reginfo) {
		// get rid of config ref if we are calling registry target
		if(dialed) {
			config::release(dialed);
			dialed = NULL;
		}

		// TODO: FORWARD CHECK ALL/AWAY-BUSY??

		// invite any available targets; increments cr->invited...
		// AWAY handled in inviteLocal, nothing added; busy fallthru!
		// stack::inviteLocal(session, registry);
	}

	if(dialed) {
		// PROCESS DIALED HERE IF EXISTS...
	}

	if(call->invited)
		return;

	stack::setBusy(sevent->tid, session);
}

void thread::identify(void)
{
	registry::mapped *rr = NULL;

	if(!stack::sip.trusted || !getsource() || !access)
		return;

	if(!String::ifind(stack::sip.trusted, access->getName(), ",; \t\n"))
		return;

	rr = registry::address(via_address.getAddr());
	if(!rr)
		return;

	String::set(display, sizeof(display), rr->display);
	extension = rr->ext;
	String::set(identity, sizeof(identity), rr->userid);
	authorized = config::getProvision(identity);
	registry::detach(rr);
}

const char *thread::getIdent(void)
{
	if(!extension)
		return identity;

	if(registry::isExtension(identity) && (unsigned)atoi(identity) == extension)
		return identity;

	if(!identbuf[0])
		snprintf(identbuf, sizeof(identbuf), "%s(%u)", identity, extension);

	return identbuf;
}
	
bool thread::unauthenticated(void)
{
	registry::mapped *rr = NULL;

	if(!stack::sip.trusted || !getsource() || !access)
		goto untrusted;

	if(!String::ifind(stack::sip.trusted, access->getName(), ",; \t\n"))
		goto untrusted;

	rr = registry::address(via_address.getAddr());
	if(!rr)
		goto untrusted;

	extension = rr->ext;
	String::set(display, sizeof(display), rr->display);
	String::set(identity, sizeof(identity), rr->userid);
	authorized = config::getProvision(identity);
	registry::detach(rr);
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
	const char *cp;
	time_t now;
	unsigned level;
	profile_t *pro;
	const char *target;
	const char *invited = NULL;
	char dbuf[MAX_USERID_SIZE];
	registry::pattern *pp;
	unsigned from_port = 5060, to_port = 5060, local_port = 5060;

	if(!sevent->request || !sevent->request->to || !sevent->request->from || !sevent->request->req_uri)
		goto invalid;

	from = sevent->request->from;
	uri = sevent->request->req_uri;
	to = sevent->request->to;

	error = SIP_ADDRESS_INCOMPLETE;

	if(stack::sip.tlsmode)
		scheme = "sips";

	if(!from->url->host || !uri->host)
		goto invalid;

	if(!from->url->username || !uri->username)
		goto invalid;

	if(!from->url->scheme || !uri->scheme)
		goto invalid;

	error = SIP_UNSUPPORTED_URI_SCHEME;
	if(stricmp(from->url->scheme, scheme) || stricmp(uri->scheme, scheme))
		goto invalid;

	if(uri->port)
		local_port = atoi(uri->port);
	if(from->url->port)
		from_port = atoi(from->url->port);
	if(to->url->port)
		to_port = atoi(to->url->port);
	if(!local_port)
		local_port = 5060;
	if(!from_port)
		from_port = 5060;
	if(!to_port)
		to_port = 5060;

/*	debug(3, "request from=%s:%s@%s:%d, uri=%s:%s@%s:%d, to=%s:%s@%s:%d\n",
		from->url->scheme, from->url->username, from->url->host, from_port,
		uri->scheme, uri->username, uri->host, local_port,
		to->url->scheme, to->url->username, to->url->host, to_port);
*/
	from_address.set(from->url->host, from_port);
	request_address.set(uri->host, local_port);

	if(request_address.getAddr() == NULL) {
		error = SIP_ADDRESS_INCOMPLETE;
		goto invalid;
	}

	if(local_port != stack::sip.port)
		goto remote;

	if(String::ifind(stack::sip.localnames, uri->host, " ,;:\t\n"))
		goto local;

	stack::getInterface((struct sockaddr *)&iface, request_address.getAddr());
	if(Socket::equal((struct sockaddr *)&iface, request_address.getAddr()))
		goto local;

	goto remote;

local:
	debug(2, "authorizing local; target=%s\n", uri->username);
	target = uri->username;
	destination = LOCAL;
	String::set(dialing, sizeof(dialing), target);

rewrite:
	debug(3, "rewrite process; target=%s, dialing=%s\n", target, dialing);
	error = SIP_NOT_FOUND;
	if(!target || !*target || strlen(target) >= MAX_USERID_SIZE)
		goto invalid;

	reginfo = registry::access(target);
	dialed = config::getProvision(target);

	debug(4, "rewrite process; registry=%p, dialed=%p\n", reginfo, dialed);

	if(!reginfo && !dialed)
		goto routing;

	// reject nodes with defined errors
	if(dialed && !stricmp(dialed->getId(), "reject")) {
		cp = service::getValue(dialed, "error");
		if(cp)
			error = atoi(cp);
		goto invalid;
	}

	if(!reginfo && dialed) {
		if(!stricmp(dialed->getId(), "group"))
			return authenticate();
		if(!stricmp(dialed->getId(), "refer"))
			return authenticate();
		if(!stricmp(dialed->getId(), "test")) {
			if(session && authenticate()) {
				session->reg = registry::invite(identity);
				cp = service::getValue(dialed, "error");
				if(cp) {
					error = atoi(cp);
					goto invalid;
				}
				return true;
			}
			return false;
		}
		if(!stricmp(dialed->getId(), "queue"))
			goto anonymous;
		if(!stricmp(dialed->getId(), "user"))
			process::errlog(NOTIFY, "unregistered destination %s", target);
		else
			process::errlog(ERRLOG, "invalid destination %s, type=%s\n", target, dialed->getId());
		error = SIP_GONE;	
		goto invalid;
	}

	if(reginfo && reginfo->type == MappedRegistry::TEMPORARY) {
		error = SIP_GONE;
		goto invalid;
	}

	time(&now);

	if(reginfo && reginfo->expires && reginfo->expires < now) {
		error = SIP_GONE;
		goto invalid;
	}
	else if(reginfo && !dialed) {
		error = SIP_NOT_FOUND;
		goto invalid;
	}

	// extension references always require authentication
	if(registry::isExtension(target)) {
		if(!authenticate())
			return false;
		if(!reginfo)
			goto invalid;
		return true;
	}

	if(reginfo && reginfo->type == MappedRegistry::USER && (reginfo->profile.features & USER_PROFILE_INCOMING))
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

	reginfo = pp->registry;
	dialing[0] = 0;
	if(pp->prefix[0] == '-') {
		if(!strnicmp(target, pp->prefix + 1, strlen(pp->prefix) - 1))
			target += strlen(pp->prefix) - 1;
	} else if(pp->prefix[0]) {
		if(strnicmp(target, pp->prefix, strlen(pp->prefix)))
			String::set(dialing, sizeof(dialing), pp->prefix);
	}
	String::add(dialing, sizeof(dialing), target);
	if(pp->suffix[0] == '-') {
		if(strlen(dialing) > strlen(pp->suffix) && !stricmp(dialing + strlen(dialing) - strlen(pp->suffix) + 1, pp->suffix + 1))	
			dialing[strlen(dialing) - strlen(pp->suffix) + 1] = 0;
	} else
		String::add(dialing, sizeof(dialing), pp->suffix);
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
			String::set(dialing, sizeof(dialing), cp);
	}
	String::add(dialing, sizeof(dialing), target);
	cp = service::getValue(dialed, "suffix");
	if(cp && *cp == '-') {
		--cp;
		if(strlen(dialing) >= strlen(cp) && !stricmp(dialing + strlen(dialing) - strlen(cp), cp))	
			dialing[strlen(dialing) - strlen(cp)] = 0;
	} else if(cp)
		String::add(dialing, sizeof(dialing), cp);
	if(!stricmp(dialed->getId(), "rewrite")) {
		String::set(dbuf, sizeof(dbuf), dialing);
		target = dbuf;
		config::release(dialed);
		if(reginfo)
			registry::detach(reginfo);
		dialed = NULL;
		reginfo = NULL;
		destination = LOCAL;
		goto rewrite;
	}
	return true;
		
anonymous:
	if(!stack::sip.published) {
		error = SIP_FORBIDDEN;
		goto invalid;
	}

	if(from_address.getAddr() == NULL) {
		error = SIP_ADDRESS_INCOMPLETE;
		goto invalid;
	}

	destination = PUBLIC;
	return true;

remote:		
	error = SIP_FORBIDDEN;
	destination = EXTERNAL;
	if(!stack::sip.published)
		goto invalid;

	if(!authenticate())
		return false;

	// must be active registration to dial out...
	reginfo = registry::access(identity);
	time(&now);
	if(!reginfo || (reginfo->expires && reginfo->expires < now))
		goto invalid;

	if(reginfo->type == MappedRegistry::USER && !(reginfo->profile.features & USER_PROFILE_OUTGOING))
		goto invalid;

	return true;

invalid:
	if(authorized)
		debug(1, "rejecting invite from %s; error=%d\n", getIdent(), error);
	else if(from->url && from->url->host && from->url->username)
		debug(1, "rejecting invite from %s@%s; error=%d\n", from->url->username, from->url->host, error);
	else
		debug(1, "rejecting unknown invite; error=%d\n", error);

	send_reply(error);
	return false;
}

void thread::send_reply(int error)
{
	assert(error >= 100);
	assert(authorizing == CALL || authorizing == MESSAGE);

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
	default:
		break;
	}
	eXosip_unlock();
}

bool thread::authenticate(void)
{
	osip_authorization_t *auth = NULL;
	service::keynode *node = NULL, *leaf;
	stringbuf<64> digest;
	int error = SIP_PROXY_AUTHENTICATION_REQUIRED;
	const char *cp;

	if(authorized != NULL)
		return true;

	display[0] = 0;
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
		if(!getsource() || !access || !String::ifind(stack::sip.restricted, access->getName(), ",; \t\n")) {
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

	leaf = node->leaf("display");
	if(leaf && leaf->getPointer())
		String::set(display, sizeof(display), leaf->getPointer());

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
	String::set(identity, sizeof(identity), auth->username);
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
	case NONE:
		break;
	}
	eXosip_unlock();
}

bool thread::getsource(void)
{
	int vpos = 0;
	unsigned via_port = 5060;

	if(is(via_address))
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

	if(via_header->port)
		via_port = atoi(via_header->port);
	if(!via_port)
		via_port = 5060;
	via_address.set(via_header->host, via_port);
	access = config::getPolicy(via_address.getAddr());
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
		process::errlog(ERRLOG, "cannot determine origin for registration");
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

	if(interval < 0)
		interval = header_expires;
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
	assert(contact != NULL && *contact != 0);
	assert(interval > 0);
	assert(identity != NULL && *identity != 0);

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

	reginfo = registry::create(identity);
	if(!reginfo) {
		if(!warning_registry) {
			warning_registry = true;
			process::errlog(ERRLOG, "registry capacity reached");
		}
		answer = SIP_TEMPORARILY_UNAVAILABLE;
		interval = 0;
		goto reply;
	}
	warning_registry = false;
	time(&expire);
	if(reginfo->expires < expire) {
		reginfo->created = expire;
		getDevice(reginfo);
	}

	expire += interval + 3;	// overdraft 3 seconds...

	refresh = reginfo->refresh(via_address, expire);
	if(!refresh) {
		if(reginfo->type == MappedRegistry::USER && (reginfo->profile.features & USER_PROFILE_MULTITARGET))
			count = reginfo->addTarget(via_address, expire, contact);
		else
			count = reginfo->setTarget(via_address, expire, contact);
	}
	if(refresh) 
		debug(2, "refreshing %s for %ld seconds from %s:%s", getIdent(), interval, via_header->host, via_header->port);
	else if(count)
			process::errlog(DEBUG1, "registering %s for %ld seconds from %s:%s", getIdent(), interval, via_header->host, via_header->port);
	else {
		process::errlog(ERRLOG, "cannot register %s from %s", getIdent(), buffer);
		answer = SIP_FORBIDDEN;
		goto reply;
	}		

	if(reginfo->type != MappedRegistry::SERVICE || reginfo->routes)
		goto reply;

	while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
		c = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos++);
		if(c && c->url && c->url->username) {
			reginfo->addContact(c->url->username);
			process::errlog(INFO, "registering service %s:%s@%s:%s",
				c->url->scheme, c->url->username, c->url->host, c->url->port);
		}
	}
reply:
	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, answer, &reply);
	eXosip_message_send_answer(sevent->tid, answer, reply);
	eXosip_unlock();
	if(reginfo && reginfo->type == MappedRegistry::USER && answer == SIP_OK)
		messages::update(identity);
}

void thread::deregister()
{
	process::errlog(DEBUG1, "unregister %s", getIdent());
}

void thread::getDevice(registry::mapped *rr)
{
	assert(rr != NULL);

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
	while(active_count)
		Thread::sleep(50);
	eXosip_quit();
	while(shutdown_count < startup_count)
		Thread::sleep(50);
}

void thread::wait(unsigned count) {
	while(startup_count < count)
		Thread::sleep(50);
}

void thread::expiration(void)
{
	osip_header_t *header = NULL;
	osip_uri_param_t *expires = NULL;
	osip_contact_t *contact;
	int pos = 0;

	assert(sevent->request != NULL);	
	
	header_expires = 0l;
	osip_message_get_expires(sevent->request, 0, &header);
	if(header && header->hvalue)
		header_expires = atol(header->hvalue);
	else while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
		contact = (osip_contact_t*)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos);
		if(osip_contact_param_get_byname(contact, "expires", &expires) != 0 && expires != NULL) {
			header_expires = atol(expires->gvalue);
			break;
		}
		++pos;
	}
}

void thread::run(void)
{
	instance = ++startup_count;
	process::errlog(DEBUG1, "starting thread %d", instance);

	for(;;) {
		assert(instance > 0);
		assert(reginfo == NULL);
		assert(dialed == NULL);
		assert(authorized == NULL);
		assert(access == NULL);

		display[0] = 0;
		extension = 0;
		identbuf[0] = 0;

		if(!shutdown_flag)
			sevent = eXosip_event_wait(0, stack::sip.timing);

		via_header = NULL;
		origin_header = NULL;

		if(shutdown_flag) {
			process::errlog(DEBUG1, "stopping thread %d", instance);
			++shutdown_count;
			DetachedThread::exit();
		}


		if(!sevent)
			continue;

		++active_count;
		debug(2, "sip: event %d; cid=%d, did=%d, instance=%d",
			sevent->type, sevent->cid, sevent->did, instance);

		switch(sevent->type) {
		case EXOSIP_CALL_CANCELLED:
			authorizing = CALL;
			if(sevent->cid > 0) {
				session = stack::access(sevent->cid);
				if(session->did == sevent->did)
					stack::close(session);
			}
			send_reply(SIP_OK);
			break;
		case EXOSIP_CALL_CLOSED:
			authorizing = CALL;
			if(sevent->cid > 0) {
				session = stack::access(sevent->cid);
				stack::close(session);
			}
			send_reply(SIP_OK);
			break;
		case EXOSIP_CALL_RELEASED:
			authorizing = NONE;
			if(sevent->cid > 0) {
				authorizing = CALL;
				session = stack::access(sevent->cid);
				stack::clear(session);
				send_reply(SIP_OK);
			}
			break;
		case EXOSIP_CALL_INVITE:
			authorizing = CALL;
			if(!sevent->request)
				break;
			if(sevent->cid < 1)
				break;
			expiration();
			session = stack::create(sevent->cid, sevent->did, sevent->tid);
			if(authorize()) 
				invite();
			break;
		case EXOSIP_MESSAGE_NEW:
			authorizing = MESSAGE;
			if(!sevent->request)
				break;
			expiration();
			if(MSG_IS_OPTIONS(sevent->request))
				options();
			else if(MSG_IS_REGISTER(sevent->request) && authenticate())
				registration();
			break;
		default:
			process::errlog(WARN, "unknown message");
		}

		// release access locks for registry and sessions quickly...
	
		if(session) {
			stack::detach(session);
			session = NULL;
		}

		if(reginfo) {
			registry::detach(reginfo);
			reginfo = NULL;
		}

		via_address.clear();
		from_address.clear();
		request_address.clear();

		// release config access lock(s)...

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

		eXosip_event_free(sevent);
		--active_count;
	}
}

END_NAMESPACE
