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
	access = NULL;
	authorized = NULL;
	destination = NULL;
	via_address = from_address = to_address = NULL;
}

bool thread::authenticate(void)
{
	osip_message_t *reply = NULL;
	osip_authorization_t *auth = NULL;
	service::keynode *node = NULL, *leaf;
	stringbuf<64> digest;
	int error = SIP_PROXY_AUTHENTICATION_REQUIRED;

	extension = 0;
	auth = NULL;
	if(!sevent->request || osip_message_get_authorization(sevent->request, 0, &auth) != 0 || !auth || !auth->username || !auth->response) {
		process::errlog(DEBUG1, "challenge request required");
		challenge();
		return false;
	}

	remove_quotes(auth->username);
	remove_quotes(auth->uri);
	remove_quotes(auth->nonce);
	remove_quotes(auth->response);

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
	eXosip_message_build_answer(sevent->tid, SIP_PROXY_AUTHENTICATION_REQUIRED, &reply);
	osip_message_set_header(reply, WWW_AUTHENTICATE, buffer);
	eXosip_message_send_answer(sevent->tid, SIP_PROXY_AUTHENTICATION_REQUIRED, reply);
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
	unsigned count;
	osip_contact_t *c = NULL;
	int pos = 0;

	if(extension && (extension < registry::getPrefix() || extension >= registry::getPrefix() + registry::getRange())) {
		answer = SIP_NOT_ACCEPTABLE_HERE;
		interval = 0;
		goto reply;
	}

	destination = registry::create(identity);
	if(!destination) {
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
	expire += interval + 3;	// overdraft 3 seconds...
	if(destination->type == REG_USER && (destination->profile.features & USER_PROFILE_MULTITARGET))
		count = registry::addTarget(destination, via_address, expire, contact);
	else
		count = registry::setTarget(destination, via_address, expire, contact);

	if(count)
		process::errlog(DEBUG1, "registering %s for %ld seconds from %s:%s", identity, interval, via_header->host, via_header->port);
	else {
		process::errlog(ERROR, "cannot register %s from %s", identity, buffer);
		answer = SIP_FORBIDDEN;
		goto reply;
	}		

	if(destination->type != REG_SERVICE || destination->routes)
		goto reply;

	while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
		c = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos++);
		if(c && c->url && c->url->username) {
			registry::addContact(destination, c->url->username);
			process::errlog(INFO, "registering service %s:%s@%s:%s",
				c->url->scheme, c->url->username, c->url->host, c->url->port);
		}
	}

reply:
	eXosip_lock();
	eXosip_message_build_answer(sevent->tid, answer, &reply);
	eXosip_message_send_answer(sevent->tid, answer, reply);
	eXosip_unlock();
}

void thread::deregister()
{
	process::errlog(DEBUG1, "deauthorize %s", identity);
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

		process::errlog(DEBUG1, "sip: event %d; cid=%d, did=%d, instance=%d",
			sevent->type, sevent->cid, sevent->did, instance);

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

		if(destination) {
			registry::release(destination);
			destination = NULL;
		}
		if(access) {
			config::release(access);
			access = NULL;
		}

		if(authorized) {
			config::release(authorized);
			authorized = NULL;
		}
		eXosip_event_free(sevent);
	}
}

END_NAMESPACE
