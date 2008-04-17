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

static mutex_t msglock;
static unsigned keysize = 177;
static LinkedObject **msgs = NULL;
static LinkedObject *sending = NULL;
static LinkedObject *freelist = NULL;
static unsigned volatile pending = 0;
static unsigned volatile allocated = 0;
static time_t volatile duration = 900;

void messages::message::create(void) 
{
	time(&expires);
	expires += duration;

	from[0] = 0;
	type[0] = 0;
	body[0] = 0;
	user[0] = 0;
	msglen = 0;
}

messages::messages() :
service::callback(2)
{
}

bool messages::check(void)
{
	process::errlog(INFO, "checking messages...");
	msglock.lock();
	msglock.release();
	return true;
}

void messages::cleanup(void)
{
	linked_pointer<message> mp;
	LinkedObject *msgnext;
	unsigned msgcount = 0;
	time_t now;

	if(!pending)
		return;

	while(msgcount < keysize) {
		msglock.lock();
		time(&now);
		mp = msgs[msgcount];
		while(mp) {
			msgnext = mp->getNext();
			if(mp->expires < now) {
				mp->delist(&msgs[msgcount]);
				mp->enlist(&freelist);
			}
			mp = msgnext;
		}
		msglock.unlock();
		++msgcount;
	}
}

bool messages::reload(service *cfg)
{
	assert(cfg != NULL);

	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("messages");

	while(sp) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			if(!stricmp(key, "keysize") && !isConfigured())
				keysize = atoi(value);
			else if(!stricmp(key, "expires"))
				duration = atoi(value) * 60;
		}
		sp.next();
	}

	if(isConfigured())
		return true;

	msgs = new LinkedObject*[keysize];
	memset(msgs, 0, sizeof(LinkedObject *) * keysize);
	return true;
}

void messages::snapshot(FILE *fp) 
{
	assert(fp != NULL);
	fprintf(fp, "Messaging:\n"); 
	fprintf(fp, "  allocated messages: %d\n", allocated);
	fprintf(fp, "  pending messages:   %d\n", pending);
}

void messages::update(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	linked_pointer<message> mp;
	LinkedObject *next;
	unsigned path;
	time_t now;
	if(!uid || !pending)
		return;

	path = NamedObject::keyindex(uid, keysize);
	msglock.lock();
	time(&now);
	mp = msgs[path];
	while(mp) {
		next = mp->getNext();
		if(!stricmp(mp->user, uid)) {
			--pending;
			mp->delist(&msgs[path]);
			if(mp->expires < now)
				mp->enlist(&freelist);
			else
				mp->enlist(&sending);
		}
		mp = next;
	}
	msglock.unlock();
}

bool messages::publish(const char *to, const char *reply, const char *from, caddr_t text, size_t len, const char *msgtype)
{
	message *msg;
	char *ep;

	if(!msgtype)
		msgtype = "text/plain";

	if(len > sizeof(msg->body))
		return false;

	msglock.lock();
	msg = static_cast<message *>(freelist);
	if(msg) 
		freelist = msg->getNext();
	msglock.unlock();
	if(!msg) {
		++allocated;
		msg = new message();
	}
	msg->create();
	String::set(msg->reply, sizeof(msg->reply), reply);
	String::set(msg->user, sizeof(msg->user), to);
	String::set(msg->from, sizeof(msg->from), from);
	String::set(msg->type, sizeof(msg->type), msgtype);	
	memset(msg->body, sizeof(msg->body), 0);
	if(len)
		memcpy(msg->body, text, len);
	msg->msglen = len;
	deliver(msg);
	return true;
}

bool messages::system(const char *to, const char *text)
{
	char from[MAX_URI_SIZE];
	const char *scheme;
	const char *sysid = stack::sip.system;
	const char *host = stack::sip.published;
	unsigned short port  = stack::sip.port;

	if(stack::sip.tlsmode)
		scheme = "sips";
	else
		scheme = "sip";

	if(!host) {
		host = "127.0.0.1";
#ifdef	AF_INET6
		if(!host && stack::sip.family == AF_INET6)
			host = "::1";
#endif
	}

	if(strchr(host, ':'))
		snprintf(from, sizeof(from), "<%s:%s@[%s]:%u>", 
			scheme, sysid, host, port);
	else	
		snprintf(from, sizeof(from), "<%s:%s@%s:%u>", 
			scheme, sysid, host, port);

	return publish(to, sysid, from, (caddr_t)text, strlen(text), "text/plain");
}


bool messages::deliver(message *msg)
{
	assert(msg != NULL);

	linked_pointer<registry::target> tp;
	registry::mapped *rr = registry::access(msg->user);
	unsigned path = NamedObject::keyindex(msg->user, keysize);
	osip_message_t *im;
	time_t now;
	unsigned msgcount = 0;
	char to[MAX_URI_SIZE];

	time(&now);
	if(!rr || (rr->expires && rr->expires < now)) {
delay:
		debug(3, "instant message pending for %s from %s", msg->user, msg->reply);
		goto final;
/*		registry::detach(rr);
		msglock.lock();
		++pending;
		msg->enlist(&msgs[path]);
		msglock.unlock();
*/		return false;
	}

	debug(3, "instant message delivered to %s from %s", msg->user, msg->reply);
	tp = rr->targets;
	while(tp) {
		if(!rr->expires || tp->expires > now) {
			stack::sipAddress(&tp->address, to + 1, msg->user, sizeof(to) - 6); 
			to[0] = '<';
			String::add(to, sizeof(to), ";lr>");
			eXosip_lock();
			im = NULL;
			eXosip_message_build_request(&im, "MESSAGE", tp->contact, msg->from, to); 
			if(im != NULL) {
				stack::sipAddress(&tp->address, to + 1, msg->user, sizeof(to) - 2); 
				to[0] = '<';
				String::add(to, sizeof(to), ">");
				if(im->to) {
					osip_to_free(im->to);
					im->to = NULL;
				}
				osip_message_set_to(im, to);
				osip_message_set_body(im, msg->body, msg->msglen);
				osip_message_set_content_type(im, msg->type);				
				stack::siplog(im);
				if(!eXosip_message_send_request(im))
					++msgcount;
			}
			eXosip_unlock();
		}
		tp.next();
	}

	if(!msgcount)
		goto delay;

final:
	registry::detach(rr);
	msglock.lock();
	msg->enlist(&freelist);
	msglock.release();
	return true;
}

void messages::automatic(void)
{
	message *msg = NULL;
	time_t now;

	for(;;) {
		msglock.lock();
		if(sending)
			time(&now);
		while(sending) {
			msg = (message *)sending;
			sending = msg->getNext();
			if(msg->expires > now)
				break;
			msg->enlist(&freelist);
			msg = NULL;	
		}
		msglock.release();
		if(!msg || deliver(msg))
			return;
	}
}

END_NAMESPACE
