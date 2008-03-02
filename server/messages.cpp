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
	user[0] = 0;
	reply[0] = 0;
	self = true;
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

messages::message *messages::create(const char *reply, const char *display)
{
	message *msg;
	char *ep;

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

	if(msg->reply) {
		msg->self = false;
		String::set(msg->reply, sizeof(msg->reply), reply);
	}
	if(reply && !display) {
		if(!strnicmp(reply, "sip:", 4))
			reply += 4;
		else if(!strnicmp(reply, "sips:", 5))
			reply += 5;
		String::set(msg->from, sizeof(msg->from), reply);
		ep = strchr(msg->from, '@');
		if(ep)
			*ep = 0;
	}	
	else
		String::set(msg->from, sizeof(msg->from), display);
	return msg;
}

bool messages::send(message *msg)
{
	assert(msg != NULL);

	linked_pointer<registry::target> tp;
	registry::mapped *rr = registry::access(msg->user);
	unsigned path = NamedObject::keyindex(msg->user, keysize);
	time_t now;
	unsigned msgcount = 0;

	time(&now);
	if(!rr || (rr->expires && rr->expires < now)) {
delay:
		registry::detach(rr);
		msglock.lock();
		++pending;
		msg->enlist(&msgs[path]);
		msglock.unlock();
		return false;
	}

	tp = rr->targets;
	while(tp) {
		if(!rr->expires || tp->expires > now) {
			if(msg->self) 
				stack::sipAddress(&tp->iface, msg->reply, NULL, sizeof(msg->reply)); 
			eXosip_lock();
			eXosip_unlock();
		}
		tp.next();
	}

	if(!msgcount)
		goto delay;

	registry::detach(rr);
	msglock.lock();
	msg->enlist(&freelist);
	msglock.release();
	return true;
}

bool messages::sms(const char *reply, const char *to, const char *text, const char *display)
{
	assert(to != NULL && *to != 0);
	assert(text != NULL);

	message *msg = create(reply, display);
	String::set(msg->user, sizeof(msg->user), to);
	String::set(msg->text, sizeof(msg->text), text);
	msg->type = message::SMS;
	return send(msg);
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
		if(!msg || send(msg))
			return;
	}
}

END_NAMESPACE
