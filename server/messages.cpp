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
static unsigned volatile pending = 0;
static time_t volatile duration = 900;

messages::message::message() :
LinkedObject()
{
	time(&expires);
	expires += duration; 
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
	LinkedObject *next;
	unsigned count = 0;
	time_t now;

	if(!pending)
		return;

	while(count < keysize) {
		msglock.lock();
		time(&now);
		mp = msgs[count];
		while(mp) {
			next = mp->getNext();
			if(mp->expires < now) {
				mp->delist(&msgs[count]);
				delete *mp;
			}
			mp = next;
		}
		msglock.unlock();
		++count;
	}
}

bool messages::reload(service *cfg)
{
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

void messages::update(const char *uid)
{
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
				delete *mp;
			else
				mp->enlist(&sending);
		}
		mp = next;
	}
	msglock.unlock();
}

bool messages::send(message *msg)
{
	linked_pointer<registry::target> tp;
	MappedRegistry *rr = registry::access(msg->user);
	unsigned path = NamedObject::keyindex(msg->user, keysize);
	time_t now;

	time(&now);
	if(!rr || (rr->expires && rr->expires < now)) {
		registry::release(rr);
		msglock.lock();
		++pending;
		msg->enlist(&msgs[path]);
		msglock.unlock();
		return false;
	}

	tp = rr->targets;
	while(tp) {
		if(!rr->expires || tp->expires > now) {
			eXosip_lock();
			eXosip_unlock();
		}
		tp.next();
	}

	registry::release(rr);
	delete msg;
	return true;
}

void messages::automatic(void)
{
	linked_pointer<registry::target> tp;
	MappedRegistry *rr;
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
			delete msg;
			msg = NULL;	
		}
		msglock.release();
		if(!msg || send(msg))
			return;
	}
}

END_NAMESPACE
