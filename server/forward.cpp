// Copyright (C) 2008 David Sugar, Tycho Softworks.
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

#include <sipwitch/sipwitch.h>
#include <eXosip2/eXosip.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	INDEX_SIZE	177

class __LOCAL forward : public modules::sipwitch
{
public:
	class __LOCAL regmap : public LinkedObject
	{
	public:
		friend class forward;
		MappedRegistry *entry;
		bool active;
	};

	char *volatile proxy;
	char *volatile realm;
	char *volatile digest;
	char *volatile server;
	char *volatile refer;
	time_t	expires;
	bool enabled;
	condlock_t locking;
	unsigned allocated, active;
	regmap *freelist;
	regmap *index[INDEX_SIZE];	
	memalloc pager;

	forward();

	void activate(int id);
	void disable(int id);
	bool isActive(int id);
	void remove(int id);
	void add(MappedRegistry *rr);
	MappedRegistry *find(int id);
	void release(MappedRegistry *rr);

private:
	void start(service *cfg);
	void reload(service *cfg);
	void activating(MappedRegistry *rr);
	void expiring(MappedRegistry *rr);
	void registration(int id, modules::regmode_t mode);
	bool publish(MappedRegistry *rr, const char *msgtype, const char *event, const char *expires, const char *body);
	bool authenticate(int id, const char *remote_realm);
	char *referLocal(MappedRegistry *rr, const char *target, char *buffer, size_t size);
};

static forward forward_plugin;

forward::forward() :
modules::sipwitch()
{
	process::errlog(INFO, "server forward plugin loaded");	
	enabled = false;
	refer = NULL;
	digest = (char *)"MD5";
	realm = (char *)"GNU Telephony";
	proxy = NULL;
	freelist = NULL;
	memset(index, 0, sizeof(index));
	allocated = active = 0;
	expires = 120;
}

void forward::release(MappedRegistry *rr)
{
	if(rr)
		locking.release();
}

bool forward::isActive(int id)
{
	bool active = false;

	linked_pointer<regmap> mp;
	int path = id % INDEX_SIZE;
	locking.access();
	mp = index[path];
	while(is(mp)) {
		if(mp->active) {
			active = true;
			break;
		}
		mp.next();
	}
	locking.release();
	return active;
}

MappedRegistry *forward::find(int id)
{
	linked_pointer<regmap> mp;
	int path = id % INDEX_SIZE;
	locking.access();
	mp = index[path];
	while(is(mp)) {
		if(mp->entry->rid == id)
			return mp->entry;
		mp.next();
	}
	locking.release();
	return NULL;
}

void forward::disable(int id)
{
	linked_pointer<regmap> mp;
	int path = id % INDEX_SIZE;
	locking.access();
	mp = index[path];
	while(is(mp)) {
		if(mp->entry->rid == id) {
			mp->active = false;
			break;
		}
		mp.next();
	}
	locking.release();
}

void forward::activate(int id)
{
	linked_pointer<regmap> mp;
	int path = id % INDEX_SIZE;
	locking.access();
	mp = index[path];
	while(is(mp)) {
		if(mp->entry->rid == id) {
			mp->active = true;
			break;
		}
		mp.next();
	}
	locking.release();
}

void forward::remove(int id)
{
	regmap *prior = NULL;
	linked_pointer<regmap> mp;
	int path = id % INDEX_SIZE;
	locking.modify();
	mp = index[path];
	while(is(mp)) {
		if(mp->entry->rid == id) {
			if(prior)
				prior->next = mp->next;
			else
				index[path] = (regmap *)mp->next;
			mp->next = freelist;
			freelist = *mp;
			debug(3, "forward unmap %s from %d", mp->entry->userid, id);
			--active;
			locking.commit();
			mp->entry->rid = -1;
			return;
		}
		mp.next();
	}
	debug(3, "forward map %d not found", id);
	locking.commit();
}

void forward::add(MappedRegistry *rr)
{
	regmap *map;	
	int path = rr->rid % INDEX_SIZE;
	locking.modify();
	map = freelist;
	if(map)
		freelist = (regmap *)map->next;
	else {
		++allocated;
		map = (regmap *)pager.alloc(sizeof(regmap));
	}
	map->entry = rr;
	map->next = index[path];
	index[path] = map;
	locking.commit();
	debug(3, "forward mapped %s as %d", rr->userid, rr->rid);
	++active;
}

void forward::reload(service *cfg)
{
	assert(cfg != NULL);

	char buffer[160];
	bool refering = false;
	bool enable = false;
	const char *key = NULL, *value;
	char *tmp_realm = (char *)realm, *tmp_digest = cfg->dup((char *)digest);
	linked_pointer<service::keynode> fp = cfg->getList("forward");
	linked_pointer<service::keynode> sp = cfg->getList("registry");

	while(is(sp)) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			if(String::equal(key, "digest"))
				tmp_digest = cfg->dup(value);
			else if(String::equal(key, "realm"))
				tmp_realm = cfg->dup(value);
		}
		sp.next();
	}	

	while(is(fp)) {
		key = fp->getId();
		value = fp->getPointer();
		if(key && value) {
			if(String::equal(key, "refer")) {
				if(uri::resolve(value, buffer, sizeof(buffer))) {
					refer = cfg->dup(buffer);
					refering = true;
					debug(2, "forward refer resolved as %s", buffer);
				}
				else {
					process::errlog(ERRLOG, "forward: %s: cannot resolve", value);
					server = NULL;
				}
			}
			else if(String::equal(key, "server")) {
				if(uri::resolve(value, buffer, sizeof(buffer))) {
					server = cfg->dup(buffer);
					debug(2, "forward server resolved as %s", buffer);
				}
				else {
					process::errlog(ERRLOG, "forward: %s: cannot resolve", value);
					server = NULL;
				}
				if(server && *server) {
					enable = true;
					service::dialmode = service::EXT_DIALING;
				}
			}
			else if(String::equal(key, "expires"))
				expires = atoi(value);
			else if(String::equal(key, "digest"))
				tmp_digest = cfg->dup(value);
			else if(String::equal(key, "realm"))
				tmp_realm = cfg->dup(value);
		}
		fp.next();
	}

	if(!refering)
		refer = NULL;

	String::upper(tmp_digest);
	realm = tmp_realm;
	digest = tmp_digest;

	if(enable && !enabled)
		process::errlog(INFO, "server forward plugin activated");
	else if(!enable && enabled)
		process::errlog(INFO, "server forward plugin disabled");
	enabled = enable;
}

void forward::start(service *cfg)
{
	assert(cfg != NULL);
}

void forward::activating(MappedRegistry *rr)
{
	osip_message_t *msg = NULL;
	char contact[MAX_URI_SIZE];
	char uri[MAX_URI_SIZE];
	char reg[MAX_URI_SIZE];
	unsigned len;

	if(!enabled || rr->rid != -1)
		return;

	// must also have extension to forward...
	if(rr->remote[0] && rr->ext && rr->type == MappedRegistry::USER) {
		snprintf(uri, sizeof(uri), "sip:%s@%s", rr->userid, server);
		snprintf(reg, sizeof(reg), "sip:%s", server);
		snprintf(contact, sizeof(contact), "sip:%s@", rr->remote);
		len = strlen(contact);
		Socket::getaddress((struct sockaddr *)&rr->contact, contact + len, sizeof(contact) - len);
		len = strlen(contact);
		snprintf(contact + len, sizeof(contact) - len, ":%d", Socket::getservice((struct sockaddr *)&rr->contact));
		debug(3, "registering %s with %s", contact, server);
		eXosip_lock();
		rr->rid = eXosip_register_build_initial_register(uri, reg, contact, expires, &msg);
		if(msg) {
			osip_message_set_header(msg, "Event", "Registration");
			osip_message_set_header(msg, "Allow-Events", "presence");
			eXosip_register_send_register(rr->rid, msg);
			add(rr);
		}
		else
			rr->rid = -1;
		eXosip_unlock();
	}
}

bool forward::publish(MappedRegistry *rr, const char *msgtype, const char *event, const char *expires, const char *body)
{
	char uri_to[MAX_URI_SIZE];
	char contact[MAX_URI_SIZE];
	osip_message_t *msg = NULL;
	size_t len;

	if(!isActive(rr->rid) || !rr->remote[0])
		return false;

	snprintf(uri_to, sizeof(uri_to), "sip:%s@%s", rr->userid, server);
	snprintf(contact, sizeof(contact), "sip:%s@", rr->remote);	
	len = strlen(contact);
	Socket::getaddress((struct sockaddr *)&rr->contact, contact + len, sizeof(contact) - len);
	len = strlen(contact);
	snprintf(contact + len, sizeof(contact) - len, ":%d", Socket::getservice((struct sockaddr *)&rr->contact));
	debug(3, "publishing %s with %s", contact, server);

	eXosip_lock();
	eXosip_build_publish(&msg, uri_to, contact, NULL, event, expires, msgtype, body);
	if(msg) 
		eXosip_publish(msg, uri_to);
	eXosip_unlock();
	return true;
}

void forward::expiring(MappedRegistry *rr)
{
	osip_message_t *msg = NULL;
	int id = rr->rid;

	if(!id == -1)
		return;

	remove(rr->rid);
	
	if(!enabled)
		return;

	eXosip_lock();
	eXosip_register_build_register(id, 0, &msg);
	if(msg)
		eXosip_register_send_register(id, msg);
	eXosip_unlock();
}

char *forward::referLocal(MappedRegistry *rr, const char *target, char *buffer, size_t size)
{
	if(!refer)
		return NULL;

	if(!isActive(rr->rid))
		return NULL;

	if(sip_tlsmode)
		snprintf(buffer, sizeof(buffer), "sips:%s@%s", target, refer);
	else
		snprintf(buffer, sizeof(buffer), "sip:%s@%s", target, refer);
	return buffer;
}
	
bool forward::authenticate(int id, const char *remote_realm)
{
	MappedRegistry *rr;
	service::keynode *node, *leaf;
	const char *secret = NULL;
	
	if(id == -1)
		return false;

	rr = find(id);
	if(!rr)
		return false;

	node = service::getUser(rr->userid);
	if(node) {
		leaf = node->leaf("secret");
		if(leaf)
			secret = leaf->getPointer();
	}

	if(secret && *secret)
		debug(3, "authorizing %s for %s", rr->userid, remote_realm);
	else {
		debug(3, "cannot authorize %s for %s", rr->userid, remote_realm);
		service::release(node);
		release(rr);
		remove(id);
		return false;
	}
	eXosip_lock();
	eXosip_add_authentication_info(rr->userid, rr->userid, secret, NULL, remote_realm);
	eXosip_automatic_action();
	eXosip_unlock();
	service::release(node);
	release(rr);
	return true;
}

void forward::registration(int id, modules::regmode_t mode)
{
	switch(mode) {
	case modules::REG_FAILED:
		disable(id);
		return;
	case modules::REG_TERMINATED:
		remove(id);
		return;
	case modules::REG_SUCCESS:
		activate(id);
		return;
	}
}

END_NAMESPACE
