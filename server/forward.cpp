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

#include <sipwitch/sipwitch.h>
#include <eXosip2/eXosip.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __LOCAL forward : public modules::sipwitch
{
public:
	volatile char *proxy;
	volatile char *realm;
	volatile char *digest;
	volatile char *server;
	time_t	expires;
	bool enabled;

	forward();

private:
	void start(service *cfg);
	void reload(service *cfg);
	void activating(MappedRegistry *rr);
	void expiring(MappedRegistry *rr);
};

static forward forward_plugin;

forward::forward() :
modules::sipwitch()
{
	process::errlog(INFO, "server forward plugin loaded");	
	enabled = false;
	digest = (volatile char *)"MD5";
	realm = (volatile char *)"GNU Telephony";
	proxy = NULL;
}

void forward::reload(service *cfg)
{
	assert(cfg != NULL);

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
			if(String::equal(key, "server")) {
				if(String::equal(value, "sip:", 4))
					value += 4;
				else if(String::equal(value, "sips:", 5))
					value += 5;
				server = cfg->dup(value);
				if(server && *server)
					enable = true;
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
	service::keynode *node, *leaf;
	const char *secret = NULL;
	osip_message_t *msg = NULL;
	char contact[MAX_URI_SIZE];
	char uri[MAX_URI_SIZE];
	unsigned len;

	if(!enabled || rr->rid != -1)
		return;

	node = service::getProtected(rr->userid);
	if(node) {
		leaf = node->leaf("secret");
		if(leaf)
			secret = leaf->getPointer();
	}
	if(secret && *secret && realm && *realm && rr->remote[0]) {
		snprintf(uri, sizeof(uri), "sip:%s@%s", rr->userid, server);
		snprintf(contact, sizeof(contact), "sip:%s@", rr->remote);
		len = strlen(contact);
		Socket::getaddress((struct sockaddr *)&rr->contact, contact + len, sizeof(contact) - len);
		eXosip_lock();
		eXosip_register_build_initial_register(uri, (char *)server, contact, expires / 1000, &msg);
		if(msg) {
			osip_message_set_header(msg, "Event", "Registration");
			osip_message_set_header(msg, "Allow-Events", "presence");
			eXosip_register_send_register(rr->rid, msg);
		}
		else
			rr->rid = -1;
		eXosip_unlock();
	}
	service::release(node);
}

void forward::expiring(MappedRegistry *rr)
{
	osip_message_t *msg = NULL;

	if(!enabled || rr->rid == -1)
		return;

	eXosip_lock();
	eXosip_register_build_register(rr->rid, 0, &msg);
	if(msg)
		eXosip_register_send_register(rr->rid, msg);
	eXosip_unlock();
	rr->rid = -1;
}

END_NAMESPACE
