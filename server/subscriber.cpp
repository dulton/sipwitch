// Copyright (C) 2007-2008 David Sugar, Tycho Softworks.
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

class __LOCAL listener : public JoinableThread
{
public:
	listener();

private:
	void run(void);
};

static class __LOCAL subscriber : private modules::sipwitch
{
private:
	static subscriber _sub;

	friend class listener;

	void registration(int id, modules::regmode_t mode);
	bool authenticate(int id, const char *remote_realm);
	void update(void);

public:
	subscriber();

	void reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);
} _sub;

static volatile bool changed = false;
static bool rtp_running = false;
static volatile timeout_t interval = 50;
static volatile time_t refresh = 60;
static volatile time_t updated = 0;
static int priority = 0;
static const char *iface = NULL;
static char *server = NULL;
static char *proxy = NULL;
static char *userid = NULL;
static char *volatile secret = NULL;
static char *identity = NULL;
static MappedRegistry provider;	// fake provider record to be used...
static char *volatile published = NULL;
static unsigned short port = 9000;
static listener *thr = NULL;

listener::listener() :
JoinableThread(priority)
{
}

void listener::run(void)
{
	time_t now;

	rtp_running = true;
	while(rtp_running) {
		time(&now);
		if(now > updated) {
			updated = now + refresh;
			service::publish((const char *)published);
		}
	}
	process::errlog(DEBUG1, "stopping rtpproxy thread");
}

subscriber::subscriber() :
modules::sipwitch()
{
	memset(&provider, 0, sizeof(provider));
	provider.rid = -1;
	provider.type = MappedRegistry::EXTERNAL;
	// we already know provider is normally external / outside NAT....
	String::set(provider.network, sizeof(provider.network), "*");
}

void subscriber::update(void)
{
	osip_message_t *msg = NULL;
	char contact[MAX_URI_SIZE];
	char uri[MAX_URI_SIZE];
	char reg[MAX_URI_SIZE];
	unsigned len;
	Socket::address dest = server;

	process::uuid(provider.remote, sizeof(provider.remote), server);
	snprintf(uri, sizeof(uri), "sip:%s@%s", userid, server);
	snprintf(reg, sizeof(reg), "sip:%s", server);
	snprintf(contact, sizeof(contact), "sip:%s@", provider.remote);

	changed = false;
	len = strlen(contact);
	Socket::getinterface((struct sockaddr *)&provider.contact, dest.getAddr());
	Socket::getaddress((struct sockaddr *)&provider.contact, contact + len, sizeof(contact) - len);
	len = strlen(contact);
	snprintf(contact + len, sizeof(contact) - len, ":%u", sip_port);
	debug(3, "registering %s with %s", contact, server);
		
	eXosip_lock();
	provider.rid = eXosip_register_build_initial_register(uri, reg, contact, refresh, &msg);
	if(msg) {
		osip_message_set_header(msg, "Event", "Registration");
		osip_message_set_header(msg, "Allow-Events", "presence");
		eXosip_register_send_register(provider.rid, msg);
		provider.status = MappedRegistry::IDLE;
	}
	else {
		provider.status = MappedRegistry::OFFLINE;
		provider.rid = -1;
	}
	eXosip_unlock();
}

void subscriber::start(service *cfg) 
{
	assert(cfg != NULL);

	if(count) {
		provider.external.statnode = stats::request("provider");	

		if(changed)
			update();
		
		thr = new listener();
		thr->start();
	} 
}

void subscriber::stop(service *cfg)
{
	assert(cfg != NULL);

	rtp_running = false;
	if(thr) {
		process::errlog(DEBUG1, "rtp proxy stopping");
		delete thr;
	}
}

void subscriber::snapshot(FILE *fp) 
{ 
	assert(fp != NULL);

	fprintf(fp, "subscriber:\n"); 
} 

void subscriber::reload(service *cfg)
{
	assert(cfg != NULL);	

	char *temp;
	char *vp;
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("subscriber");
	char buffer[160];

	updated = 0l;

	while(is(sp)) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			if(!stricmp(key, "count") && !isConfigured())
				count = atoi(value);
			else if(!stricmp(key, "interface") && !isConfigured())
				iface = strdup(value);
			else if(!stricmp(key, "interval"))
				interval = atol(value);
			else if(!stricmp(key, "priority") && !isConfigured())
				priority = atoi(value);
			else if(!stricmp(key, "port") && !isConfigured())
				port = atoi(value);
			// very rare we may wish to override provider network/nat state
			else if(!stricmp(key, "network"))
				String::set(provider.network, sizeof(provider.network), value);
			else if(!stricmp(key, "refresh"))
				refresh = atoi(value);
			else if(!stricmp(key, "publish") || !stricmp(key, "public") || !stricmp(key, "gateway")) {
				vp = published;
				published = strdup(value);
				if(vp)
					free((void *)vp);
			}			
			else if(!stricmp(key, "registrar") || !stricmp(key, "server")) {
				if(uri::resolve(value, buffer, sizeof(buffer))) {
					changed = true;
					server = cfg->dup(buffer);
					debug(2, "subscriber provider is %s", buffer);
				}
				else {
					changed = false;
					process::errlog(ERRLOG, "subscriber: %s: cannot resolve", value);
				}
			}
			else if(!stricmp(key, "proxy")) {
				temp = proxy;
				proxy = strdup(value);
				if(temp)
					free(temp);
			}
			else if(!stricmp(key, "userid")) {
				temp = userid;
				userid = strdup(value);
				if(temp)
					free(temp);
			}
			else if(!stricmp(key, "secret")) {
				temp = secret;
				secret = strdup(value);
				if(temp)
					free(temp);
			}
			else if(!stricmp(key, "identity")) {
				temp = identity;
				identity = strdup(value);
				if(temp)
					free(temp);
			}
		}
		sp.next();
	}

	if(!isConfigured() && count)
		stats::allocate(1);
}

void subscriber::registration(int id, modules::regmode_t mode) 
{
	if(id == -1 || id != provider.rid)
		return;

	switch(mode) {
	case modules::REG_FAILED:
		process::errlog(ERRLOG, "service provider offline");
		provider.status = MappedRegistry::OFFLINE;
		return;
	case modules::REG_TERMINATED:
		process::errlog(ERRLOG, "service provider failed");
		provider.rid = -1;
		provider.status = MappedRegistry::OFFLINE;
		if(changed)
			update();
		return;
	case modules::REG_SUCCESS:
		process::errlog(NOTICE, "service provider active");
		provider.status = MappedRegistry::IDLE;
		return;
	}
}	

bool subscriber::authenticate(int id, const char *remote_realm)
{
	if(id == -1 || id != provider.rid)
		return false;

	if(secret && *secret)
		debug(3, "authorizing %s for %s", userid, remote_realm);
	else {
		debug(3, "cannot authorize %s for %s", userid, remote_realm);
		return false;
	}

	eXosip_lock();
	eXosip_add_authentication_info(userid, userid, secret, NULL, remote_realm);
	eXosip_automatic_action();
	eXosip_unlock();
	return true;
}

END_NAMESPACE
