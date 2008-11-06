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

static bool rtp_running = false;
static volatile timeout_t interval = 50;
static volatile time_t refresh = 60;
static volatile time_t updated = 0;
static int priority = 0;
static const char *iface = NULL;
static char *registrar = NULL;
static char *proxy = NULL;
static char *userid = NULL;
static char *secret = NULL;
static char *identity = NULL;

class __LOCAL subscriber : private modules::sipwitch
{
private:
	unsigned short port;
	unsigned count;
	volatile char *published;

	static subscriber provider;

	class __LOCAL listener : public JoinableThread
	{
	public:
		listener();

	private:
		void run(void);
	};

	listener *thr;

	friend class subscriber::listener;

public:
	subscriber();

	bool classifier(rtpproxy::session *session, rtpproxy::session *source, struct sockaddr *addr);
	void reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);
};

subscriber subscriber::provider;

subscriber::listener::listener() :
JoinableThread(priority)
{
}

void subscriber::listener::run(void)
{
	time_t now;

	rtp_running = true;
	while(rtp_running) {
		rtpproxy::slice(interval);
		time(&now);
		if(now > updated) {
			updated = now + refresh;
			rtpproxy::publish((const char *)subscriber::provider.published);
		}
	}
	process::errlog(DEBUG1, "stopping rtpproxy thread");
	JoinableThread::exit();
}

subscriber::subscriber() :
modules::sipwitch()
{
	port = 9000;
	count = 0; 	
	published = NULL;
	thr = NULL;
}

void subscriber::start(service *cfg) 
{
	assert(cfg != NULL);

	if(count) {
		rtpproxy::startup(count, port, iface);
		process::errlog(INFO, "rtp proxy started for %d ports", count);
		thr = new subscriber::listener();
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
		rtpproxy::shutdown();
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
	volatile char *vp;
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("subscriber");

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
			else if(!stricmp(key, "refresh"))
				refresh = atoi(value);
			else if(!stricmp(key, "publish") || !stricmp(key, "public")) {
				vp = published;
				published = strdup(value);
				if(vp)
					free((void *)vp);
			}			
			else if(!stricmp(key, "registrar")) {
				temp = registrar;
				registrar = strdup(value);
				if(temp)
					free(temp);
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
}

bool subscriber::classifier(rtpproxy::session *sid, rtpproxy::session *src, struct sockaddr *addr)
{
	// gateway mode on a router, we assume external calls are always through
	// subscriber's sip provider, and hence require rtp proxy between isp
	// and local user's subnet...
	if(!sid)
		return true;

	sid->type = rtpproxy::NO_PROXY;

	if(!addr)
		addr = rtpproxy::getPublished();

	Socket::getinterface((struct sockaddr *)(&sid->iface), addr);
	if(sid != src) {
		if(!Socket::equalhost((struct sockaddr *)(&sid->iface), (struct sockaddr *)(&src->iface))) {
			sid->type = rtpproxy::GATEWAY_PROXY;
			String::set(sid->network, sizeof(sid->network), "-");
			return true;
		}
	}
	return false;
}

END_NAMESPACE
