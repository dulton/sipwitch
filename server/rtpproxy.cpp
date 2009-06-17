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

static bool rtp_running = false;
static volatile timeout_t interval = 50;
static volatile time_t refresh = 60;
static volatile time_t updated = 0;
static int priority = 0;
static const char *iface = NULL;

class __LOCAL rtp : private modules::sipwitch
{
private:
	unsigned short port;
	unsigned count;
	char *volatile published;
	cidr::policy *nets;

	static rtp proxy;

	class __LOCAL listener : public JoinableThread
	{
	public:
		listener();

	private:
		void run(void);
	};

	listener *thr;

	friend class rtp::listener;

public:
	rtp();

	void reload(service *cfg);
	void start(service *cfg);
	void stop(service *cfg);
	void snapshot(FILE *fp);
};

rtp rtp::proxy;

rtp::listener::listener() :
JoinableThread(priority)
{
}

void rtp::listener::run(void)
{
	time_t now;

	rtp_running = true;
	while(rtp_running) {
		rtpproxy::slice(interval);
		time(&now);
		if(now > updated) {
			updated = now + refresh;
			rtpproxy::publish((const char *)rtp::proxy.published);
		}
	}
	process::errlog(DEBUG1, "stopping rtpproxy thread");
}

rtp::rtp() :
modules::sipwitch()
{
	port = 9000;
	count = 0; 	
	published = NULL;
	thr = NULL;
	nets = NULL;
}

void rtp::start(service *cfg) 
{
	assert(cfg != NULL);

	if(count) {
		rtpproxy::startup(count, port, iface);
		process::errlog(INFO, "rtp proxy started for %d ports", count);
		thr = new rtp::listener();
		thr->start();
	} 
}

void rtp::stop(service *cfg)
{
	assert(cfg != NULL);

	rtp_running = false;
	if(thr) {
		process::errlog(DEBUG1, "rtp proxy stopping");
		delete thr;
		rtpproxy::shutdown();
	}
}

void rtp::snapshot(FILE *fp) 
{ 
	assert(fp != NULL);

	fprintf(fp, "RTP PROXY:\n"); 
} 

void rtp::reload(service *cfg)
{
	assert(cfg != NULL);	

	caddr_t mp;
	char *vp;
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("rtpproxy");

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
		}
		sp.next();
	}

	sp = cfg->getList("rtpproxy.networks");
	nets = NULL;

	while(is(sp)) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			mp = (caddr_t)cfg->alloc(sizeof(cidr));
			new(mp) cidr(&nets, value, key);
		}
		sp.next();
	}
}

END_NAMESPACE
