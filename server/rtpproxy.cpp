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

proxy proxy::rtp;

proxy::listener::listener() :
JoinableThread(priority)
{
}

void proxy::listener::run(void)
{
	time_t now;

	rtp_running = true;
	while(rtp_running) {
		rtpproxy::slice(interval);
		time(&now);
		if(now > updated) {
			updated = now + refresh;
			rtpproxy::publish((const char *)proxy::rtp.published);
		}
	}
	process::errlog(DEBUG1, "stopping rtpproxy thread");
	JoinableThread::exit();
}

proxy::proxy() :
service::callback(-1)
{
	port = 9000;
	count = 0; 	
	published = NULL;
	thr = NULL;
}

void proxy::start(service *cfg) 
{
	assert(cfg != NULL);

	if(count) {
		rtpproxy::startup(count, port, stack::sip.family, iface);
		process::errlog(INFO, "rtp proxy started for %d ports", count);
		thr = new proxy::listener();
		thr->start();
	} 
}

void proxy::stop(service *cfg)
{
	assert(cfg != NULL);

	rtp_running = false;
	if(thr) {
		process::errlog(DEBUG1, "rtp proxy stopping");
		delete thr;
		rtpproxy::shutdown();
	}
}

void proxy::snapshot(FILE *fp) 
{ 
	assert(fp != NULL);

	fprintf(fp, "RTP PROXY:\n"); 
} 

bool proxy::publishingAddress(const char *address)
{
	rtpproxy::publish(address);
	return true;
}

bool proxy::reload(service *cfg)
{
	assert(cfg != NULL);	

	volatile char *vp;
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("rtpproxy");
	int val;

	updated = 0l;
	while(sp) {
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
	return true;
}

END_NAMESPACE
