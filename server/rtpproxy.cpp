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

class __LOCAL rtp : private service::callback
{
private:
	unsigned short port;
	unsigned count;
	volatile char *published;
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

	bool classifier(rtpproxy::session *session, rtpproxy::session *source, struct sockaddr *addr);
	bool reload(service *cfg);
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
	JoinableThread::exit();
}

rtp::rtp() :
service::callback(-1)
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

bool rtp::reload(service *cfg)
{
	assert(cfg != NULL);	

	caddr_t mp;
	volatile char *vp;
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
			mp = (caddr_t)cfg->alloc_locked(sizeof(cidr));
			new(mp) cidr(&nets, value, key);
		}
		sp.next();
	}
	return true;
}

bool rtp::classifier(rtpproxy::session *sid, rtpproxy::session *src, struct sockaddr *addr)
{
	service::keynode *cfg;

	if(!sid) {
		if(!rtp::proxy.count || rtpproxy::isIPV6())
			return false;

		return true;
	}

	sid->type = rtpproxy::NO_PROXY;

	if(!rtp::proxy.count)
		return false;

	cfg = service::get();
	if(!cfg)
		return false;

	linked_pointer<cidr> np = rtp::proxy.nets;

	if(!is(np)) {
		service::release(cfg);
		return false;
	}

	cidr *member = NULL;
	unsigned top = 0;
		
	while(is(np) && addr) {
		if(np->isMember(addr)) {
			if(np->getMask() > top) {
				top = np->getMask();
				member = *np;
			}
		}
		np.next();	
	}

	if(member)
		String::set(sid->network, sizeof(sid->network), member->getName());
	else
		String::set(sid->network, sizeof(sid->network), "-");

	service::release(cfg);

	// we only do external-to-internal proxy for ipv4.  We can still need rtp
	// proxying if joining two different subnets (private & public), however.

	if(src != sid) {
		if(!stricmp(src->network, "-") && stricmp(sid->network, "-")) {
			if(!rtpproxy::isIPV6())
				sid->type = rtpproxy::REMOTE_PROXY;
		}
		else if(stricmp(src->network, "-") && !stricmp(sid->network, "-")) {
			if(!rtpproxy::isIPV6())
				sid->type = rtpproxy::LOCAL_PROXY;
		}
		else if(!stricmp(src->network, "-") && !stricmp(sid->network, "-")) {
			if(!rtpproxy::isIPV6())
				sid->type = rtpproxy::BRIDGE_PROXY;
		}
		else if(stricmp(src->network, sid->network)) {
			Socket::getinterface((struct sockaddr *)(&sid->iface), addr);
			sid->type = rtpproxy::SUBNET_PROXY;
		}
	}
	else if(addr)
		Socket::getinterface((struct sockaddr *)(&sid->iface), addr);	

	if(sid->type != rtpproxy::NO_PROXY)
		return true;
	
	return false;		
}

END_NAMESPACE
