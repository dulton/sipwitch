// Copyright (C) 2010 David Sugar, Tycho Softworks.
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

static unsigned priority = 0;
static unsigned baseport = 5062;
static unsigned portcount = 38;
static bool ipv6 = false;
static LinkedObject *runlist = NULL;
static mutex_t lock;
static media::proxy *nat = NULL;
static fd_set connections;
static media::proxy *map[sizeof(connections) * 8];

static media _proxy;

media::proxy::proxy() :
LinkedObject(&runlist)
{
	so = INVALID_SOCKET;
	expires = 0l;
	port = baseport++;
};

media::proxy::~proxy()
{
	Socket::release(so);
}

void media::proxy::reconnect(struct sockaddr *host)
{
	struct sockaddr *hp = (struct sockaddr *)&local;

	switch(host->sa_family) {
#ifdef	AF_INET6
	case AF_INET6:
		((struct sockaddr_in6*)(host))->sin6_port = 
			((struct sockaddr_in6 *)(hp))->sin6_port;
		break;
#endif
	case AF_INET:
		((struct sockaddr_in*)(host))->sin_port = 
			((struct sockaddr_in *)(hp))->sin_port;
	}
	Socket::store(&local, host);
}

bool media::proxy::activate(media::sdp& parser)
{
	struct sockaddr *iface = parser.peering;
	struct sockaddr *host = (struct sockaddr *)&parser.local;
	
	release(0);
	Socket::store(&local, host);

	switch(iface->sa_family) {
#ifdef	AF_INET6
	case AF_INET6:
		so = Socket::create(AF_INET6, SOCK_DGRAM, 0);
		((struct sockaddr_in6*)(host))->sin6_port = htons(++parser.mediaport);
		((struct sockaddr_in6*)(iface))->sin6_port = htons(port);
		break;
#endif
	case AF_INET:
		so = Socket::create(AF_INET, SOCK_DGRAM, 0);
		((struct sockaddr_in*)(host))->sin_port = htons(++parser.mediaport);
		((struct sockaddr_in*)(iface))->sin_port = htons(port);
	}

	if(so == INVALID_SOCKET)
		return false;

	Socket::store(&peering, iface);
	Socket::bindto(so, iface);
	FD_SET(so, &connections);
	map[so] = this;
}

void media::proxy::release(time_t expire)
{
	expire = expires;
	if(expire || so == INVALID_SOCKET)
		return;

	FD_CLR(so, &connections);
	map[so] = NULL;
	Socket::release(so);
	so = INVALID_SOCKET;
}

media::sdp::sdp()
{
	outdata = NULL;
	bufdata = NULL;
	mediacount = 0;
	mediaport = 0;
	nat = NULL;
	memset(&local, 0, sizeof(local));
	memset(&top, 0, sizeof(local));
}

media::sdp::sdp(const char *source, char *target, size_t len)
{
	set(source, target, len);
}

void media::sdp::connect(void)
{
	linked_pointer<media::proxy> pp = *nat;
	
	while(is(pp) && mediacount--) {
		pp->reconnect((struct sockaddr *)&local);
		pp.next();
	}
	memcpy(&local, &top, sizeof(local));
}

void media::sdp::set(const char *source, char *target, size_t len)
{
	outdata = target;
	bufdata = source;
	outpos = 0;
}

char *media::sdp::get(char *buffer, size_t len)
{
	char *base = buffer;

	// if eod, return NULL
	if(!bufdata || *bufdata == 0) {
		*buffer = 0;
		return NULL;
	}

	while(len > 1 && *bufdata != 0) {
		if(*bufdata == '\r') {
			++bufdata;
			continue;
		}
		else if(*buffer == '\n') {
			*buffer = 0;
			return base;
		}
		*(buffer++) = *(bufdata++);
		--len;
	}
	*buffer = 0;
	return base;
}

size_t media::sdp::put(char *buffer)
{
	size_t count = 0;

	if(!outdata)
		return 0;	

	while(*buffer && outpos < (MAX_SDP_BUFFER - 2)) {
		++count;
		*(outdata++) = *(buffer++);
	}
	
	*(outdata++) = '\r';
	*(outdata++) = '\n';
	*outdata = 0;
	return count + 2;
}

media::media() :
service::callback(2)
{
}

void media::reload(service *cfg)
{
	assert(cfg != NULL);

	if(isConfigured())
		return;

	baseport = sip_port + 2;
	
	linked_pointer<service::keynode> mp = cfg->getList("media");
    const char *key = NULL, *value;

	while(is(mp)) {
		key = mp->getId();
        value = mp->getPointer();
        if(key && value) {
			if(!stricmp(key, "port"))
				baseport = atoi(value);
			else if(!stricmp(key, "priority"))
				priority = atoi(value);
			else if(!stricmp(key, "count"))
				portcount = atoi(value);
		}
		mp.next();
	}
	if(portcount)
		process::errlog(DEBUG2, "media proxy configured for %d ports", portcount);
	else
		process::errlog(DEBUG1, "media proxy disabled");
}

void media::start(service *cfg)
{
	if(portcount)
		process::errlog(DEBUG1, "media proxy starting for %d ports", portcount);
}

void media::stop(service *cfg)
{
	if(portcount)
		process::errlog(DEBUG1, "media proxy stopping");
}

void media::enableIPV6(void)
{
	ipv6 = true;
}

media::proxy *get(media::sdp& parser)
{
	lock.acquire();
	linked_pointer<media::proxy> pp = runlist;
	while(is(pp)) {
		if(pp->so == INVALID_SOCKET) {
			pp->delist(&runlist);
			lock.release();
			// pp->activate(parser);
			return *pp;
		}
		pp.next();
	}
	lock.release();
	return NULL;
}

void media::release(LinkedObject **nat, unsigned expires)
{
	assert(nat != NULL);
	
	proxy *member;
	time_t expire = 0;

	if(!*nat)
		return;

	if(expires) {
		time(&expire);
		expire += expires;
	}

	lock.acquire();
	linked_pointer<proxy> pp = *nat;
	while(is(pp)) {
		member = *pp;
		pp.next();
		member->release(expires);
		member->enlist(&runlist);
	}
	lock.release();
	
	*nat = NULL;
}

bool media::isProxied(const char *source, const char *target, struct sockaddr_storage *peering)
{
	assert(source != NULL);
	assert(target != NULL);
	assert(peering != NULL);

	bool proxy = false;

	// if no port count, then proxy is disabled...
	if(!portcount)
		return false;

	// if same subnets, then we know is not proxied
	if(String::equal(source, target))
		return false;

	// if unknown networks then we cannot proxy...
	if(String::equal(source, "-") || String::equal(target, "-"))
		return false;

	// if sdp source is external, we do not need to proxy (one-legged only)
	// since we assume we can trust external user's public sdp
	if(String::equal(source, "*"))
		return false;

	// if external is remote and also we're ipv6, no need to proxy either...
	if(String::equal(target, "*") && ipv6)
		return false;

	// if remote, then peering for proxy is public address
	if(String::equal(target, "*")) {
		server::published(peering);
		return true;
	}

	// get subnets from policy name
	stack::subnet *src = server::getSubnet(source);
	stack::subnet *dst = server::getSubnet(target);
	
	if(!src || !dst)
		goto exit;

	// check by interface to see if same subnet, else to get subnet peering
	if(!Socket::equal((struct sockaddr *)(&src->iface), (struct sockaddr *)(&dst->iface))) {
		memcpy(peering, &dst->iface, sizeof(struct sockaddr_storage));
		proxy = true;
	}

exit:
	server::release(src);
	server::release(dst);
	// will become true later...
	return proxy;
}

char *media::reinvite(stack::session *session, const char *sdpin)
{
	assert(session != NULL);
	assert(sdpin != NULL);

	stack::call *cr = session->parent;
	struct sockaddr_storage peering;
	stack::session *target = NULL;
	LinkedObject **nat;

	if(session == cr->source)
		target = cr->target;
	else
		target = cr->source;

	// in case we had a nat chain...
	nat = &target->nat;
	media::release(nat, 2);

	if(!isProxied(session->network, target->network, &peering)) {
		String::set(session->sdp, sizeof(session->sdp), sdpin);
		return session->sdp;
	}

	sdp parser(sdpin, session->sdp, sizeof(session->sdp));
	parser.peering = (struct sockaddr *)&peering;
	parser.nat = nat;

	return rewrite(parser);
}

char *media::answer(stack::session *session, const char *sdpin)
{
	assert(session != NULL);
	assert(sdpin != NULL);

	LinkedObject **nat;
	stack::call *cr = session->parent;
	stack::session *target = cr->source;
	struct sockaddr_storage peering;

	if(session == target || (cr->target != NULL && cr->target != session))
		return NULL;

	// in case we had a nat chain...
	nat = &target->nat;
	media::release(nat, 2);

	if(!isProxied(session->network, target->network, &peering)) {
		String::set(session->sdp, sizeof(session->sdp), sdpin);
		return session->sdp;
	}

	sdp parser(sdpin, session->sdp, sizeof(session->sdp));
	parser.peering = (struct sockaddr *)&peering;
	parser.nat = nat;

	return rewrite(parser);
}

char *media::invite(stack::session *session, const char *target, LinkedObject **nat, char *sdpout, size_t size)
{
	assert(session != NULL);
	assert(target != NULL);
	assert(nat != NULL);

	*nat = NULL;
	struct sockaddr_storage peering;

	if(!isProxied(session->network, target, &peering)) {
		String::set(sdpout, size, session->sdp);
		return sdpout;
	}

	sdp parser(session->sdp, sdpout, size);
	parser.peering = (struct sockaddr *)&peering;
	parser.nat = nat;

	return rewrite(parser);
}

char *media::rewrite(media::sdp& parser)
{
	return NULL;
}

END_NAMESPACE
