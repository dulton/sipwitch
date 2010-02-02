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

static unsigned baseport = 5062;
static bool ipv6 = false;
static LinkedObject *runlist = NULL;
static mutex_t lock;
static media::proxy *nat = NULL;
static fd_set connections;

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

void media::proxy::release(time_t expire)
{
	expire = expires;
	if(expire || so == INVALID_SOCKET)
		return;

	FD_CLR(so, &connections);
	Socket::release(so);
	so = INVALID_SOCKET;
}

media::sdp::sdp()
{
	outdata = bufdata = NULL;
}

media::sdp::sdp(char *source, char *target, size_t len)
{
	set(source, target, len);
}

void media::sdp::set(char *source, char *target, size_t len)
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

void media::enableIPV6(void)
{
	ipv6 = true;
}

media::proxy *get(struct sockaddr *local)
{
	lock.acquire();
	linked_pointer<media::proxy> pp = runlist;
	while(is(pp)) {
		if(pp->so == INVALID_SOCKET) {
			pp->delist(&runlist);
			lock.release();
			// pp->activate(local);
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

char *media::invite(stack::session *session, const char *target, LinkedObject **nat, char *sdp, size_t size)
{
	assert(session != NULL);
	assert(target != NULL);
	assert(nat != NULL);

	*nat = NULL;
	struct sockaddr_storage peering;

	if(!isProxied(session->network, target, &peering)) {
		String::set(sdp, size, session->sdp);
		return sdp;
	}

	// no proxy code yet...
	return NULL;
}

END_NAMESPACE
