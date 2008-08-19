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

#include <config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/rtpproxy.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

class __LOCAL rtpsocket : public LinkedObject
{
public:
	int so;
	unsigned short port;
	rtpproxy *proxy;
	volatile bool has_remote, has_local;
	struct sockaddr_storage peer, from;
	time_t lastio;

	rtpsocket(bool reuse);

	void release(void);
};

static condlock_t locking;
static LinkedObject *free_proxy = NULL;
static LinkedObject *free_sockets = NULL;
static rtpsocket **map = NULL;
static mempager heap;
static bool running = true;
static unsigned priority = 0;
static unsigned alloc_proxy = 0, alloc_sockets = 0;
static unsigned active_proxy = 0, active_sockets = 0;
static unsigned proxy_sockets = 0;
static const char *proxy_iface = NULL;
static struct sockaddr_storage proxy_published;
static unsigned short proxy_port = 9000;
static int proxy_family = AF_INET;
static fd_set active, result;
static volatile unsigned hiwater = 0;

rtpsocket::rtpsocket(bool reuse) :
LinkedObject()
{
	char num[8];
	if(!reuse) {
		port = proxy_port++;
		snprintf(num, sizeof(num), "%u", proxy_port);
		so = Socket::create(proxy_iface, num, proxy_family, 0, SOCK_DGRAM);
		if(so >= hiwater)
			hiwater = so + 1;
		FD_SET(so, &active); 
	}
	if(so != INVALID_SOCKET)
		map[so] = this;	
	proxy = NULL;
	has_remote = false;
}

void rtpsocket::release(void)
{
	LinkedObject::next = free_sockets;
	free_sockets = this;
}

rtpproxy::rtpproxy() :
LinkedObject()
{
}

void rtpproxy::enableIPV6(void)
{
#ifdef	AF_INET6
	proxy_family = AF_INET6;
#endif
}

bool rtpproxy::isIPV6(void)
{
	if(proxy_family == AF_INET)
		return false;

	return true;
}

struct sockaddr *rtpproxy::getPublished(void)
{
	return (struct sockaddr *)&proxy_published;
}

rtpproxy::session::session()
{
	clear();
}

void rtpproxy::session::clear(void)
{
	memset(&iface, 0, sizeof(iface));
	type = rtpproxy::NO_PROXY;
	String::set(network, sizeof(network), "*");
}

void rtpproxy::slice(timeout_t timeout)
{
	struct sockaddr_storage addr;
	struct timeval ts;
	int count;
	socket_t so = 0;
	rtpsocket *rtp, *target;
	char buffer[1024];
	ssize_t len;

	locking.access();
	count = hiwater;

	if(count)
		memcpy(&result, &active, sizeof(fd_set));
	locking.release();

	if(!count) {
		Thread::sleep(timeout);
		return;
	}

	ts.tv_sec = timeout / 1000l;
	ts.tv_usec = (timeout % 1000l) * 1000l;
	if(select(count, &result, NULL, NULL, &ts) < 1) 
		return;

	while(so < count) {
		len = 0;
		if(FD_ISSET(so, &result)) {
			rtp = map[so];
#ifdef	MSG_DONTWAIT
			len = Socket::recvfrom(rtp->so, buffer, sizeof(buffer), MSG_DONTWAIT, &addr);
#else
			len = Socket::recvfrom(rtp->so, buffer, 1, MSG_PEEK, NULL);
			if(len > 0)
				len = Socket::recvfrom(rtp->so, buffer, sizeof(buffer), 0, &addr);
#endif
			// initialize local side if bi-directional proxy
			if(rtp->proxy->mode == BOTHWAY && !rtp->has_local && !rtp->has_remote) {
				time(&rtp->lastio);
				memcpy(&rtp->peer, &addr, Socket::getlen((struct sockaddr *)&addr));
				rtp->has_local = rtp->proxy->has_local;
				len = 0;
			}	
		}
		if(len > 0) {
			time(&rtp->lastio);
			if(!Socket::equal((struct sockaddr *)&(rtp->peer), (struct sockaddr *)&addr)) { 
				if(!rtp->has_remote) {
					rtp->has_remote = rtp->proxy->has_remote = true;
					memcpy(&rtp->from, &addr, Socket::getlen((struct sockaddr *)&addr)); 
				}
				Socket::sendto(rtp->so, buffer, (size_t)len, 0, (struct sockaddr *)&rtp->peer);
			}
			else if(rtp->has_remote) {
				rtp->has_local = rtp->proxy->has_local = true;
				Socket::sendto(rtp->so, buffer, (size_t)len, 0, (struct sockaddr *)&rtp->from);
			}
		}
		++so;
	}
	Thread::yield();
}

void rtpproxy::pinhole(void)
{
	socket_t so = 0;
	rtpsocket *rtp;
	time_t now;
	
	time(&now);

	while(so < hiwater) {
		rtp = map[so++];
		if(!rtp || !rtp->proxy || !rtp->proxy->quality)
			continue;
		if(now < rtp->lastio + rtp->proxy->quality)
			continue;	
//		if(rtp->has_local && rtp->proxy->mode == BOTHWAY)
//			time(&rtp->lastio);
//		if(rtp->has_remote)	
//			time(&rtp->lastio);
	}
}

void rtpproxy::startup(unsigned count, unsigned short port, const char *iface)
{
	proxy_iface = iface;
	proxy_port = port;
	proxy_sockets = count;
	if(proxy_sockets) {
		running = true;
		map = new rtpsocket*[sizeof(fd_set)];
		memset(map, 0, sizeof(fd_set) * sizeof(rtpsocket*));
	}

	publish(iface);
}

void rtpproxy::publish(const char *iface)
{
	struct sockaddr *addr = NULL;

	if(!iface || strchr(iface, '*'))
		return;

	Socket::address published(iface);
	addr = published.get(proxy_family);
	if(addr) {
		locking.modify();
		memcpy(&proxy_published, addr, Socket::getlen(addr));
		locking.commit();
	}
}

void rtpproxy::shutdown(void)
{
	running = false;

	if(map) {
		delete[] map;
		map = NULL;
	}

	linked_pointer<rtpsocket> sp = free_sockets;
	while(is(sp)) {
		Socket::release(sp->so);
		sp.next();
	}
}

void rtpproxy::release(void)
{
	rtpsocket *node;

	locking.modify();
	--active_proxy;
	active_sockets -= LinkedObject::count(sockets);
	enlist(&free_proxy);

	linked_pointer<rtpsocket> sp = sockets;
	while(is(sp)) {
		node = *sp;
		sp.next();
		node->release();
	}
	locking.commit();
}

rtpproxy *rtpproxy::create(unsigned count, mode_t mode, unsigned qval)
{
	rtpsocket *sp;
	rtpproxy *proxy;
	bool reuse = true;

	if(!running)
		return false;

	locking.modify();
	if(active_sockets + count > proxy_sockets) {
		locking.commit();
		return NULL;
	}

	caddr_t mem;
	if(free_proxy) { 
		mem = (caddr_t)free_proxy;
		free_proxy = free_proxy->getNext();
		proxy = new(mem) rtpproxy;
	}
	else {
		++alloc_proxy;
		proxy = new rtpproxy;
	}
	
	assert(proxy == NULL);

	while(count--) {
		if(free_sockets) {
			mem = (caddr_t)free_sockets;
			free_sockets = free_sockets->getNext();
		}
		else {
			++alloc_sockets;
			reuse = false;
			mem = (caddr_t)heap.alloc(sizeof(rtpsocket));
		}
		sp = new(mem) rtpsocket(reuse);
		sp->enlist(&proxy->sockets);
		sp->proxy = proxy;
	}	
	proxy->mode = mode;
	proxy->quality = qval;
	locking.commit();
	return proxy;
}	

void rtpproxy::copy(session *target, session *source)
{
	memcpy(target, source, sizeof(session));
}
