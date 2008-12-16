// Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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

#ifndef _SIPWITCH_RTPPROXY_H_
#define	_SIPWITCH_RTPPROXY_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	_UCOMMON_SOCKET_H_
#include <ucommon/socket.h>
#endif

#ifndef	_SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT rtpproxy : protected LinkedObject
{
private:
	rtpproxy();
	LinkedObject *sockets;

public:
	typedef enum {NO_PROXY, LOCAL_PROXY, REMOTE_PROXY, SUBNET_PROXY, BRIDGE_PROXY, GATEWAY_PROXY} type_t;
	typedef	enum {UNKNOWN, INCOMING, OUTGOING, BOTHWAY} mode_t;

	class __EXPORT session {
	public:
		rtpproxy::type_t type;
		char network[16];
		struct sockaddr_internet iface;

		session();
		void clear(void);
	};

	char sdp[1024];
	volatile bool has_remote, has_local;
	unsigned quality;
	
	mode_t mode;

	static bool isIPV6(void);
	static void enableIPV6(void);
	static void startup(unsigned count, unsigned short port = 9000, const char *iface = NULL);
	static void shutdown(void);
	static rtpproxy *create(unsigned count, mode_t = rtpproxy::UNKNOWN, unsigned quality = 0);
	static void slice(timeout_t timeout);
	static void publish(const char *published);
	static void pinhole(void);
	static struct sockaddr *getPublished(void);
	static void copy(session *target, session *source);
	static unsigned count(rtpproxy *rtp);
	static rtpproxy *assign(rtpproxy *proxy, unsigned count);

	void release(void);
	void rewrite(const char *body, struct sockaddr *iface = NULL);
};

END_NAMESPACE

#endif
