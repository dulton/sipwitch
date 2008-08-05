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
	char sdp[1024];

	static void startup(unsigned count, unsigned short port = 9000, int family = AF_INET, const char *iface = NULL);
	static void shutdown(void);
	static rtpproxy *create(unsigned count);
	static void slice(timeout_t timeout);
	static void publish(const char *published);

	void release(void);
	void rewrite(const char *body, struct sockaddr *iface = NULL);
};

END_NAMESPACE

#endif