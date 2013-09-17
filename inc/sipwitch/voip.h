// Copyright (C) 2008-2009 David Sugar, Tycho Softworks.
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

#ifndef _SIPWITCH_VOIP_H_
#define _SIPWITCH_VOIP_H_

#pragma GCC diagnostic ignored "-Wvariadic-macros"
#undef  HAVE_CONFIG_H

#ifdef  WIN32
#undef  alloca
#endif

#include <eXosip2/eXosip.h>
#undef WARNING
#undef CONTACT

#ifndef __SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#if defined(EXOSIP_OPT_BASE_OPTION) && !defined(EXOSIP_OPT_DONT_SEND_101)
#define EXOSIP_API4
#endif

class __EXPORT voip
{
public:
	#ifdef  EXOSIP_API4
	typedef eXosip_t    *context_t;
	inline  static void lock(context_t ctx) {eXosip_lock(ctx);}
	inline  static void unlock(context_t ctx) {eXosip_unlock(ctx);}
	#else
	typedef void        *context_t;
	inline  static void lock(context_t ctx) {eXosip_lock();}
	inline  static void unlock(context_t ctx) {eXosip_unlock();}
	#endif

	typedef eXosip_event_t		*event_t;
	typedef int reg_t;			// registration id
	typedef	int	tid_t;			// transaction id
	typedef	int did_t;			// dialog id
	typedef	int	call_t;			// call id
	typedef	osip_header_t		*hdr_t;
	typedef	osip_message_t		*msg_t;
	typedef	osip_contact_t		*contact_t;
	typedef	osip_uri_param_t	*uri_param_t;
	typedef osip_body_t			*body_t;
	typedef	osip_content_type_t	*ctype_t;
	typedef	osip_from_t			*from_t;
	typedef	osip_via_t			*via_t;
	typedef	osip_to_t			*to_t;
	typedef	osip_uri_t			*uri_t;
	typedef	unsigned long		timeout_t;
	typedef osip_authorization_t		*auth_t;
	typedef	osip_generic_param_t		*param_t;
	typedef	osip_proxy_authenticate_t	*proxyauth_t;

	static bool make_request_message(context_t ctx, const char *method, const char *to, const char *from, msg_t *msg, const char *route = NULL);
	static bool make_response_message(context_t ctx, tid_t tid, int status, msg_t *msg);
	static void send_request_message(context_t ctx, msg_t msg);
	static void send_response_message(context_t ctx, tid_t tid, int status, msg_t msg = NULL);

	static bool make_options_response(context_t ctx, tid_t tid, int status, msg_t *msg);
	static void send_options_response(context_t ctx, tid_t tid, int status, msg_t msg = NULL);

	static bool make_invite_request(context_t ctx, const char *to, const char *from, const char *subject, msg_t *msg, const char *route = NULL);
	static call_t send_invite_request(context_t ctx, msg_t msg);

	static bool make_answer_response(context_t ctx, tid_t tid, int status, msg_t *msg);
	static void send_answer_response(context_t ctx, tid_t tid, int status, msg_t msg = NULL);

	static void release_call(context_t ctx, call_t cid, did_t did);

	static bool make_dialog_request(context_t ctx, did_t did, const char *method, msg_t *msg);
	static bool make_dialog_notify(context_t ctx, did_t did, int status, msg_t *msg);
	static bool make_dialog_update(context_t ctx, did_t did, msg_t *msg);
	static bool make_dialog_refer(context_t ctx, did_t did, const char *to, msg_t *msg);
	static bool make_dialog_info(context_t ctx, did_t did, msg_t *msg);
	static bool make_dialog_options(context_t ctx, did_t did, msg_t *msg);
	static void send_dialog_message(context_t ctx, did_t did, msg_t msg);

	static bool make_ack_message(context_t ctx, did_t did, msg_t *msg);
	static void send_ack_message(context_t ctx, did_t did, msg_t msg = NULL);

	static bool make_prack_message(context_t ctx, tid_t tid, msg_t *msg);
	static void send_prack_message(context_t ctx, tid_t tid, msg_t msg);

	static reg_t make_registry_request(context_t ctx, const char *uri, const char *s, const char *c, unsigned exp, msg_t *msg);
	static void send_registry_request(context_t ctx, reg_t rid, msg_t msg);
	static bool release_registry(context_t ctx, reg_t rid);

	static void add_authentication(context_t ctx, const char *user, const char *secret, const char *realm, bool automatic = false);

	static void default_action(context_t ctx, event_t ev);
	static void automatic_action(context_t ctx);

	static bool publish(context_t ctx, const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body);

	static event_t get_event(context_t ctx, timeout_t timeout);
	static void call_reference(context_t ctx, call_t cid, void *route);
	static void free_message_request(context_t ctx, voip::msg_t msg);
	static void release_event(event_t ev);
	static void option(context_t ctx, int opt, const void *value);

	static bool listen(context_t ctx, int proto = IPPROTO_UDP, const char *iface = NULL, unsigned port = 5060, bool tls = false);
	static void create(context_t *ctx, const char *agent, int family = AF_INET);
	static void release(context_t ctx);
	static void show(msg_t msg);
	static void header(msg_t msg, const char *key, const char *value);
	static void attach(msg_t msg, const char *type, const char *body);
	static void attach(msg_t msg, const char *type, const char *body, size_t size);

	static void server_allows(voip::msg_t msg);
	static void server_accepts(voip::msg_t msg);
	static void server_supports(voip::msg_t msg, const char *txt);
	static void server_requires(voip::msg_t msg, const char *txt);
};

#ifndef SESSION_EXPIRES
#define SESSION_EXPIRES "session-expires"
#endif

#ifndef ALLOW_EVENTS
#define ALLOW_EVENTS    "allow-events"
#endif

#ifndef SESSION_EVENT
#define SESSION_EVENT   "event"
#endif

#define	SDP_BODY	"application/sdp"

// private sipwitch headers...

#define P_SIPWITCH_NODE		"P-sipwitch-node"	// internodal calling
#define	P_SIPWITCH_FEATURE	"P-sipwitch-feat"	// feature code reply


END_NAMESPACE

#endif
