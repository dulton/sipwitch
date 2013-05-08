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

#pragma GCC diagnostic ignored "-Wvariadic-macros"
#undef  HAVE_CONFIG_H

#ifdef  WIN32
#undef  alloca
#endif

#include <ucommon/socket.h>
#include <eXosip2/eXosip.h>

#if defined(EXOSIP_OPT_BASE_OPTION) && !defined(EXOSIP_OPT_DONT_SEND_101)
#define EXOSIP_API4
#endif

namespace sip {
#ifdef  EXOSIP_API4
typedef eXosip_t    *context_t;
inline  void lock(context_t ctx) {eXosip_lock(ctx);}
inline  void unlock(context_t ctx) {eXosip_unlock(ctx);}
#else
typedef void        *context_t;
inline  void lock(context_t ctx) {eXosip_lock();}
inline  void unlock(context_t ctx) {eXosip_unlock();}
#endif

typedef eXosip_event_t  *event_t;
typedef int reg_t;		// registration id
typedef	int	tid_t;		// transaction id
typedef	int did_t;		// dialog id
typedef	int	call_t;		// call id
typedef	osip_message_t	*msg_t;
typedef	unsigned long timeout_t;

bool make_request_message(context_t ctx, const char *method, const char *to, const char *from, msg_t *msg, const char *route = NULL);
bool make_response_message(context_t ctx, tid_t tid, int status, msg_t *msg);
void send_request_message(context_t ctx, msg_t msg);
void send_response_message(context_t ctx, tid_t tid, int status, msg_t msg = NULL);

bool make_invite_request(context_t ctx, const char *to, const char *from, const char *subject, msg_t *msg, const char *route = NULL);
call_t send_invite_request(context_t ctx, msg_t msg);

bool make_answer_response(context_t ctx, tid_t tid, int status, msg_t *msg);
void send_answer_response(context_t ctx, tid_t tid, int status, msg_t msg = NULL);

void release_call(context_t ctx, call_t cid, did_t did);

bool make_dialog_request(context_t ctx, did_t did, const char *method, msg_t *msg);
bool make_dialog_notify(context_t ctx, did_t did, int status, msg_t *msg);
bool make_dialog_update(context_t ctx, did_t did, msg_t *msg);
bool make_dialog_refer(context_t ctx, did_t did, const char *to, msg_t *msg);
bool make_dialog_info(context_t ctx, did_t did, msg_t *msg);
bool make_dialog_options(context_t ctx, did_t did, msg_t *msg);
void send_dialog_message(context_t ctx, did_t did, msg_t msg);

bool make_ack_message(context_t ctx, did_t did, msg_t *msg);
void send_ack_message(context_t ctx, did_t did, msg_t msg = NULL);

bool make_prack_message(context_t ctx, tid_t tid, msg_t *msg);
void send_prack_message(context_t ctx, tid_t tid, msg_t msg);

reg_t make_registry_request(context_t ctx, const char *uri, const char *s, const char *c, unsigned exp, msg_t *msg);
void send_registry_request(context_t ctx, reg_t rid, msg_t msg);
bool release_registry(context_t ctx, reg_t rid);

void add_authentication(context_t ctx, const char *user, const char *secret, const char *realm, bool automatic = false);

void default_action(context_t ctx, event_t ev);
void automatic_action(context_t ctx);

event_t get_event(context_t ctx, timeout_t timeout);
void release_event(event_t ev);

bool listen(context_t ctx, int proto = IPPROTO_UDP, const char *iface = NULL, unsigned port = 5060, bool tls = false);
void create(context_t *ctx, const char *agent, int family = AF_INET);
void release(context_t ctx);

} // end namespace

#ifndef SESSION_EXPIRES
#define SESSION_EXPIRES "session-expires"
#endif

#ifndef ALLOW_EVENTS
#define ALLOW_EVENTS    "allow-events"
#endif

#ifndef SESSION_EVENT
#define SESSION_EVENT   "event"
#endif

