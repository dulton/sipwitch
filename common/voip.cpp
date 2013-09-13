/// Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
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

#include <sipwitch-config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/voip.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

static int family = AF_INET;

#ifdef	EXOSIP_API4

bool voip::publish(voip::context_t ctx, const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body)
{
    bool result = true;
    voip::msg_t msg = NULL;

    eXosip_lock(ctx);
    eXosip_build_publish(ctx, &msg, uri, contact, NULL, event, duration, type, body);
    if(msg)
        eXosip_publish(ctx, msg, uri);
    else
        result = false;
    eXosip_unlock(ctx);
    return result;
}

void voip::call_reference(context_t ctx, call_t cid, void *route)
{
    eXosip_lock(ctx);
    eXosip_call_set_reference(ctx, cid, route);
    eXosip_unlock(ctx);
}

void voip::option(context_t ctx, int opt, const void *value)
{
    if(ctx && value) {
        eXosip_lock(ctx);
        eXosip_set_option(ctx, opt, value);
        eXosip_unlock(ctx);
    }
}

void voip::add_authentication(context_t ctx, const char *user, const char *secret, const char *realm, bool automatic) 
{
    eXosip_lock(ctx);
    eXosip_add_authentication_info(ctx, user, user, secret, NULL, realm);
    if(automatic)
        eXosip_automatic_action(ctx);
    eXosip_unlock(ctx);
}

void voip::free_message_request(context_t ctx, msg_t msg)
{
    if(msg)
        osip_message_free(msg);
    eXosip_unlock(ctx);
}

bool voip::make_request_message(context_t ctx, const char *method, const char *to, const char *from, msg_t *msg, const char *route)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_message_build_request(ctx, msg, method, to, from, route);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }
    return true;
}

bool voip::make_response_message(context_t ctx, tid_t tid, int status, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_message_build_answer(ctx, tid, status, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }
    return true;
}

void voip::send_response_message(context_t ctx, tid_t tid, int status, msg_t msg)
{
    if(!msg)
        eXosip_lock(ctx);
    eXosip_message_send_answer(ctx, tid, status, msg);
    eXosip_unlock(ctx);
}

bool voip::make_ack_message(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_ack(ctx, did, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }
    return true;
}

void voip::send_ack_message(context_t ctx, did_t tid, msg_t msg)
{
    if(!msg)
        eXosip_lock(ctx);
    eXosip_call_send_ack(ctx, tid, msg);
    eXosip_unlock(ctx);
}

bool voip::make_prack_message(context_t ctx, tid_t tid, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_prack(ctx, tid, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }
    return true;
}

void voip::send_prack_message(context_t ctx, tid_t tid, msg_t msg)
{
    if(!msg)
        eXosip_lock(ctx);
    eXosip_call_send_prack(ctx, tid, msg);
    eXosip_unlock(ctx);
}

bool voip::make_options_response(context_t ctx, tid_t tid, int status, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_options_build_answer(ctx, tid, status, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }
    return true;
}

void voip::send_options_response(context_t ctx, tid_t tid, int status, msg_t msg)
{
    if(!msg)
        eXosip_lock(ctx);
    eXosip_options_send_answer(ctx, tid, status, msg);
    eXosip_unlock(ctx);
}

bool voip::make_answer_response(context_t ctx, tid_t tid, int status, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_answer(ctx, tid, status, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }
    return true;
}

void voip::send_answer_response(context_t ctx, tid_t tid, int status, msg_t msg)
{
    if(!msg)
        eXosip_lock(ctx);
    eXosip_call_send_answer(ctx, tid, status, msg);
    eXosip_unlock(ctx);
}

void voip::send_request_message(context_t ctx, msg_t msg)
{
    if(!msg)
        return;

    eXosip_message_send_request(ctx, msg);
    eXosip_unlock(ctx);
}

void voip::release_call(context_t ctx, call_t cid, did_t did)
{
    eXosip_lock(ctx);
    eXosip_call_terminate(ctx, cid, did);
    eXosip_unlock(ctx);
}

bool voip::make_dialog_request(context_t ctx, did_t did, const char *method, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_request(ctx, did, method, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

bool voip::make_dialog_notify(context_t ctx, did_t did, int status, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_notify(ctx, did, status, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

bool voip::make_dialog_update(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_update(ctx, did, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

bool voip::make_dialog_refer(context_t ctx, did_t did, const char *to, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_refer(ctx, did, to, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

bool voip::make_dialog_info(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_info(ctx, did, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

bool voip::make_dialog_options(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_options(ctx, did, msg);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

void voip::send_dialog_message(context_t ctx, did_t did, msg_t msg)
{
    if(!msg)
        return;

    eXosip_call_send_request(ctx, did, msg);
    eXosip_unlock(ctx);
}

bool voip::make_invite_request(context_t ctx, const char *to, const char *from, const char *subject, msg_t *msg, const char *route)
{
    *msg = NULL;
    eXosip_lock(ctx);
    eXosip_call_build_initial_invite(ctx, msg, to, from, route, subject);
    if(!*msg) {
        eXosip_unlock(ctx);
        return false;
    }

    return true;
}

voip::call_t voip::send_invite_request(context_t ctx, msg_t msg)
{
    if(!msg)
        return -1;

    int rtn = eXosip_call_send_initial_invite(ctx, msg);
    eXosip_unlock(ctx);
    return rtn;
}

voip::reg_t voip::make_registry_request(context_t ctx, const char *uri, const char *s, const char *c, unsigned exp, msg_t *msg) 
{
    *msg = NULL;
    eXosip_lock(ctx);
    reg_t rid = eXosip_register_build_initial_register(ctx, uri, s, c, exp, msg);
    if(!*msg)
        eXosip_unlock(ctx);
    return rid;
}

void voip::send_registry_request(context_t c, reg_t r, msg_t msg) 
{
    if(!msg)
	    return;
    eXosip_register_send_register(c, r, msg);
    eXosip_unlock(c);
}

bool voip::release_registry(context_t ctx, reg_t rid)
{
    bool rtn = false;
    msg_t msg = NULL;
    eXosip_lock(ctx);
    eXosip_register_build_register(ctx, rid, 0, &msg);
    if(msg) {
        eXosip_register_send_register(ctx, rid, msg);
        rtn = true;
    }
    eXosip_unlock(ctx);
    return rtn;
}

void voip::default_action(context_t ctx, event_t ev)
{
    eXosip_lock(ctx);
    eXosip_default_action(ctx, ev);
    eXosip_unlock(ctx);
}

void voip::automatic_action(context_t ctx)
{
    eXosip_lock(ctx);
    eXosip_automatic_action(ctx);
    eXosip_unlock(ctx);
}

voip::event_t voip::get_event(context_t ctx, timeout_t timeout)
{
    unsigned s = timeout / 1000l;
    unsigned ms = timeout % 1000l;
    return eXosip_event_wait(ctx, s, ms);
}

bool voip::listen(context_t ctx, int proto, const char *addr, unsigned port, bool tls)
{
    int tlsmode = 0;

    if(!ctx)
        return false;

#ifdef  AF_INET6
    if(family == AF_INET6 && addr && (!strcmp(addr, "::0") || !strcmp(addr, "::*")))
        addr = NULL;
#endif
    if(addr && !strcmp(addr, "*"))
        addr = NULL;

    // port always even...
    port = port & 0xfffe;
    if(tls) {
        tlsmode = 1;
        ++port;	// tls always next odd port...
    }

    if(eXosip_listen_addr(ctx, proto, addr, port, family, tlsmode))
        return false;

    return true;
}

void voip::create(context_t *ctx, const char *agent, int f)
{
    *ctx = eXosip_malloc();
    eXosip_init(*ctx);

    if(agent)
        eXosip_set_user_agent(*ctx, agent);

    family = f;

#ifdef  AF_INET6
    if(family == AF_INET6)
        eXosip_enable_ipv6(1);
#endif
}

void voip::release(context_t ctx)
{
    if(!ctx)
        return;

    eXosip_quit(ctx);
}

#else

static bool active = false;

bool voip::publish(voip::context_t ctx, const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body)
{
    bool result = true;
    voip::msg_t msg = NULL;

    eXosip_lock();
    eXosip_build_publish(&msg, uri, contact, NULL, event, duration, type, body);
    if(msg)
        eXosip_publish(msg, uri);
    else
        result = false;
    eXosip_unlock();
    return result;
}

void voip::call_reference(context_t ctx, call_t cid, void *route)
{
    eXosip_lock();
    eXosip_call_set_reference(cid, route);
    eXosip_unlock();
}

void voip::option(voip::context_t ctx, int opt, const void *value)
{
    if(ctx && value) {
        eXosip_lock();
        eXosip_set_option(opt, value);
        eXosip_unlock();
    }
}

void voip::add_authentication(context_t ctx, const char *user, const char *secret, const char *realm, bool automatic) 
{
    eXosip_lock();
    eXosip_add_authentication_info(user, user, secret, NULL, realm);
    if(automatic)
        eXosip_automatic_action();
    eXosip_unlock();
}

void voip::free_message_request(context_t ctx, msg_t msg)
{
    if(msg)
        osip_message_free(msg);
    eXosip_unlock();
}

bool voip::make_request_message(context_t ctx, const char *method, const char *to, const char *from, msg_t *msg, const char *route)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_message_build_request(msg, method, to, from, route);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }
    return true;
}

bool voip::make_response_message(context_t ctx, tid_t tid, int status, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_message_build_answer(tid, status, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }
    return true;
}

void voip::send_response_message(context_t ctx, tid_t tid, int status, msg_t msg)
{
    if(!msg)
        eXosip_lock();
    eXosip_message_send_answer(tid, status, msg);
    eXosip_unlock();
}

bool voip::make_invite_request(context_t ctx, const char *to, const char *from, const char *subject, msg_t *msg, const char *route)
{
    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_initial_invite(msg, to, from, route, subject);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

voip::call_t voip::send_invite_request(context_t ctx, msg_t msg)
{
    if(!msg)
        return -1;

    int rtn = eXosip_call_send_initial_invite(msg);
    eXosip_unlock();
    return rtn;
}

bool voip::make_options_response(context_t ctx, tid_t tid, int status, msg_t *msg)
{
    if(!msg)
        return false;
    *msg = NULL;
    eXosip_lock();
    eXosip_options_build_answer(tid, status, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }
    return true;
}

void voip::send_options_response(context_t ctx, tid_t tid, int status, msg_t msg)
{
    if(!msg)
        eXosip_lock();
    eXosip_options_send_answer(tid, status, msg);
    eXosip_unlock();
}

bool voip::make_answer_response(context_t ctx, tid_t tid, int status, msg_t *msg)
{
    if(!msg)
        return false;
    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_answer(tid, status, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }
    return true;
}

void voip::send_answer_response(context_t ctx, tid_t tid, int status, msg_t msg)
{
    if(!msg)
        eXosip_lock();
    eXosip_call_send_answer(tid, status, msg);
    eXosip_unlock();
}

void voip::send_request_message(context_t ctx, msg_t msg)
{
    if(!msg)
        return;

    eXosip_message_send_request(msg);
    eXosip_unlock();
}

voip::reg_t voip::make_registry_request(context_t ctx, const char *uri, const char *s, const char *c, unsigned exp, msg_t *msg) 
{
    if(!msg)
        return -1;

    *msg = NULL;
    eXosip_lock();
    reg_t rid = eXosip_register_build_initial_register(uri, s, c, exp, msg);
    if(!msg)
        eXosip_unlock();
    return rid;
}

void voip::send_registry_request(context_t c, reg_t r, msg_t msg) 
{
    if(!msg)
        return;
    eXosip_register_send_register(r, msg);
    eXosip_unlock();
}

bool voip::release_registry(context_t ctx, reg_t rid)
{
    bool rtn = false;
    msg_t msg = NULL;
    eXosip_lock();
    eXosip_register_build_register(rid, 0, &msg);
    if(msg) {
        eXosip_register_send_register(rid, msg);
        rtn = true;
    }
    eXosip_unlock();
    return rtn;
}

void voip::release_call(context_t ctx, call_t cid, did_t did)
{
    eXosip_lock();
    eXosip_call_terminate(cid, did);
    eXosip_unlock();
}

bool voip::make_ack_message(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_ack(did, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }
    return true;
}

void voip::send_ack_message(context_t ctx, did_t tid, msg_t msg)
{
    if(!msg)
        eXosip_lock();
    eXosip_call_send_ack(tid, msg);
    eXosip_unlock();
}

bool voip::make_prack_message(context_t ctx, tid_t tid, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_prack(tid, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }
    return true;
}

void voip::send_prack_message(context_t ctx, tid_t tid, msg_t msg)
{
    if(!msg)
        eXosip_lock();
    eXosip_call_send_prack(tid, msg);
    eXosip_unlock();
}

bool voip::make_dialog_request(context_t ctx, did_t did, const char *method, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_request(did, method, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

bool voip::make_dialog_notify(context_t ctx, did_t did, int status, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_notify(did, status, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

bool voip::make_dialog_update(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_update(did, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

bool voip::make_dialog_refer(context_t ctx, did_t did, const char *to, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_refer(did, to, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

bool voip::make_dialog_info(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_info(did, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

bool voip::make_dialog_options(context_t ctx, did_t did, msg_t *msg)
{
    if(!msg)
        return false;

    *msg = NULL;
    eXosip_lock();
    eXosip_call_build_options(did, msg);
    if(!*msg) {
        eXosip_unlock();
        return false;
    }

    return true;
}

void voip::send_dialog_message(context_t ctx, did_t did, msg_t msg)
{
    if(!msg)
        return;

    eXosip_call_send_request(did, msg);
    eXosip_unlock();
}

void voip::default_action(context_t ctx, event_t ev)
{
    eXosip_lock();
    eXosip_default_action(ev);
    eXosip_unlock();
}

void voip::automatic_action(context_t ctx)
{
    eXosip_lock();
    eXosip_automatic_action();
    eXosip_unlock();
}

voip::event_t voip::get_event(context_t ctx, timeout_t timeout)
{
    unsigned s = timeout / 1000l;
    unsigned ms = timeout % 1000l;
    return eXosip_event_wait(s, ms);
}

bool voip::listen(context_t ctx, int proto, const char *addr, unsigned port, bool tls)
{
    int tlsmode = 0;

#ifdef  AF_INET6
    if(family == AF_INET6 && addr && (!strcmp(addr, "::0") || !strcmp(addr, "::*")))
        addr = NULL;
#endif
    if(addr && !strcmp(addr, "*"))
        addr = NULL;

    // port always even...
    port = port & 0xfffe;
    if(tls) {
        tlsmode = 1;
        ++port;	// tls always next odd port...
    }

    if(eXosip_listen_addr(proto, addr, port, family, tlsmode))
        return false;

    return true;
}

void voip::create(context_t *ctx, const char *agent, int f)
{
    if(active) {
        *ctx = NULL;
        return;
    }
    *ctx = (void *)-1;
    eXosip_init();
    active = true;

    if(agent)
        eXosip_set_user_agent(agent);

    family = f;

#ifdef  AF_INET6
    if(family == AF_INET6)
        eXosip_enable_ipv6(1);
#endif
}

void voip::release(context_t ctx)
{
    if(!ctx || !active)
        return;

    active = false;
    eXosip_quit();
}

#endif

void voip::release_event(event_t ev)
{
    if(ev)
        eXosip_event_free(ev);
}

void voip::show(msg_t msg)
{
    char *text = NULL;
    size_t tlen;

    osip_message_to_str(msg, &text, &tlen);
    if(text) {
        text[tlen] = 0;
        shell::printf("%s", text);
        osip_free(text);
    }
}

void voip::server_accepts(voip::msg_t msg)
{
    osip_message_set_header(msg, ACCEPT, "application/sdp, text/plain");
}

void voip::server_allows(voip::msg_t msg)
{
    osip_message_set_header(msg, ALLOW, "INVITE,ACK,CANCEL,OPTIONS,INFO,REFER,MESSAGE,SUBSCRIBE,NOTIFY,REGISTER,PRACK");
    osip_message_set_header(msg, ALLOW_EVENTS, "talk, hold, refer");
}

void voip::server_requires(voip::msg_t msg, const char *txt)
{
    osip_message_set_require(msg, txt);
}

void voip::server_supports(voip::msg_t msg, const char *txt)
{
    osip_message_set_supported(msg, txt);
}

void voip::header(voip::msg_t msg, const char *key, const char *value)
{
    osip_message_set_header(msg, key, value);
}

void voip::attach(msg_t msg, const char *type, const char *body, size_t size)
{
    if(body)
        osip_message_set_body(msg, body, size);
    if(type)
        osip_message_set_content_type(msg, type);
}

void voip::attach(msg_t msg, const char *type, const char *body)
{
    attach(msg, type, body, strlen(body));
}


