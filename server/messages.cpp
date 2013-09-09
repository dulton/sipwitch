// Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
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

static mutex_t msglock;
static unsigned keysize = 177;
static unsigned pending = 0;
static LinkedObject **msgs = NULL;
static LinkedObject *sending = NULL;
static LinkedObject *freelist = NULL;
static unsigned volatile allocated = 0;
static time_t volatile duration = 900;

void messages::message::create(void)
{
    time(&expires);
    expires += duration;

    from[0] = 0;
    type[0] = 0;
    body[0] = 0;
    user[0] = 0;
    msglen = 0;
}

messages::messages() :
service::callback(2)
{
}

bool messages::check(void)
{
    shell::log(shell::INFO, "checking messages...");
    msglock.lock();
    msglock.release();
    return true;
}

void messages::cleanup(void)
{
    linked_pointer<message> mp;
    LinkedObject *msgnext;
    unsigned msgcount = 0;
    time_t now;

    if(!pending)
        return;

    while(msgcount < keysize) {
        msglock.lock();
        time(&now);
        mp = msgs[msgcount];
        while(mp) {
            msgnext = mp->getNext();
            if(mp->expires < now) {
                mp->delist(&msgs[msgcount]);
                mp->enlist(&freelist);
            }
            mp = msgnext;
        }
        msglock.unlock();
        ++msgcount;
    }
}

void messages::reload(service *cfg)
{
    assert(cfg != NULL);

    const char *key = NULL, *value;
    linked_pointer<service::keynode> sp = cfg->getList("messages");

    while(sp) {
        key = sp->getId();
        value = sp->getPointer();
        if(key && value) {
            if(!stricmp(key, "keysize") && !is_configured())
                keysize = atoi(value);
            else if(!stricmp(key, "expires"))
                duration = atoi(value) * 60;
        }
        sp.next();
    }

    if(is_configured())
        return;

    msgs = new LinkedObject*[keysize];
    memset(msgs, 0, sizeof(LinkedObject *) * keysize);
}

void messages::snapshot(FILE *fp)
{
    assert(fp != NULL);
    fprintf(fp, "Messaging:\n");
    fprintf(fp, "  allocated messages: %d\n", allocated);
    fprintf(fp, "  pending messages:   %d\n", pending);
}

void messages::update(const char *uid)
{
    assert(uid == NULL || *uid != 0);

    linked_pointer<message> mp;
    LinkedObject *next;
    unsigned path;
    time_t now;
    if(!uid || !pending)
        return;

    path = NamedObject::keyindex(uid, keysize);
    msglock.lock();
    time(&now);
    mp = msgs[path];
    while(mp) {
        next = mp->getNext();
        if(!stricmp(mp->user, uid)) {
            --pending;
            mp->delist(&msgs[path]);
            if(mp->expires < now)
                mp->enlist(&freelist);
            else
                mp->enlist(&sending);
        }
        mp = next;
    }
    msglock.unlock();
}

int messages::deliver(const char *to, const char *reply, const char *from, caddr_t text, size_t len, const char *msgtype, const char *digest)
{
    message *msg;

    if(!msgtype)
        msgtype = "text/plain";

    if(len > sizeof(msg->body))
        return SIP_MESSAGE_TOO_LARGE;

    msglock.lock();
    msg = static_cast<message *>(freelist);
    if(msg)
        freelist = msg->getNext();
    msglock.unlock();
    if(!msg) {
        ++allocated;
        msg = new message();
    }
    msg->create();
    String::set(msg->reply, sizeof(msg->reply), reply);
    String::set(msg->from, sizeof(msg->from), from);
    String::set(msg->type, sizeof(msg->type), msgtype);
    memset(msg->body, 0, sizeof(msg->body));
    if(len)
        memcpy(msg->body, text, len);
    msg->msglen = len;

    if(!strchr(to, '@')) {
        String::set(msg->user, sizeof(msg->user), to);
        return deliver(msg);
    }
    return remote(to, msg, digest);
}

int messages::system(const char *to, const char *text)
{
    char from[MAX_URI_SIZE];
    const char *scheme;
    const char *sysid = stack::sip.system;
    const char *host = stack::sip.published;
    unsigned short port  = sip_port;

    if(stack::sip_tlsmode)
        scheme = "sips";
    else
        scheme = "sip";

    if(!host) {
        host = "127.0.0.1";
#ifdef  AF_INET6
        if(!host && stack::sip_family == AF_INET6)
            host = "::1";
#endif
    }

    if(strchr(host, ':'))
        snprintf(from, sizeof(from), "<%s:%s@[%s]:%u>",
            scheme, sysid, host, port);
    else
        snprintf(from, sizeof(from), "<%s:%s@%s:%u>",
            scheme, sysid, host, port);

    return deliver(to, sysid, from, (caddr_t)text, strlen(text), "text/plain");
}

int messages::remote(const char *to, message *msg, const char *digest)
{
    shell::debug(3, "instant message delivered to %s from %s", to, msg->reply);

    osip_message_t *im = NULL;
    int error = SIP_BAD_REQUEST;

    EXOSIP_LOCK
    eXosip_message_build_request(OPTION_CONTEXT &im, "MESSAGE", to, msg->from, NULL);
    if(im && digest) {
        char *authbuf = new char[1024];
        stringbuf<64> response;
        stringbuf<64> once;
        char nounce[64];
        char *req = NULL;
        osip_uri_to_str(im->req_uri, &req);
        snprintf(authbuf, 1024, "%s:%s", im->sip_method, req);
        Random::uuid(nounce);

        digest_t auth = "md5";
        auth.puts(nounce);
        once = *auth;
        auth = registry::getDigest();
        auth.puts(authbuf);
        response = *auth;
        snprintf(authbuf, 1024, "%s:%s:%s", digest, *once, *response);
        auth.reset();
        auth.puts(authbuf);
        response = *auth;
        snprintf(authbuf, 1024,
            "Digest username=\"%s\""
            ",realm=\"%s\""
            ",uri=\"%s\""
            ",response=\"%s\""
            ",nonce=\"%s\""
            ",algorithm=%s"
            ,msg->reply, registry::getRealm(), req, *response, *once, registry::getDigest());
        voip::header(im, AUTHORIZATION, authbuf);
        delete[] authbuf;
        osip_free(req);
    }
    if(im) {
        printf("BODY %s\n", msg->body);
        osip_message_set_body(im, msg->body, msg->msglen);
        osip_message_set_content_type(im, msg->type);
        stack::siplog(im);
        if(!eXosip_message_send_request(OPTION_CONTEXT im))
            error = SIP_OK;
    }
    EXOSIP_UNLOCK
    return error;
}

int messages::deliver(message *msg)
{
    assert(msg != NULL);

    linked_pointer<registry::target> tp;
    registry::mapped *rr = registry::access(msg->user);
    osip_message_t *im;
    time_t now;
    unsigned msgcount = 0;
    char to[MAX_URI_SIZE];
    int error = SIP_GONE;

    time(&now);
    if(!rr)
        error = SIP_NOT_FOUND;

    if(!rr || (rr->expires && rr->expires < now)) {
        shell::debug(3, "instant message failed for %s from %s; error=%d", msg->user, msg->reply, error);
        goto final;
    }

    shell::debug(3, "instant message delivered to %s from %s", msg->user, msg->reply);
    tp = rr->source.internal.targets;
    while(tp) {
        if(!rr->expires || tp->expires > now) {
            stack::sipAddress(&tp->address, to + 1, msg->user, sizeof(to) - 6);
            to[0] = '<';
            String::add(to, sizeof(to), ";lr>");
            EXOSIP_LOCK
            im = NULL;
            eXosip_message_build_request(OPTION_CONTEXT &im, "MESSAGE", tp->contact, msg->from, to);
            if(im != NULL) {
                stack::sipAddress(&tp->address, to + 1, msg->user, sizeof(to) - 2);
                to[0] = '<';
                String::add(to, sizeof(to), ">");
                if(im->to) {
                    osip_to_free(im->to);
                    im->to = NULL;
                }
                osip_message_set_to(im, to);
                osip_message_set_body(im, msg->body, msg->msglen);
                osip_message_set_content_type(im, msg->type);
                stack::siplog(im);
                if(!eXosip_message_send_request(OPTION_CONTEXT im))
                    ++msgcount;
            }
            EXOSIP_UNLOCK
        }
        tp.next();
    }

    // as long as we sent to one extension, we are ok...
    if(msgcount)
        error = SIP_OK;

final:
    registry::detach(rr);
    msglock.lock();
    msg->enlist(&freelist);
    msglock.release();
    return error;
}

void messages::automatic(void)
{
    message *msg = NULL;
    time_t now;

    for(;;) {
        msglock.lock();
        if(sending)
            time(&now);
        while(sending) {
            msg = (message *)sending;
            sending = msg->getNext();
            if(msg->expires > now)
                break;
            msg->enlist(&freelist);
            msg = NULL;
        }
        msglock.release();
        if(!msg || deliver(msg))
            return;
    }
}

END_NAMESPACE
