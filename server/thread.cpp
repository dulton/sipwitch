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

static volatile bool warning_registry = false;
static bool shutdown_flag = false;
static unsigned shutdown_count = 0;
static unsigned startup_count = 0;
static unsigned active_count = 0;

static char *remove_quotes(char *c)
{
    assert(c != NULL);

    char *o = c;
    char *d = c;
    if(*c != '\"')
        return c;

    ++c;

    while(*c)
        *(d++) = *(c++);

    *(--d) = 0;
    return o;
}

thread::thread() : DetachedThread(stack::sip.stacksize)
{
    to = NULL;
    from = NULL;
    access = NULL;
    routed = NULL;
    reginfo = NULL;
    session = NULL;
}

void thread::publish(void)
{
    int error = SIP_BAD_REQUEST;
    osip_body_t *mbody = NULL;
    const char *tmp = NULL;
    registry::target::status_t status = registry::target::UNKNOWN;
    bool presence = false;
    bool basic = true;
    osip_content_type_t *ct;
    char msgtype[128];
    const char *content = msgtype;
    const char *expires = NULL;
    const char *event = NULL;
    osip_header_t *msgheader;

    if(destination != LOCAL)
        goto final;

    if(!reginfo || !reginfo->isUser())
        goto final;

    if(!String::equal(reginfo->userid, identity))
        goto final;

    osip_message_get_body(sevent->request, 0, &mbody);
    ct = sevent->request->content_type;
    if(mbody)
        tmp = mbody->body;

    msgheader = NULL;
    osip_message_header_get_byname(sevent->request, SESSION_EXPIRES, 0, &msgheader);
    if(msgheader && msgheader->hvalue)
        expires = msgheader->hvalue;

    msgheader = NULL;
    osip_message_header_get_byname(sevent->request, SESSION_EVENT, 0, &msgheader);
    if(msgheader && msgheader->hvalue)
        event = msgheader->hvalue;

    if(ct && ct->subtype)
        snprintf(msgtype, sizeof(msgtype), "%s/%s", ct->type, ct->subtype);
    else if(ct && ct->type)
        String::set(msgtype, sizeof(msgtype), ct->type);
    else
        content = NULL;

    // publish event to forwarders...
    server::announce(reginfo, content, event, expires, tmp);

    // if not presence event, then skip local parsing...
    if(event && stricmp(event, "presence")) {
        error = SIP_OK;
        goto final;
    }

    while(tmp && *tmp)
    {
        if(!strnicmp(tmp, "<presence", 9))
            presence = true;
        else if(!strnicmp(tmp, "</basic", 7))
            basic = false;
        else if(!strnicmp(tmp, "</status>", 9))
            break;
        else if(!strnicmp(tmp, "<basic>open", 11) && basic) {
            status = registry::target::READY;
            tmp += 10;
        }
        else if(!strnicmp(tmp, "<show>dnd", 9) && presence) {
            status = registry::target::DND;
            break;
        }
        else if(!strnicmp(tmp, "<basic>closed", 13) && basic) {
            status = registry::target::OFFLINE;
            break;
        }
        else if(!strnicmp(tmp, "available", 9) && presence) {
            status = registry::target::READY;
            break;
        }
        else if(!strnicmp(tmp, "unavailable", 11) && presence) {
            status = registry::target::OFFLINE;
            break;
        }
        else if(!strnicmp(tmp, "on-the-phone", 12) && presence) {
            status = registry::target::BUSY;
            break;
        }
        else if(!strnicmp(tmp, "online", 6) && presence) {
            tmp += 5;
            status = registry::target::READY;
        }
        else if(!strnicmp(tmp, "busy", 4) && presence) {
            status = registry::target::BUSY;
            break;
        }
        else if(!strnicmp(tmp, "dnd", 3) && presence) {
            status = registry::target::DND;
            break;
        }
        else if(!strnicmp(tmp, "vacation", 8) && presence)
        {
            status = registry::target::AWAY;
            break;
        }
        else if(!strnicmp(tmp, "away", 4) && presence)
        {
            status = registry::target::AWAY;
            break;
        }
        ++tmp;
    }

    reginfo->update(via_address, status);
    error = SIP_OK;

final:
    send_reply(error);
}

void thread::message(void)
{
    osip_content_type_t *ct;
    osip_body_t *body = NULL;
    char address[MAX_URI_SIZE];
    char fromhdr[MAX_URI_SIZE];
    char target[MAX_URI_SIZE];
    char msgtype[64];
    char sysid[64];
    char *msglen = NULL;
    const char *id = NULL;
    const char *digest = NULL;
    const char *hash = NULL;

    switch(destination) {
    case LOCAL:
        if(!dialed.keys) {
            send_reply(SIP_DECLINE);
            return;
        }
        id = service::getValue(dialed.keys, "extension");
        if(!id)
            id = service::getValue(dialed.keys, "id");
        String::set(target, sizeof(target), id);
        break;
    case EXTERNAL:
        String::set(target, sizeof(target), requesting);
        break;
    case REDIRECTED:
        // -digest-: get user digest into "digest" buffer
        if(authorized.keys) {
            hash = digests::get(server::getValue(authorized.keys, "id"));
            if(hash)
                digest = hash;
            else
                digest = server::getValue(authorized.keys, "digest");
        }
        if(!digest) {
            send_reply(SIP_DECLINE);
            return;
        }
        String::set(target, sizeof(target), requesting);
        break;
    default:
        send_reply(SIP_DECLINE);
        return;
    }

    osip_message_get_body(sevent->request, 0, &body);
    ct = sevent->request->content_type;
    if(!body || !ct || !ct->type) {
        send_reply(SIP_BAD_REQUEST);
        digests::release(hash);
        return;
    }

    if(ct->subtype)
        snprintf(msgtype, sizeof(msgtype), "%s/%s",
            ct->type, ct->subtype);
    else
        snprintf(msgtype, sizeof(msgtype), "%s",
            ct->type);

    if(extension && !digest)
        snprintf(sysid, sizeof(sysid), "%u", extension);
    else
        String::set(sysid, sizeof(sysid), identity);

    uri::publish(requesting, address, sysid, sizeof(address));
    if(extension && !display[0])
        snprintf(fromhdr, sizeof(fromhdr),
            "\"%u\" <%s;user=phone>", extension, address);
    else if(display[0])
        snprintf(fromhdr, sizeof(fromhdr),
            "\"%s\" <%s>", display, address);
    else
        snprintf(fromhdr, sizeof(fromhdr),
            "<%s>", address);

    shell::debug(3, "sending message from %s to %s\n", sysid, target);
    osip_content_length_to_str(sevent->request->content_length, &msglen);
    if(!msglen) {
        digests::release(hash);
        send_reply(SIP_BAD_REQUEST);
        return;
    }
    send_reply(messages::deliver(target, sysid, fromhdr, body->body, atoi(msglen), msgtype, digest));
    digests::release(hash);
    osip_free(msglen);
}

void thread::invite(void)
{
    const char *target = dialing;
    osip_body_t *body = NULL;
    stack::call *call = session->parent;
    unsigned toext = 0;
    osip_header_t *msgheader = NULL;
    char fromext[32];
    cdr *cdrnode = NULL;
    const char *domain = registry::getDomain();

    uri::serviceid(requesting, call->request, sizeof(call->request));

    if(!domain)
        domain = requesting;

    if(!access)
        getsource();

    if(String::equal(network, "decline")) {
        send_reply(SIP_DECLINE);
        call->failed(this, session);
        return;
    }

    if(String::equal(network, "reject")) {
        send_reply(SIP_SERVICE_UNAVAILABLE);
        call->failed(this, session);
        return;
    }

    if(access && access->offline()) {
        send_reply(SIP_TEMPORARILY_UNAVAILABLE);
        call->failed(this, session);
    }

    if(extension)
        snprintf(fromext, sizeof(fromext), "%u", extension);

    msgheader = NULL;
    osip_message_header_get_byname(sevent->request, SESSION_EXPIRES, 0, &msgheader);
    if(msgheader && msgheader->hvalue && msgheader->hvalue[0]) {
        time(&call->expires);
        call->expires += atol(msgheader->hvalue);
    }

    msgheader = NULL;
    osip_message_get_subject(sevent->request, 0, &msgheader);
    if(msgheader && msgheader->hvalue && msgheader->hvalue[0])
        string::set(call->subject, sizeof(call->subject), msgheader->hvalue);
    else
        string::set(call->subject, sizeof(call->subject), "inviting call");

    msgheader = NULL;
    osip_message_get_expires(sevent->request, 0, &msgheader);
    if(msgheader && msgheader->hvalue && atol(msgheader->hvalue))
        header_expires = atol(msgheader->hvalue);
    else
        header_expires = 120;

    osip_message_get_body(sevent->request, 0, &body);
    if(body && body->body)
        String::set(session->sdp, sizeof(session->sdp), body->body);

    if(dialed.keys) {
        target = service::getValue(dialed.keys, "extension");
        if(target)
            toext = atoi(target);
        target = service::getValue(dialed.keys, "id");
    }
    else if(reginfo) {
        target = reginfo->userid;
        toext = reginfo->ext;
    }

    time(&call->starting);
    cdrnode = cdr::get();
    cdrnode->type = cdr::START;
    cdrnode->starting = call->starting;
    cdrnode->sequence = session->sequence;
    cdrnode->cid = session->cid;
    String::set(cdrnode->uuid, sizeof(cdrnode->uuid), session->uuid);
    String::set(cdrnode->network, sizeof(cdrnode->network), network);

    call->type = destination;
    switch(destination) {
    case LOCAL:
        if(extension)
            snprintf(session->sysident, sizeof(session->sysident), "%u", extension);
        else
            String::set(session->sysident, sizeof(session->sysident), identity);
        if(display[0])
            String::set(session->display, sizeof(session->display), display);
        else
            String::set(session->display, sizeof(session->display), session->sysident);

        String::set(call->dialed, sizeof(call->dialed), dialing);
        String::set(cdrnode->ident, sizeof(cdrnode->ident), session->sysident);
        String::set(cdrnode->dialed, sizeof(cdrnode->dialed), call->dialed);
        String::set(cdrnode->display, sizeof(cdrnode->display), session->display);
        snprintf(session->identity, sizeof(session->identity), "%s:%s@%s",
            stack::sip.getScheme(), session->sysident, domain);

        if(toext) {
            call->phone = true;
            snprintf(call->dialed, sizeof(call->dialed), "%u", toext);
        }
        else
            String::set(call->dialed, sizeof(call->dialed), target);

        if(reginfo && !strcmp(reginfo->userid, identity)) {
            shell::debug(1, "calling self %08x:%u, id=%s\n",
                session->sequence, session->cid, getIdent());

            String::set(call->subject, sizeof(call->subject), "calling self");
            call->busy(this);
            cdr::post(cdrnode);
            return;
        }

        if(extension && !display[0])
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s;user=phone>", session->sysident, session->identity);
        else if(display[0])
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s>", session->display, session->identity);
        else
            snprintf(session->from, sizeof(session->from),
                "<%s>", session->identity);

        session->closed = false;
        session->reg = registry::invite(identity, stats::INCOMING);
        shell::debug(1, "local call %08x:%u for %s from %s\n",
            session->sequence, session->cid, call->dialed, session->sysident);
        break;
    case PUBLIC:
        String::set(call->dialed, sizeof(call->dialed), target);
        snprintf(session->identity, sizeof(session->identity), "%s:%s@%s:%s",
            from->url->scheme, from->url->username, from->url->host, from->url->port);
        snprintf(session->sysident, sizeof(session->sysident), "%s@%s", from->url->username, from->url->host);
        if(from->displayname) {
            String::set(session->display, sizeof(session->display), from->displayname);
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s>", from->displayname, session->identity);
        }
        else {
            String::set(session->display, sizeof(session->display), from->url->username);
            snprintf(session->from, sizeof(session->from),
                "<%s>", session->identity);
        }
        shell::debug(1, "incoming call %08x:%u for %s from %s\n",
            session->sequence, session->cid, call->dialed, session->sysident);

        String::set(cdrnode->ident, sizeof(cdrnode->ident), session->sysident);
        String::set(cdrnode->dialed, sizeof(cdrnode->dialed), call->dialed);
        String::set(cdrnode->display, sizeof(cdrnode->display), session->display);
        session->closed = false;
        registry::incUse(NULL, stats::INCOMING);    // external...
        break;
    case REDIRECTED:
    case EXTERNAL:
        if(extension)
            snprintf(session->sysident, sizeof(session->sysident), "%u", extension);
        else
            String::set(session->sysident, sizeof(session->sysident), identity);
        session->reg = registry::invite(identity, stats::INCOMING);
        if(display[0])
            String::set(session->display, sizeof(session->display), display);
        else
            String::set(session->display, sizeof(session->display), identity);

        if(registry::getDomain() || destination != EXTERNAL)
            snprintf(session->identity, sizeof(session->identity), "%s:%s@%s",
                stack::sip.getScheme(), session->sysident, domain);
        else {
            gethostname(buftemp, sizeof(buftemp));
            snprintf(session->identity, sizeof(session->identity), "%s:%s@%s",
                stack::sip.getScheme(), session->sysident, buftemp);
        }

        if(destination == EXTERNAL)
            uri::identity(request_address.getAddr(), call->dialed, uri->username, sizeof(call->dialed));
        else
            String::set(call->dialed, sizeof(call->dialed), dialing);

        if(extension && !display[0])
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s;user=phone>", session->sysident, session->identity);
        else if(display[0])
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s>", display, session->identity);
        else
            snprintf(session->from, sizeof(session->from),
                "<%s>", session->identity);

        shell::debug(1, "outgoing call %08x:%u from %s to %s",
            session->sequence, session->cid, getIdent(), requesting);

        String::set(cdrnode->ident, sizeof(cdrnode->ident), session->sysident);
        String::set(cdrnode->dialed, sizeof(cdrnode->dialed), call->dialed);
        String::set(cdrnode->display, sizeof(cdrnode->display), session->display);
        if(destination == REDIRECTED)
            stack::inviteRemote(session, requesting, server::getValue(authorized.keys, "digest"));
        else
            stack::inviteRemote(session, requesting);

        session->closed = false;
        goto exit;
    case ROUTED:
        call->phone = true;

        if(extension)
            snprintf(session->sysident, sizeof(session->sysident), "%u", extension);
        else
            String::set(session->sysident, sizeof(session->sysident), identity);
        if(display[0])
            String::set(session->display, sizeof(session->display), display);
        else
            String::set(session->display, sizeof(session->display), session->sysident);

        snprintf(session->identity, sizeof(session->identity), "%s:%s@%s",
            stack::sip.getScheme(), session->sysident, domain);

        if(extension)
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s;user=phone>", session->display, session->identity);
        else
            snprintf(session->from, sizeof(session->from),
                "\"%s\" <%s>", session->display, session->identity);

        String::set(call->dialed, sizeof(call->dialed), dialing);

        String::set(cdrnode->ident, sizeof(cdrnode->ident), session->sysident);
        String::set(cdrnode->dialed, sizeof(cdrnode->dialed), call->dialed);
        String::set(cdrnode->display, sizeof(cdrnode->display), session->display);
        session->closed = false;
        session->reg = registry::invite(identity, stats::INCOMING);
        shell::debug(1, "dialed call %08x:%u for %s from %s, dialing=%s\n",
            session->sequence, session->cid, target, getIdent(), dialing);
        break;
    default:
        String::set(cdrnode->ident, sizeof(cdrnode->ident), "unknown");
        String::set(cdrnode->dialed, sizeof(cdrnode->dialed), dialing);
        String::set(cdrnode->display, sizeof(cdrnode->display), "");
        session->closed = true;
        break;
    }

    call->map->sequence = session->sequence;
    call->map->cid = session->cid;
    String::set(call->map->source, sizeof(call->map->source), session->sysident);
    String::set(call->map->display, sizeof(call->map->display), session->display);
    if(reginfo) {
        // get rid of config ref if we are calling registry target
        server::release(dialed);

        String::set(call->forward, MAX_USERID_SIZE, reginfo->userid);
        call->forwarding = "na";
        stack::inviteLocal(session, reginfo, destination);
    }

    if(dialed.keys) {
        // PROCESS DIALED HERE IF EXISTS...
    }

exit:
    if(cdrnode)
        cdr::post(cdrnode);

    if(!call->invited && !stack::forward(call)) {
        call->busy(this);
        return;
    }

    call->trying(this);
    shell::debug(2, "call proceeding %08x:%u\n", session->sequence, session->cid);
    return;

// noproxy:
//  send_reply(SIP_SERVICE_UNAVAILABLE);
//  call->failed(this, session);
}

void thread::identify(void)
{
    registry::mapped *rr = NULL;

    if(!stack::sip.trusted || !getsource() || !access)
        return;

    if(!String::ifind(stack::sip.trusted, access->getName(), ",; \t\n"))
        return;

    // trust also only if no intermediary proxies
    if(via_hops == 1)
        rr = registry::address(via_address.getAddr());
    if(!rr)
        return;

    String::set(display, sizeof(display), rr->display);
    extension = rr->ext;
    String::set(identity, sizeof(identity), rr->userid);
    server::getProvision(identity, authorized);
    registry::detach(rr);
}

const char *thread::getIdent(void)
{
    if(!extension)
        return identity;

    if(registry::isExtension(identity) && (unsigned)atoi(identity) == extension)
        return identity;

    if(!identbuf[0])
        snprintf(identbuf, sizeof(identbuf), "%s(%u)", identity, extension);

    return identbuf;
}

bool thread::unauthenticated(void)
{
    registry::mapped *rr = NULL;

    if(!stack::sip.trusted || !getsource() || !access)
        goto untrusted;

    if(!String::ifind(stack::sip.trusted, access->getName(), ",; \t\n"))
        goto untrusted;

    rr = registry::address(via_address.getAddr());
    if(!rr)
        goto untrusted;

    extension = rr->ext;
    String::set(display, sizeof(display), rr->display);
    String::set(identity, sizeof(identity), rr->userid);
    server::getProvision(identity, authorized);
    registry::detach(rr);
    if(authorized.keys)
        return true;

untrusted:
    if(via_host)
        shell::debug(2, "challenge required for %s:%u", via_host, via_port);
    else
        shell::debug(2, "%s", "challenge request required");
    challenge();
    return false;
}

bool thread::authorize(void)
{
    int error = SIP_UNDECIPHERABLE;
    const char *scheme = "sip";
    const char *cp;
    time_t now;
    unsigned level;
    profile_t *pro;
    const char *target = dialing;
    char dbuf[MAX_USERID_SIZE];
    registry::pattern *pp;
    unsigned to_port = stack::sip_port, local_port = stack::sip_port;
    const char *sep1 = "", *sep2 = "";
    const char *refer = NULL;
    const char *uri_host;
    struct sockaddr_internet iface;
    osip_header_t *msgheader = NULL;
    bool anon = false;
    UserCache *usercache = NULL;

    if(!sevent->request || !sevent->request->to || !sevent->request->from || !sevent->request->req_uri)
        goto invalid;

    from_port = 5060;
    from = sevent->request->from;
    uri = sevent->request->req_uri;
    to = sevent->request->to;
    uri_host = uri->host;

    osip_message_header_get_byname(sevent->request, P_SIPWITCH_NODE, 0, &msgheader);
    if(msgheader && msgheader->hvalue)
        if(!stricmp(msgheader->hvalue, "no") || !strnicmp(msgheader->hvalue, "anon", 4))
            anon = true;

    error = SIP_ADDRESS_INCOMPLETE;

    if(stack::sip_tlsmode)
        scheme = "sips";

    if(!uri_host && registry::getDomain())
        uri_host = (char *)registry::getDomain();

    if(!from->url->host || !uri_host)
        goto invalid;

    if(!from->url->username || !uri->username)
        goto invalid;

    if(!from->url->scheme || !uri->scheme)
        goto invalid;

    error = SIP_UNSUPPORTED_URI_SCHEME;
    if(stricmp(from->url->scheme, scheme) || stricmp(uri->scheme, scheme))
        goto invalid;

    if(strchr(uri_host, ':') != NULL && uri_host[0] != '[') {
        sep1 = "[";
        sep2 = "]";
    }

    if(uri->username && uri->username[0]) {
        if(uri->port && uri->port[0])
            snprintf(requesting, sizeof(requesting), "%s:%s@%s%s%s:%s",
                uri->scheme, uri->username, sep1, uri_host, sep2, uri->port);
        else
            snprintf(requesting, sizeof(requesting), "%s:%s@%s%s%s",
                uri->scheme, uri->username, sep1, uri_host, sep2);
    }
    else {
        if(uri->port && uri->port[0])
            snprintf(requesting, sizeof(requesting), "%s:%s%s%s:%s",
                uri->scheme, sep1, uri_host, sep2, uri->port);
        else
            snprintf(requesting, sizeof(requesting), "%s:%s%s%s",
                uri->scheme, sep1, uri_host, sep2);
    }

    if(uri->port && uri->port[0])
        local_port = atoi(uri->port);
    if(from->url->port)
        from_port = atoi(from->url->port);
    if(to->url->port && to->url->port[0])
        to_port = atoi(to->url->port);
    if(!local_port)
        local_port = 5060;
    if(!from_port)
        from_port = 5060;
    if(!to_port)
        to_port = 5060;

/*  shell::debug(3, "request from=%s:%s@%s:%d, uri=%s:%s@%s:%d, to=%s:%s@%s:%d\n",
        from->url->scheme, from->url->username, from->url->host, from_port,
        uri->scheme, uri->username, uri_host, local_port,
        to->url->scheme, to->url->username, to->url->host, to_port);
*/

    // if marked as a remote call, we can skip local tests entirely
    if(anon)
        goto remote;

    // bypass request address processing if local domain call....
    memset(&iface, 0, sizeof(iface));

    if(String::equal(registry::getRealm(), uri_host))
        goto local;

    if(String::equal("localdomain", uri_host))
        goto local;

    if(String::ifind(stack::sip.localnames, uri_host, " ,;:\t\n"))
        goto local;

    request_address.set(uri_host, local_port);

    if(request_address.getAddr() == NULL) {
        shell::log(shell::ERR, "unresolvable request: %s", uri_host);
        error = SIP_ADDRESS_INCOMPLETE;
        goto invalid;
    }

    stack::getInterface((struct sockaddr *)&iface, request_address.getAddr());

    if(local_port != stack::sip_port)
        goto remote;

    if(Socket::equalhost((struct sockaddr *)&iface, request_address.getAddr()))
        goto local;

    goto remote;

local:
    shell::debug(2, "authorizing local; target=%s\n", uri->username);
    target = uri->username;
    destination = LOCAL;
    String::set(dialing, sizeof(dialing), target);

rewrite:
    shell::debug(3, "rewrite process; target=%s, dialing=%s\n", target, dialing);
    error = SIP_NOT_FOUND;
    if(!target || !*target || strlen(target) >= MAX_USERID_SIZE)
        goto invalid;

    // handle anon@here and system@here identities...

    if(!stricmp(target, stack::sip.anon))
        goto invalid;

    if(!stricmp(target, stack::sip.system)) {
        error = SIP_FORBIDDEN;
        goto invalid;
    }

    reginfo = registry::dialing(target);
    server::getDialing(target, dialed);

    shell::debug(4, "rewrite process; registry=%p, dialed=%p\n", (void *)reginfo, (void *)dialed.keys);

    if(!reginfo && !dialed.keys)
        goto routing;

    // reject nodes with defined errors
    if(dialed.keys && !stricmp(dialed.keys->getId(), "reject")) {
        cp = service::getValue(dialed.keys, "error");
        if(cp)
            error = atoi(cp);
        goto invalid;
    }

    if(!reginfo && dialed.keys) {
        if(!stricmp(dialed.keys->getId(), "group"))
            return authenticate();
        if(!stricmp(dialed.keys->getId(), "refer"))
            return authenticate();
        if(!stricmp(dialed.keys->getId(), "test")) {
            if(session && authenticate()) {
                session->reg = registry::invite(identity, stats::INCOMING);
                cp = service::getValue(dialed.keys, "error");
                if(cp) {
                    error = atoi(cp);
                    goto invalid;
                }
                return true;
            }
            return false;
        }
        if(!stricmp(dialed.keys->getId(), "queue"))
            goto anonymous;
        if(!stricmp(dialed.keys->getId(), "user") || !stricmp(dialed.keys->getId(), "admin")) {
            if(MSG_IS_MESSAGE(sevent->request))
                goto trying;
            shell::log(shell::NOTIFY, "unregistered destination %s", target);
        }
        else
            shell::log(shell::ERR, "invalid destination %s, type=%s\n", target, dialed.keys->getId());
        error = SIP_GONE;
        goto invalid;
    }

    if(reginfo && reginfo->type == MappedRegistry::TEMPORARY) {
        if(MSG_IS_MESSAGE(sevent->request))
            goto trying;
        error = SIP_GONE;
        goto invalid;
    }

    time(&now);

    if(reginfo && reginfo->expires && reginfo->expires < now) {
        if(!MSG_IS_MESSAGE(sevent->request)) {
            error = SIP_GONE;
            goto invalid;
        }
    }
    else if(reginfo && !dialed.keys) {
        error = SIP_NOT_FOUND;
        goto invalid;
    }

trying:
    if(MSG_IS_PUBLISH(sevent->request))
        return authenticate();

    // extension references always require authentication
    if(registry::isExtension(target)) {
        if(!authenticate())
            return false;
        if(!reginfo && !MSG_IS_MESSAGE(sevent->request))
            goto invalid;
        return true;
    }

    // see if destination allows anonymous remote (public) callers

    if(reginfo && reginfo->isFeature(USER_PROFILE_INCOMING) && from->url->host) {

        // now we make sure the originating call does not "claim" to be
        // associated with us.  If it has any of our our names, then we have
        // the inbound caller authenticate like any local-to-local call

        if(String::equal(registry::getRealm(), from->url->host))
            return authenticate();

        if(String::equal("localdomain", from->url->host))
            return authenticate();

        if(String::ifind(stack::sip.localnames, from->url->host, " ,;:\t\n"))
            return authenticate();

        // It "seems" external, user allows incoming, handle as public
        goto anonymous;
    }

    return authenticate();

routing:
    // cannot re-route extension #s...
    if(registry::isExtension(target))
        goto invalid;

    destination = ROUTED;
    if(!authenticate() || !authorized.keys)
        return false;

    if(!stricmp(authorized.keys->getId(), "user")) {
        cp = service::getValue(authorized.keys, "profile");
        if(!cp)
            cp = "*";
        pro = server::getProfile(cp);
        level = pro->level;
    }
    else
        level = registry::getRoutes();
    cp = service::getValue(authorized.keys, "trs");
    if(cp)
        level = atoi(cp);

    if(!level)
        goto invalid;

    pp = registry::getRouting(level, target);
    if(!pp)
        goto static_routing;

    reginfo = pp->registry;
    dialing[0] = 0;
    if(pp->prefix[0] == '-') {
        if(!strnicmp(target, pp->prefix + 1, strlen(pp->prefix) - 1))
            target += strlen(pp->prefix) - 1;
    } else if(pp->prefix[0]) {
        if(strnicmp(target, pp->prefix, strlen(pp->prefix)))
            String::set(dialing, sizeof(dialing), pp->prefix);
    }
    String::add(dialing, sizeof(dialing), target);
    if(pp->suffix[0] == '-') {
        if(strlen(dialing) > strlen(pp->suffix) && !stricmp(dialing + strlen(dialing) - strlen(pp->suffix) + 1, pp->suffix + 1))
            dialing[strlen(dialing) - strlen(pp->suffix) + 1] = 0;
    } else
        String::add(dialing, sizeof(dialing), pp->suffix);
    return true;

static_routing:
    routed = server::getRouting(target);
    if(!routed) {
        registry::mapped *idmap = registry::access(identity);
        refer = server::referLocal(idmap, target, buffer, sizeof(buffer));
        registry::detach(idmap);
        if(refer)
            goto redirect;
    }

    if(!routed)
        usercache = UserCache::find(target);

    if(usercache) {
        stack::sipAddress(&usercache->address, buffer, target, sizeof(buffer));
        refer = buffer;
        UserCache::release(usercache);
        goto redirect;
    }

    if(!routed)
        goto invalid;

    if(!stricmp(routed->getId(), "refuse")) {
        cp = service::getValue(routed, "error");
        if(cp)
            error = atoi(cp);
        goto invalid;
    }

    if(!stricmp(routed->getId(), "redirect") || !stricmp(routed->getId(), "refer")) {
        cp = service::getValue(routed, "server");
        if(!cp)
            cp = service::getValue(routed, "target");
        if(cp && !strchr(cp, '@')) {
            if(String::equal(cp, "sip:", 4) || String::equal(cp, "sips:", 5))
                snprintf(buffer, sizeof(buffer), "%s@%s", target, cp);
            else
                snprintf(buffer, sizeof(buffer), "sip:%s@%s", target, cp);
            refer = buffer;
            goto redirect;
        }
        if(!cp)
            goto invalid;
        if(String::equal(cp, "sip:", 4) || String::equal(cp, "sips:"))
            snprintf(buffer, sizeof(buffer), "%s", cp);
        else
            snprintf(buffer, sizeof(buffer), "sip:%s", cp);
        refer = buffer;
        goto redirect;
    }

    // adjust dialing & processing based on routing properties

    cp = service::getValue(routed, "replace");
    if(cp)
        String::set(dialing, sizeof(dialing), cp);
    else {
        dialing[0] = 0;
        cp = service::getValue(routed, "prefix");
        if(cp && *cp == '-') {
            --cp;
            if(!strnicmp(target, cp, strlen(cp)))
                target += strlen(cp);
        } else if(cp) {
            if(strnicmp(target, cp, strlen(cp)))
                String::set(dialing, sizeof(dialing), cp);
        }
        String::add(dialing, sizeof(dialing), target);
        cp = service::getValue(routed, "suffix");
        if(cp && *cp == '-') {
            --cp;
            if(strlen(dialing) >= strlen(cp) && !stricmp(dialing + strlen(dialing) - strlen(cp), cp))
                dialing[strlen(dialing) - strlen(cp)] = 0;
        } else if(cp)
            String::add(dialing, sizeof(dialing), cp);
    }
    if(!stricmp(routed->getId(), "rewrite")) {
        if(strchr(dialing, '@')) {
            if(String::equal(dialing, "sips:", 5) || String::equal("sip:", dialing, 4))
                snprintf(dbuf, sizeof(dbuf), "%s", dialing);
            else
                snprintf(dbuf, sizeof(dbuf), "sip:%s", dialing);
            refer = dbuf;
            goto redirect;
        }
        String::set(dbuf, sizeof(dbuf), dialing);
        target = dbuf;
        server::release(routed);
        if(reginfo)
            registry::detach(reginfo);
        routed = NULL;
        reginfo = NULL;
        destination = LOCAL;
        goto rewrite;
    }
    goto invalid;

anonymous:
    if(!stack::sip.published) {
        error = SIP_FORBIDDEN;
        goto invalid;
    }

    if(from->url->host == NULL) {
        error = SIP_ADDRESS_INCOMPLETE;
        goto invalid;
    }

    destination = PUBLIC;
    return true;

remote:
    error = SIP_FORBIDDEN;
    destination = EXTERNAL;
    if(!stack::sip.published)
        goto invalid;

    if(!authenticate())
        return false;

    // must be active registration to dial out...
    reginfo = registry::access(identity);
    time(&now);
    if(!reginfo || (reginfo->expires && reginfo->expires < now))
        goto invalid;

    if(!reginfo->isFeature(USER_PROFILE_OUTGOING))
        goto invalid;

    refer = server::referRemote(reginfo, requesting, buffer, sizeof(buffer));
    if(refer)
        goto redirect;

    return true;

invalid:
    if(authorized.keys)
        shell::debug(1, "rejecting invite from %s; error=%d\n", getIdent(), error);
    else if(from->url && from->url->host && from->url->username)
        shell::debug(1, "rejecting invite from %s@%s; error=%d\n", from->url->username, from->url->host, error);
    else
        shell::debug(1, "rejecting unknown invite; error=%d\n", error);

    send_reply(error);
    return false;

redirect:
    destination = REDIRECTED;
    String::set(requesting, sizeof(requesting), refer);
    return true;
}

void thread::send_reply(int error)
{
    assert(error >= 100);

    osip_message_t *reply = NULL;

    eXosip_lock();
    switch(authorizing) {
    case CALL:
        eXosip_call_build_answer(sevent->tid, error, &reply);
        if(reply != NULL) {
            if(stack::sip_protocol == IPPROTO_UDP)
                osip_message_set_require(reply, "100rel");
            stack::siplog(reply);
            eXosip_call_send_answer(sevent->tid, error, reply);
        }
        else
            eXosip_call_send_answer(sevent->tid, SIP_BAD_REQUEST, NULL);
        break;
    case REGISTRAR:
    case MESSAGE:
        eXosip_message_build_answer(sevent->tid, error, &reply);
        if(reply != NULL) {
            if(stack::sip_protocol == IPPROTO_UDP)
                osip_message_set_require(reply, "100rel");
            stack::siplog(reply);
            eXosip_message_send_answer(sevent->tid, error, reply);
        }
        else
            eXosip_call_send_answer(sevent->tid, SIP_BAD_REQUEST, NULL);
        break;
    default:
        break;
    }
    eXosip_unlock();
}

bool thread::authenticate(stack::session *s)
{
    assert(s != NULL);

    const char *userid = NULL, *secret = NULL;
    registry::mapped *rr = s->reg;
    service::keynode *auth;

    // if not managed destination, try plugins using realm only...
    if(!rr)
        return server::authenticate(-1, sip_realm);

    // if has externally managed registration, call plugins to authenticate...
    if(rr->rid != -1)
        return server::authenticate(rr->rid, sip_realm);

    server::getProvision(rr->userid, authorized);
    if(!authorized.keys)
        return false;

    auth = authorized.keys->leaf("authorize");
    if(auth) {
        userid = server::getValue(auth, "userid");
        secret = server::getValue(auth, "secret");
    }

    switch(rr->type) {
    // Services use special magic to authenticate using uuid generated
    // userid that service originally registered with as "contact".  This
    // means that a single secret is needed for authenticating both ways
    // and all references to the service is instance unique.
    case MappedRegistry::SERVICE:
        // sipwitch aware app servers can generate uuid's and use same secret
        if(!userid)
            userid = rr->remote;
        if(!secret)
            secret = service::getValue(authorized.keys, "secret");
        break;
    default:
        return false;
    }

    if(!sip_realm || !*sip_realm || !userid || !secret || !*userid)
        return false;

    eXosip_lock();
    eXosip_add_authentication_info(userid, userid, secret, NULL, sip_realm);
    eXosip_automatic_action();
    eXosip_unlock();
    return true;
}


bool thread::authenticate(void)
{
    osip_authorization_t *auth = NULL;
    service::keynode *node = NULL, *leaf;
    stringbuf<64> digest;
    int error = SIP_PROXY_AUTHENTICATION_REQUIRED;
    const char *cp;
    const char *hash = NULL;
    digest_t calc = registry::getDigest();

    if(authorized.keys != NULL)
        return true;

    display[0] = 0;
    extension = 0;
    auth = NULL;

    if(!sevent->request || osip_message_get_authorization(sevent->request, 0, &auth) != 0 || !auth || !auth->username || !auth->response)
        return unauthenticated();

    remove_quotes(auth->username);
    remove_quotes(auth->uri);
    remove_quotes(auth->nonce);
    remove_quotes(auth->response);

    // if subnet restrictions and authenticated from outside, reject

    if(stack::sip.restricted) {
        if(!getsource() || !access || !String::ifind(stack::sip.restricted, access->getName(), ",; \t\n")) {
            if(via_host)
                shell::log(shell::NOTIFY, "rejecting restricted %s from %s:%u", auth->username, via_host, via_port);
            else
                shell::log(shell::NOTIFY, "rejecting restricted %s", auth->username);
            error = SIP_FORBIDDEN;
            goto failed;
        }
    }

    server::getProvision(auth->username, authorized);
    node = authorized.keys;
    if(!node) {
        shell::log(shell::NOTIFY, "rejecting unknown %s", auth->username);
        error = SIP_NOT_FOUND;
        goto failed;
    }

    // reject can be used as a placeholder when manually editing
    // provisioning records for a user that is being disabled but which
    // one doesn't want to loose configuration info

    if(!stricmp(node->getId(), "reject")) {
        shell::log(shell::NOTIFY, "rejecting user %s", auth->username);
        error = SIP_FORBIDDEN;
        cp = service::getValue(node, "error");
        if(cp)
            error = atoi(cp);
        goto failed;
    }

    leaf = node->leaf("extension");
    if(leaf && leaf->getPointer())
        extension = atoi(leaf->getPointer());

    leaf = node->leaf("display");
    if(leaf && leaf->getPointer())
        String::set(display, sizeof(display), leaf->getPointer());

    // -digest-: fetch from leaf node...
    hash = digests::get(auth->username);
    leaf = node->leaf("digest");
    if(!hash && (!leaf || !leaf->getPointer())) {
        shell::log(shell::NOTIFY, "rejecting unsupported %s", auth->username);
        error = SIP_FORBIDDEN;
        goto failed;
    }

    // compute service request digest string
    snprintf(buffer, sizeof(buffer), "%s:%s", sevent->request->sip_method, auth->uri);

    calc.puts(buffer);
    digest = *calc;

    // apply user digest pointer with nonce, and service digest string
    if(hash)
        snprintf(buffer, sizeof(buffer), "%s:%s:%s", hash, auth->nonce, *digest);
    else
        snprintf(buffer, sizeof(buffer), "%s:%s:%s", leaf->getPointer(), auth->nonce, *digest);
    digests::release(hash);

    calc.reset();
    calc.puts(buffer);
    digest = *calc;

    // see if digests match
    if(stricmp(*digest, auth->response)) {
        shell::log(shell::NOTIFY, "rejecting unauthorized %s", auth->username);
        goto failed;
    }

    String::set(identity, sizeof(identity), auth->username);
    return true;

failed:
    server::release(authorized);
    send_reply(error);
    return false;
}

void thread::challenge(void)
{
    osip_message_t *reply = NULL;
    char nonce[32];
    time_t now;

    time(&now);
    snprintf(nonce, sizeof(nonce), "%08lx", (long)now);
    snprintf(buffer, sizeof(buffer),
        "Digest realm=\"%s\", nonce=\"%s\", algorithm=%s",
                registry::getRealm(), nonce, registry::getDigest());

    eXosip_lock();
    switch(authorizing) {
    case REGISTRAR:
        eXosip_message_build_answer(sevent->tid, SIP_UNAUTHORIZED, &reply);
        if(reply != NULL) {
            osip_message_set_header(reply, WWW_AUTHENTICATE, buffer);
            osip_message_set_header(reply, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
            osip_message_set_header(reply, ALLOW_EVENTS , "talk, hold, refer");
            stack::siplog(reply);
            eXosip_message_send_answer(sevent->tid, SIP_UNAUTHORIZED, reply);
        }
        break;
    case MESSAGE:
        eXosip_message_build_answer(sevent->tid, SIP_UNAUTHORIZED, &reply);
        if(reply != NULL) {
            osip_message_set_header(reply, WWW_AUTHENTICATE, buffer);
            osip_message_set_header(reply, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
            osip_message_set_header(reply, ALLOW_EVENTS , "talk, hold, refer");
            stack::siplog(reply);
            eXosip_message_send_answer(sevent->tid, SIP_UNAUTHORIZED, reply);
        }
        break;
    case CALL:
        eXosip_call_build_answer(sevent->tid, SIP_UNAUTHORIZED, &reply);
        if(reply != NULL) {
            osip_message_set_header(reply, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
            osip_message_set_header(reply, ALLOW_EVENTS, "talk, hold, refer");
            osip_message_set_header(reply, WWW_AUTHENTICATE, buffer);
            stack::siplog(reply);
            eXosip_call_send_answer(sevent->tid, SIP_UNAUTHORIZED, reply);
        }
        break;
    case NONE:
        break;
    }
    eXosip_unlock();
}

bool thread::getsource(void)
{
    osip_generic_param_t *param;
    int vpos = 0;

    if(is(via_address))
        return true;

    via_host = NULL;
    via_port = 5060;
    via_header = NULL;
    while(sevent->request && osip_list_eol(OSIP2_LIST_PTR sevent->request->vias, vpos) == 0) {
        via_header = (osip_via_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->vias, vpos++);
        ++via_hops;
    }

    if(!via_header)
        return false;

    via_host = via_header->host;
    if(via_header->port)
        via_port = atoi(via_header->port);
    if(!via_port)
        via_port = 5060;

    osip_via_param_get_byname(via_header, (char *)"rport", &param);
    if(param != NULL && param->gvalue != NULL)
        via_port = atoi(param->gvalue);

    osip_via_param_get_byname(via_header, (char *)"received", &param);
    if(param != NULL && param->gvalue != NULL)
        via_host = param->gvalue;

    via_address.set(via_host, via_port);
    access = server::getPolicy(via_address.getAddr());
    if(access) {
        peering = access->iface;
        String::set(network, sizeof(network), access->getId());
    }
    else {
        service::published(&peering);
        String::set(network, sizeof(network), "*");
    }
    if(session) {
        session->peering = peering;
        String::set(session->network, sizeof(session->network), network);
    }
    return true;
}

void thread::validate(void)
{
    osip_authorization_t *auth = NULL;
    service::keynode *node = NULL, *leaf;
    stringbuf<64> digest;
    int error = SIP_PROXY_AUTHENTICATION_REQUIRED;
    const char *cp;
    char temp[64];
    osip_message_t *reply = NULL;
    service::usernode user;
    const char *hash = NULL;
    digest_t calc = registry::getDigest();

    if(!sevent->request || osip_message_get_authorization(sevent->request, 0, &auth) != 0 || !auth || !auth->username || !auth->response) {
        challenge();
        return;
    }

    remove_quotes(auth->username);
    remove_quotes(auth->uri);
    remove_quotes(auth->nonce);
    remove_quotes(auth->response);

    server::getProvision(auth->username, user);
    node = user.keys;
    if(!node) {
        error = SIP_NOT_FOUND;
        goto reply;
    }

    // reject can be used as a placeholder when manually editing
    // provisioning records for a user that is being disabled but which
    // one doesn't want to loose configuration info

    if(!stricmp(node->getId(), "reject")) {
        error = SIP_FORBIDDEN;
        cp = service::getValue(node, "error");
        if(cp)
            error = atoi(cp);
        goto reply;
    }

    // -digest-: get a leaf pointer
    hash = digests::get(auth->username);
    leaf = node->leaf("digest");
    if(!hash && (!leaf || !leaf->getPointer())) {
        error = SIP_FORBIDDEN;
        goto reply;
    }

    // compute a method/uri hash
    snprintf(buffer, sizeof(buffer), "%s:%s", sevent->request->sip_method, auth->uri);
    calc.puts(buffer);
    digest = *calc;

    // compute with user digest
    if(hash)
        snprintf(buffer, sizeof(buffer), "%s:%s:%s", hash, auth->nonce, *digest);
    else
        snprintf(buffer, sizeof(buffer), "%s:%s:%s", leaf->getPointer(), auth->nonce, *digest);

    digests::release(hash);

    calc.reset();
    calc.puts(buffer);
    digest = *calc;

    if(!stricmp(*digest, auth->response))
        error = SIP_OK;

reply:
    if(error == SIP_OK)
        shell::debug(2, "validating %s; expires=%lu", auth->username, (long)registry::getExpires());
    else
        shell::debug(2, "rejecting %s; error=%d", auth->username, error);

    server::release(user);
    eXosip_lock();
    eXosip_message_build_answer(sevent->tid, error, &reply);
    if(reply != NULL) {
        if(error == SIP_OK) {
            snprintf(temp, sizeof(temp), ";expires=%lu", (long)registry::getExpires());
            osip_message_set_contact(reply, temp);
            snprintf(temp, sizeof(temp), "%lu", (long)registry::getExpires());
            osip_message_set_expires(reply, temp);
        }
        osip_message_set_header(reply, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
        osip_message_set_header(reply, ALLOW_EVENTS , "talk, hold, refer");
        stack::siplog(reply);
        eXosip_message_send_answer(sevent->tid, error, reply);
    }
    else
        eXosip_message_send_answer(sevent->tid, SIP_BAD_REQUEST, NULL);
    eXosip_unlock();
}

void thread::registration(void)
{
    osip_contact_t *contact = NULL;
    osip_uri_param_t *param = NULL;
    osip_uri_t *reguri = NULL;
    char *port;
    int interval = -1;
    int pos = 0;
    int error = SIP_ADDRESS_INCOMPLETE;
    osip_message_t *reply = NULL;
    struct sockaddr_internet iface;

    while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
        contact = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos++);
        if(contact && contact->url) {
            osip_contact_param_get_byname(contact, (char *)"expires", &param);
            if(param && param->gvalue)
                interval = osip_atoi(param->gvalue);
            break;
        }
    }

    if(registry::getDomain())
        String::set(binding, sizeof(binding), registry::getDomain());
    else if(sevent->request->req_uri->port && !eq(sevent->request->req_uri->port, "5060"))
        snprintf(binding, sizeof(binding), "%s:%s",
            sevent->request->req_uri->host, sevent->request->req_uri->port);
    else
        String::set(binding, sizeof(binding), sevent->request->req_uri->host);

    if(contact && contact->url && contact->url->username && contact->url->username[0]) {
        if(!authenticate())
            return;

        if(!getsource()) {
            shell::log(shell::ERR, "cannot determine origin for registration");
            return;
        }

        reguri = contact->url;
        port = reguri->port;
        if(!port || !port[0])
            port = (char *)"5060";
        snprintf(buffer, sizeof(buffer), "%s:%s@%s:%s",
            reguri->scheme, reguri->username, reguri->host, port);

        // auto-detect registration from ephemerial ports...
        contact_port = atoi(port);
        contact_host = reguri->host;
        if(!Socket::isNumeric(reguri->host) || !String::equal(contact_host, via_host) || contact_port == via_port) {
            // non-ephemeral or source based registration required...
            contact_host = via_host;
            contact_port = via_port;
        }
        contact_address.set(contact_host, contact_port);
    }
    else
    {
        if(stack::sip.restricted) {
            if(!getsource() || !access || !String::ifind(stack::sip.restricted, access->getName(), ",; \t\n")) {
                error = SIP_FORBIDDEN;
                goto reply;
            }
        }

        if(sevent->request->to)
            reguri = sevent->request->to->url;
        if(!uri || !reguri->username || reguri->username[0] == 0) {
            validate();
            return;
        }

        port = reguri->port;
        if(!port || !port[0])
            port = (char *)"5060";
        request_address.set(reguri->host, port);
        if(request_address.getAddr() == NULL)
            goto reply;

        error = SIP_NOT_FOUND;
//      if(!String::ifind(stack::sip.localnames, reguri->host, " ,;:\t\n")) {
            stack::getInterface((struct sockaddr *)&iface, request_address.getAddr());
            if(!Socket::equalhost((struct sockaddr *)&iface, request_address.getAddr()) && atoi(port) == stack::sip_port)
                goto reply;
//      }

        if(registry::exists(reguri->username))
            error = SIP_OK;

reply:
        if(error == SIP_OK)
            shell::debug(3, "querying %s", reguri->username);
        else
            shell::debug(3, "query rejected for %s; error=%d", reguri->username, error);
        eXosip_lock();
        eXosip_message_build_answer(sevent->tid, error, &reply);
        if(reply != NULL) {
            if(error == SIP_OK) {
                snprintf(buftemp, sizeof(buftemp), "<%s:%s@%s>",
                    stack::getScheme(), reguri->username, binding);
                osip_message_set_contact(reply, buftemp);
            }
            osip_message_set_header(reply, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
            osip_message_set_header(reply, ALLOW_EVENTS , "talk, hold, refer");
            stack::siplog(reply);
            eXosip_message_send_answer(sevent->tid, error, reply);
        }
        else
            eXosip_message_send_answer(sevent->tid, SIP_BAD_REQUEST, NULL);
        eXosip_unlock();
        return;
    }

    if(interval < 0)
        interval = header_expires;
    if(interval < 0)
        interval = (int)registry::getExpires();
    if(!interval || !contact) {
        deregister();
        return;
    }
    reregister(buffer, interval);
}

void thread::reregister(const char *contact, time_t interval)
{
    assert(contact != NULL && *contact != 0);
    assert(interval > 0);
    assert(identity != NULL && *identity != 0);

    int answer = SIP_OK;
    osip_message_t *reply = NULL;
    time_t expire;
    unsigned count = 0;
    osip_contact_t *c = NULL;
    int pos = 0;
    bool refresh;

    if(extension && (extension < registry::getPrefix() || extension >= registry::getPrefix() + registry::getRange())) {
        shell::debug(2, "rejecting %s, not in local dialing plan", getIdent());
        answer = SIP_NOT_ACCEPTABLE_HERE;
        interval = 0;
        goto reply;
    }

    reginfo = registry::allocate(identity);
    if(!reginfo) {
        if(!warning_registry) {
            warning_registry = true;
            shell::log(shell::ERR, "registry capacity reached");
        }
        answer = SIP_TEMPORARILY_UNAVAILABLE;
        interval = 0;
        goto reply;
    }
    warning_registry = false;
    time(&expire);
    if(reginfo->expires < expire) {
        reginfo->created = expire;
        getDevice(reginfo);
    }

    expire += interval + 3; // overdraft 3 seconds...

    refresh = reginfo->refresh(contact_address, expire, contact);
    if(!refresh) {
        if(reginfo->type == MappedRegistry::USER)
            count = reginfo->addTarget(contact_address, expire, contact, network, (struct sockaddr *)&peering);
        else
            count = reginfo->setTarget(contact_address, expire, contact, network, (struct sockaddr *)&peering);
    }
    if(refresh)
        shell::debug(2, "refreshing %s for %ld seconds from %s:%u", getIdent(), (long)interval, contact_host, contact_port);
    else if(count) {
        time(&reginfo->created);
        activated = true;
        shell::log(DEBUG1, "registering %s for %ld seconds from %s:%u", getIdent(), (long)interval, contact_host, contact_port);
    }
    else {
        shell::log(shell::ERR, "cannot register %s from %s", getIdent(), buffer);
        answer = SIP_FORBIDDEN;
        goto reply;
    }

    if(reginfo->type != MappedRegistry::SERVICE || reginfo->source.internal.routes)
        goto reply;

    while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
        c = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos++);
        if(c && c->url && c->url->username) {
            reginfo->addContact(c->url->username);
            shell::log(shell::INFO, "registering service %s:%s@%s:%s",
                c->url->scheme, c->url->username, c->url->host, c->url->port);
        }
    }
reply:
    eXosip_lock();
    eXosip_message_build_answer(sevent->tid, answer, &reply);
    if(reply != NULL) {

        if(answer == SIP_OK) {
            if(reginfo->ext) {
                snprintf(buftemp, sizeof(buftemp), "<%s:%d@%s>;expires=%ld",
                    stack::getScheme(), reginfo->ext, binding, (long)interval);
                osip_message_set_contact(reply, buftemp);
            }

            snprintf(buftemp, sizeof(buftemp), "<%s:%s@%s>;expires=%ld",
                stack::getScheme(), reginfo->userid, binding, (long)interval);
            osip_message_set_contact(reply, buftemp);
        }
        osip_message_set_header(reply, ALLOW, "INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, SUBSCRIBE, PRACK, MESSAGE, INFO");
        osip_message_set_header(reply, ALLOW_EVENTS, "talk, hold, refer");
        stack::siplog(reply);
        eXosip_message_send_answer(sevent->tid, answer, reply);
    }
    else
        eXosip_message_send_answer(sevent->tid, SIP_BAD_REQUEST, NULL);
    eXosip_unlock();
    if(reginfo && reginfo->isUser() && answer == SIP_OK)
        messages::update(identity);
}

void thread::deregister()
{
    bool unreg = false;
    registry::mapped *rr = registry::access(identity);
    if(rr) {
        unreg = rr->expire(contact_address);
        registry::detach(rr);
    }
    if(unreg)
        shell::log(DEBUG1, "unregister %s", getIdent());
}

void thread::getDevice(registry::mapped *rr)
{
    assert(rr != NULL);

    linked_pointer<service::keynode> device = server::list("devices");

    while(device) {
        linked_pointer<service::keynode> node = device->getFirst();
        const char *id, *value;
        while(node) {
            id = node->getId();
            value = node->getPointer();
            if(id && value && !stricmp(id, "match")) {
            }
            node.next();
        }
        device.next();
    }
}

void thread::options(void)
{
    osip_message_t *reply = NULL;

    eXosip_lock();
    if(eXosip_options_build_answer(sevent->tid, SIP_OK, &reply) == 0) {
        osip_message_set_header(reply, ACCEPT, "application/sdp, text/plain");
        osip_message_set_header(reply, ALLOW, "INVITE,ACK,CANCEL,OPTIONS,INFO,REFER,MESSAGE,SUBSCRIBE,NOTIFY,REGISTER,PRACK");
        osip_message_set_header(reply, ALLOW_EVENTS, "talk, hold, refer");
        stack::siplog(reply);
        eXosip_options_send_answer(sevent->tid, SIP_OK, reply);
    }
    else
        eXosip_options_send_answer(sevent->tid, SIP_BAD_REQUEST, NULL);
    eXosip_unlock();
}

void thread::shutdown(void)
{
    shutdown_flag = true;
    while(active_count)
        Thread::sleep(50);
    eXosip_quit();
    while(shutdown_count < startup_count)
        Thread::sleep(50);
}

void thread::wait(unsigned count) {
    while(startup_count < count)
        Thread::sleep(50);
}

void thread::expiration(void)
{
    osip_header_t *msgheader = NULL;
    osip_uri_param_t *expires = NULL;
    osip_contact_t *contact;
    int pos = 0;

    assert(sevent->request != NULL);

    header_expires = 0l;
    osip_message_get_expires(sevent->request, 0, &msgheader);
    if(msgheader && msgheader->hvalue)
        header_expires = atol(msgheader->hvalue);
    else while(osip_list_eol(OSIP2_LIST_PTR sevent->request->contacts, pos) == 0) {
        contact = (osip_contact_t*)osip_list_get(OSIP2_LIST_PTR sevent->request->contacts, pos);
        if(osip_contact_param_get_byname(contact, (char *)"expires", &expires) != 0 && expires != NULL) {
            header_expires = atol(expires->gvalue);
            break;
        }
        ++pos;
    }
}

void thread::run(void)
{
    osip_body_t *body;

    instance = ++startup_count;
    shell::log(DEBUG1, "starting event thread %d", instance);

    for(;;) {
        assert(instance > 0);
        assert(reginfo == NULL);
        assert(dialed.keys == NULL);
        assert(routed == NULL);
        assert(authorized.keys == NULL);
        assert(access == NULL);

        display[0] = 0;
        extension = 0;
        identbuf[0] = 0;

        if(!shutdown_flag)
            sevent = eXosip_event_wait(0, stack::sip.timing);

        activated = false;
        accepted = NULL;
        via_host = NULL;
        via_port = 0;
        via_hops = 0;
        via_header = NULL;

        if(shutdown_flag) {
            shell::log(DEBUG1, "stopping event thread %d", instance);
            ++shutdown_count;
            return; // exits thread...
        }

        if(!sevent)
            continue;

        ++active_count;
        shell::debug(2, "sip: event %d; cid=%d, did=%d, instance=%d",
            sevent->type, sevent->cid, sevent->did, instance);

        switch(sevent->type) {
        case EXOSIP_REGISTRATION_FAILURE:
            stack::siplog(sevent->response);
            shell::debug(4, "sip: registration response %d", sevent->response->status_code);
            if(sevent->response && sevent->response->status_code == 401) {
                sip_realm = NULL;
                proxy_auth = (osip_proxy_authenticate_t*)osip_list_get(OSIP2_LIST_PTR sevent->response->proxy_authenticates, 0);
                www_auth = (osip_proxy_authenticate_t*)osip_list_get(OSIP2_LIST_PTR sevent->response->www_authenticates,0);
                if(proxy_auth)
                    sip_realm = osip_proxy_authenticate_get_realm(proxy_auth);
                else if(www_auth)
                    sip_realm = osip_www_authenticate_get_realm(www_auth);
                sip_realm = String::unquote(sip_realm, "\"\"");
                server::authenticate(sevent->rid, sip_realm);
            }
            else
                server::registration(sevent->rid, modules::REG_FAILED);
            break;
        case EXOSIP_REGISTRATION_TERMINATED:
            stack::siplog(sevent->response);
            server::registration(sevent->rid, modules::REG_TERMINATED);
            break;
        case EXOSIP_REGISTRATION_SUCCESS:
        case EXOSIP_REGISTRATION_REFRESHED:
            stack::siplog(sevent->response);
            server::registration(sevent->rid, modules::REG_SUCCESS);
            break;
        case EXOSIP_CALL_PROCEEDING:
            stack::siplog(sevent->response);
            session = stack::access(sevent->cid);
            if(session)
                stack::setDialog(session, sevent->did);
            break;
        case EXOSIP_CALL_ACK:
            stack::siplog(sevent->ack);
            authorizing = CALL;
            if(sevent->cid <= 0)
                break;
            session = stack::access(sevent->cid);
            if(!session)
                break;
            session->parent->confirm(this, session);
            break;
        case EXOSIP_CALL_CANCELLED:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(sevent->cid > 0) {
                session = stack::access(sevent->cid);
                if(stack::getDialog(session) == sevent->did)
                    stack::close(session);
                else
                    break;
            }
            send_reply(SIP_OK);
            break;
        case EXOSIP_CALL_NOANSWER:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(sevent->cid <= 0)
                break;
            session = stack::access(sevent->cid);
            if(!session)
                break;
            stack::close(session);
            break;
        case EXOSIP_CALL_TIMEOUT:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(sevent->cid <= 0)
                break;
            session = stack::access(sevent->cid);
            if(!session)
                break;
            session->parent->failed(this, session);
            break;
        case EXOSIP_CALL_ANSWERED:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(!sevent->response || sevent->cid <= 0)
                break;
            session = stack::access(sevent->cid);
            if(!session)
                break;

            switch(session->state) {
            case stack::session::REINVITE:
            case stack::session::REFER:
                session->parent->relay(this, session);
            default:
                break;
            }
            // copy target sdp into session object...
            body = NULL;
            osip_message_get_body(sevent->response, 0, &body);
            if(body && body->body) {
                if(media::answer(session, body->body) == NULL) {
                    session->parent->failed(this, session);
                    break;
                }
            }
            session->parent->answer(this, session);
            break;
        case EXOSIP_CALL_SERVERFAILURE:
        case EXOSIP_CALL_REQUESTFAILURE:
        case EXOSIP_CALL_GLOBALFAILURE:
        case EXOSIP_CALL_MESSAGE_REQUESTFAILURE:
        case EXOSIP_CALL_MESSAGE_SERVERFAILURE:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(!sevent->response || sevent->cid <= 0)
                break;
            session = stack::access(sevent->cid);
            if(!session)
                break;
            shell::debug(4, "sip: call response %d\n", sevent->response->status_code);
            switch(sevent->response->status_code) {
            case SIP_DECLINE:
            case SIP_MOVED_PERMANENTLY:
            case SIP_REQUEST_TIME_OUT:
            case SIP_SERVER_TIME_OUT:
            case SIP_REQUEST_TERMINATED:
                stack::close(session);
                break;
            case SIP_GONE:
            case SIP_NOT_FOUND:
            case SIP_BUSY_HERE:
            case SIP_BUSY_EVRYWHERE:
            case SIP_TEMPORARILY_UNAVAILABLE:
            case SIP_MOVED_TEMPORARILY:
            case SIP_SERVICE_UNAVAILABLE:
                session->parent->busy(this, session);
                break;
            case SIP_UNAUTHORIZED:
            case SIP_PROXY_AUTHENTICATION_REQUIRED:
                sip_realm = NULL;
                proxy_auth = (osip_proxy_authenticate_t*)osip_list_get(OSIP2_LIST_PTR sevent->response->proxy_authenticates, 0);
                www_auth = (osip_proxy_authenticate_t*)osip_list_get(OSIP2_LIST_PTR sevent->response->www_authenticates,0);
                if(proxy_auth)
                    sip_realm = osip_proxy_authenticate_get_realm(proxy_auth);
                else if(www_auth)
                    sip_realm = osip_www_authenticate_get_realm(www_auth);
                sip_realm = String::unquote(sip_realm, "\"\"");
                if(authenticate(session))
                    break;
                // otherwise failed session if cannot authenticate...
            default:
                session->parent->failed(this, session);
                break;
            }
            break;
        case EXOSIP_CALL_CLOSED:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(sevent->cid > 0) {
                session = stack::access(sevent->cid);
                if(session)
                    stack::close(session);
                else
                    break;
            }
            break;
        case EXOSIP_CALL_RELEASED:
            stack::siplog(sevent->response);
            authorizing = NONE;
            if(sevent->cid > 0) {
                authorizing = CALL;
                session = stack::access(sevent->cid);
                if(session)
                    stack::clear(session);
            }
            break;
        case EXOSIP_CALL_RINGING:
            stack::siplog(sevent->response);
            authorizing = NONE;
            if(sevent->cid > 0) {
                authorizing = CALL;
                session = stack::access(sevent->cid);
                if(session && session->parent) {
                    stack::setDialog(session, sevent->did);
                    session->parent->ring(this, session);
                }
            }
            break;

        case EXOSIP_CALL_REINVITE:
            stack::siplog(sevent->request);
            authorizing = CALL;
            if(!sevent->request)
                break;
            if(sevent->cid < 1 && sevent->did < 1) {
                send_reply(SIP_NOT_FOUND);
                break;
            }
            expiration();
            session = stack::access(sevent->cid);
            if(!session) {
                send_reply(SIP_NOT_FOUND);
                break;
            };

            session->parent->reinvite(this, session);
            break;
        case EXOSIP_CALL_INVITE:
            stack::siplog(sevent->request);
            authorizing = CALL;
            if(!sevent->request)
                break;
            if(sevent->cid < 1)
                break;
            expiration();
            session = stack::create(sevent->cid, sevent->did, sevent->tid);
            if(!session) {
                send_reply(SIP_TEMPORARILY_UNAVAILABLE);
                break;
            }
            session->closed = true;
            if(authorize())
                invite();
            break;
        case EXOSIP_CALL_MESSAGE_ANSWERED:
            stack::siplog(sevent->response);
            authorizing = CALL;
            if(!sevent->response)
                break;
            if(sevent->cid < 1)
                break;
            session = stack::access(sevent->cid);
            if(session)
                session->parent->relay(this, session);
            break;
        case EXOSIP_MESSAGE_ANSWERED:
            stack::siplog(sevent->response);
            authorizing = MESSAGE;
            if(!sevent->response)
                break;
            if(sevent->cid < 1)
                break;
            session = stack::access(sevent->cid);
            if(session)
                session->parent->message_reply(this, session);
            else
                send_reply(SIP_NOT_FOUND);
            break;
        case EXOSIP_CALL_MESSAGE_NEW:
            stack::siplog(sevent->request);
            authorizing = CALL;
            if(MSG_IS_BYE(sevent->request)) {
                if(sevent->cid > 0)
                    session = stack::access(sevent->cid);
                if(session) {
                    send_reply(SIP_OK);
                    session->parent->bye(this, session);
                }
                else
                    send_reply(SIP_NOT_FOUND);
            }
            else if(MSG_IS_REFER(sevent->request)) {
                if(sevent->cid > 0)
                    session = stack::access(sevent->cid);
                if(session)
                    stack::refer(session, sevent);
            }
            break;
        case EXOSIP_MESSAGE_NEW:
            stack::siplog(sevent->request);
            authorizing = MESSAGE;
            if(!sevent->request)
                break;
            expiration();
            if(MSG_IS_OPTIONS(sevent->request))
                options();
            else if(MSG_IS_REGISTER(sevent->request)) {
                authorizing = REGISTRAR;
                registration();
            }
            else if(MSG_IS_REFER(sevent->request)) {
                if(sevent->cid > 0)
                    session = stack::access(sevent->cid);
                if(session)
                    stack::refer(session, sevent);
            }
            else if(MSG_IS_BYE(sevent->request)) {
                if(sevent->cid > 0)
                    session = stack::access(sevent->cid);
                if(session) {
                    send_reply(SIP_OK);
                    stack::close(session);
                }
                else
                    send_reply(SIP_BAD_REQUEST);
                break;
            }
            else if(MSG_IS_MESSAGE(sevent->request)) {
                if(authorize())
                    message();
                break;
            }
            else if(MSG_IS_PUBLISH(sevent->request)) {
                if(authorize())
                    publish();
            }
            else if(!MSG_IS_INFO(sevent->request)) {
                shell::debug(2, "unsupported %s in dialog", sevent->request->sip_method);
                break;
            }
            if(sevent->cid > 0) {
                session = stack::access(sevent->cid);
                if(session)
                    stack::infomsg(session, sevent);
            }
            send_reply(SIP_OK);
            break;
        default:
            if(sevent->response)
                stack::siplog(sevent->response);
            else
                stack::siplog(sevent->request);
            shell::log(shell::WARN, "unknown message");
        }

        // release access locks for registry and sessions quickly...

        if(session) {
            stack::detach(session);
            session = NULL;
        }

        if(reginfo) {
            if(activated)
                server::activate(reginfo);
            registry::detach(reginfo);
            reginfo = NULL;
        }

        via_address.clear();
        request_address.clear();

        // release config access lock(s)...

        if(access) {
            server::release(access);
            access = NULL;
        }

        if(routed) {
            server::release(routed);
            routed = NULL;
        }

        server::release(authorized);
        server::release(dialed);

        eXosip_event_free(sevent);
        --active_count;
    }
}

END_NAMESPACE
