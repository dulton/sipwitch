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

#include <sipwitch-config.h>
#include <ucommon/secure.h>
#include <ucommon/export.h>
#include <sipwitch/uri.h>
#include <sipwitch/service.h>
#include <sipwitch/modules.h>

#ifdef  HAVE_RESOLV_H
extern "C" {
#include <resolv.h>
}

#if PACKETSZ > 1024
#define MAXPACKET PACKETSZ
#else
#define MAXPACKET 1024
#endif 

typedef union {
        HEADER hdr;
        char buf[MAXPACKET];
} query;

#ifndef T_SRV 
#define T_SRV           33
#endif

#endif

namespace sipwitch {

srv::srv(const char *uri) : Socket::address()
{
#ifdef  _MSWINDOWS_
    Socket::init();
#endif
    srvlist = NULL;
    entry = NULL;
    count = 0;

    set(uri);
}

srv::srv() : Socket::address()
{
#ifdef  _MSWINDOWS_
    Socket::init();
#endif
    srvlist = NULL;
    entry = NULL;
    count = 0;
}

void srv::set(const char *uri)
{
    int protocol = IPPROTO_UDP;
    int port = uri::portid(uri);
    char host[256], svc[10];
    struct addrinfo hint;

    if(service::callback::out_context != service::callback::udp_context)
        protocol = IPPROTO_TCP;

#if defined(HAVE_RESOLV_H)
    bool nosrv = false;
#endif

    clear();

    String::set(svc, sizeof(svc), "sip");

    if(port) {
#ifdef  HAVE_RESOLV_H
        nosrv = true;
#endif
        snprintf(svc, sizeof(svc), "%d", port);
    }
    else if(eq(uri, "sips:", 5)) {
        protocol = IPPROTO_TCP;
        String::set(svc, sizeof(svc), "sips");
    }
    else if(eq(uri, "tcp:", 4)) {
        protocol = IPPROTO_TCP;
        uri += 4;    
    }
    else if(eq(uri, "udp:", 4)) {
        protocol = IPPROTO_UDP;
        uri += 4;    
    }

    uri::hostid(uri, host, sizeof(host));
    memset(&hint, 0, sizeof(hint));

    hint.ai_socktype = 0;
    hint.ai_protocol = protocol;

    if(hint.ai_protocol == IPPROTO_UDP)
        hint.ai_socktype = SOCK_DGRAM;
    else
        hint.ai_socktype = SOCK_STREAM;

#ifdef  PF_UNSPEC
    hint.ai_flags = AI_PASSIVE;
#endif

    if(Socket::is_numeric(host)) {
        hint.ai_flags |= AI_NUMERICHOST;
#ifdef  HAVE_RESOLV_H
        nosrv = true;
#endif
    }

    hint.ai_family = service::callback::sip_family;

#if defined(AF_INET6) && defined(AI_V4MAPPED)
    if(hint.ai_family == AF_INET6)
        hint.ai_flags |= AI_V4MAPPED;
#endif
#ifdef  AI_NUMERICSERV
    if(atoi(svc) > 0)
        hint.ai_flags |= AI_NUMERICSERV;
#endif

    linked_pointer<modules::generic> cb = service::getGenerics();
    while(is(cb)) {
        srvlist = cb->resolve(uri, &hint);
        if(srvlist) {
            count = 1;
            entry = (struct sockaddr *)&srvlist[0].addr;
            pri = srvlist[0].priority;
            return;
        }
        cb.next();
    }

#ifdef  HAVE_RESOLV_H
    int result;
    HEADER *hp;
    char hbuf[256];
    uint16_t acount, qcount;
    unsigned char *mp, *ep, *cp;
    uint16_t type, weight, priority, hport, dlen;

    if(nosrv)
        goto nosrv;

    query reply;
    char zone[256];
    
    if(hint.ai_protocol == IPPROTO_TCP)
        snprintf(zone, sizeof(zone), "_%s._tcp.%s", svc, host);
    else
        snprintf(zone, sizeof(zone), "_%s._udp.%s", svc, host);

    result = res_query(zone, C_IN, T_SRV, (unsigned char *)&reply, sizeof(reply));
    if(result < (int)sizeof(HEADER))
        goto nosrv;

    hp = (HEADER *)&reply;
    acount = ntohs(hp->ancount);
    qcount = ntohs(hp->qdcount);
    mp = (unsigned char *)&reply;
    ep = (unsigned char *)&reply + result;
    cp = (unsigned char *)&reply + sizeof(HEADER);

    if(!acount)
        goto nosrv;

    srvlist = new srv::address[acount];
    while(qcount-- > 0 && cp < ep) {
        result = dn_expand(mp, ep, cp, hbuf, sizeof(hbuf));
        if(result < 0)
            goto nosrv;
        cp += result + QFIXEDSZ;
    }

    while(acount-- > 0 && cp < ep) {
        result = dn_expand(mp, ep, cp, hbuf, sizeof(hbuf));
        if(result < 0)
            goto nosrv;
        
        cp += result;

        type = ntohs(*((uint16_t *)cp));
        cp += sizeof(uint16_t);

		// class
		cp += sizeof(uint16_t);

        // ttl
        cp += sizeof(uint32_t);

        dlen = ntohs(*((uint16_t *)cp));
        cp += sizeof(uint16_t);
        
		if(type != T_SRV) {
	        cp += dlen;
			continue;
		}
		
        priority = ntohs(*((uint16_t *)cp));
		cp += sizeof(uint16_t);
	
		weight = ntohs(*((uint16_t *)cp));
		cp += sizeof(uint16_t);

		hport = ntohs(*((uint16_t *)cp));
		cp += sizeof(uint16_t);

		result = dn_expand(mp, ep, cp, hbuf, sizeof(hbuf));
		if(result < 0)
			break;

        Socket::address resolv(hbuf, hport);
        struct sockaddr *sp = resolv.getAddr();

        if(sp) {
            uint16_t rand;
            srv::address *current = NULL;

            Random::fill((unsigned char *)&rand, sizeof(rand));
            rand &= 0x7fff;
            if(weight)
                weight = (1 + rand) % ( 10000 * weight);
        
            srvlist[count].weight = weight;
            srvlist[count].priority = priority;
            Socket::store(&srvlist[count].addr, sp);
            if(!current || priority < current->priority || weight > current->weight) {
                current = &srvlist[count];
                entry = (struct sockaddr *)&srvlist[count].addr;
                pri = priority;
            }
            ++count;
        }
		cp += result;
    }
	
	return;
nosrv:
    if(srvlist) {
        delete[] srvlist;
        srvlist = NULL;
    }
#endif

    if(eq(svc, "sips"))
        String::set(svc, sizeof(svc), "5061");
    else if(eq(svc, "sip"))
        String::set(svc, sizeof(svc), "5060");
    getaddrinfo(host, svc, &hint, &list);
	struct addrinfo *ap = list;
    count = 0;

    if(ap)
        entry = ap->ai_addr;
	while(ap) {
		++count;
		ap = ap->ai_next;
	}
}

srv::~srv()
{
    clear();
}

void srv::clear(void)
{
    if(srvlist) {
        delete[] srvlist;
        srvlist = NULL;
    }

    if(list) {
        freeaddrinfo(list);
        list = NULL;
    } 

    entry = NULL;
	count = 0;
}       

struct sockaddr *srv::next(void)
{
#ifdef  HAVE_RESOLV_H
    unsigned index = 0;
    srv::address *node = NULL, *np = NULL;
    ++pri;
    while(index < count) {
        np = &srvlist[index++];
        if(np->priority < pri)
            continue;
        if(!node || np->priority < node->priority || np->weight > node->weight)
            node = np;
    }
    if(!np) {
        entry = NULL;
        return NULL;
    }
    pri = node->priority;
    entry = (struct sockaddr *)&node->addr;
#else
    entry = NULL;
#endif
    return entry;
}

voip::context_t srv::route(const char *uri, char *buf, size_t size)
{
    char host[256];
    const char *schema = "sip";
    const char *sid = uri;
    unsigned short port = uri::portid(uri);
    voip::context_t ctx = service::callback::out_context;

    if(!uri::hostid(uri, host, sizeof(host)))
        return NULL;

    if(eq(uri, "sips:", 5)) {
        schema = "sips";
        ctx = service::callback::tls_context;
    }
    else if(eq(uri, "tcp:", 4)) {
        uri += 4;
        ctx = service::callback::tcp_context;
    }
    else if(eq(uri, "udp:", 4)) {
        uri += 4;
        ctx = service::callback::udp_context;
    }

    buf[0] = 0;
    char *cp = strrchr(host, '.');
    if(Socket::is_numeric(host) || !cp || eq(cp, ".local") || eq(cp, ".localdomain")) {
        if(!port) {
            if(eq(schema, "sips"))
                port = 5061;
            else
                port = 5060;
        }
        if(strchr(host, ':'))
            snprintf(buf, size, "%s:[%s]:%u", schema, host, port);
        else
            snprintf(buf, size, "%s:%s:%u", schema, host, port);
        sid = buf;
    }
    set(sid);
    if(!entry)
        return NULL;
    if(!Socket::query(entry, host, sizeof(host)))
        return NULL;
#ifdef	AF_INET6
	if(entry->sa_family == AF_INET6)
		snprintf(buf, size, "%s:[%s]:%u", schema, host, (unsigned)ntohs(((struct sockaddr_in6 *)(entry))->sin6_port) & 0xffff);
	else
#endif
		snprintf(buf, size, "%s:%s:%u", schema, host, (unsigned)ntohs(((struct sockaddr_in *)(entry))->sin_port) & 0xffff);
    return ctx;
}

} // end namespace
