// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015-2017 Cherokees of Idaho.
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
#include <sipwitch/uri.h>
#include <sipwitch/service.h>

namespace sipwitch {

void uri::serviceid(const char *addr, char *buf, size_t size)
{
    const char *cp = strchr(addr, '@');
    if(addr) {
        String::set(buf, size, ++cp);
        return;
    }

    if(String::equal(addr, "sip:", 4))
        addr += 4;
    else if(String::equal(addr, "sips:", 5))
        addr += 5;

    String::set(buf, size, addr);
}

bool uri::hostid(const char *addr, char *buf, size_t size)
{
    assert(buf != NULL);
    assert(size > 0);

    char *ep;
    const char *cp;
    buf[0] = 0;

    if(!addr)
        return false;

    if(!strnicmp(addr, "sip:", 4))
        addr += 4;
    else if(!strnicmp(addr, "sips:", 5))
        addr += 5;

    cp = strchr(addr, '@');
    if(cp)
        addr = ++cp;

    String::set(buf, size, addr);
    if(buf[0] == '[')
        ep = strchr(buf, ']');
    else
        ep = strrchr(buf, ':');

    if(ep)
        *ep = 0;
    return true;
}

bool uri::userid(const char *addr, char *buf, size_t size)
{
    assert(buf != NULL);
    assert(size > 0);

    buf[0] = 0;
    char *ep;

    if(!addr)
        return false;

    if(!strnicmp(addr, "sip:", 4))
        addr += 4;
    else if(!strnicmp(addr, "sips:", 5))
        addr += 5;

    if(!strchr(addr, '@'))
        return false;

    String::set(buf, size, addr);
    ep = strchr(buf, '@');
    if(ep)
        *ep = 0;
    return true;
}

unsigned short uri::portid(const char *uri)
{
    const char *pp = NULL;
    const char *fp = NULL;

    if(eq(uri, "sips:", 5))
        uri += 5;
    else if(eq(uri, "sip:", 4)) {
        uri += 4;
    }

    if(*uri == '[') {
        pp = strchr(uri, ']');
        if(pp)
            pp = strchr(pp, ':');
    }
    else {
        pp = strrchr(uri, ':');
        fp = strchr(uri, ':');
        if(fp != pp)
            pp = NULL;
    }
    if(pp)
        return atoi(++pp);
    else
        return 0;
}

void uri::publish(const char *uri, char *buf, const char *user, size_t size)
{
    assert(uri != NULL);
    assert(buf != NULL);
    assert(user == NULL || *user != 0);
    assert(size > 0);

    const char *schema = "sip";
    const char *cp;

    if(String::equal(uri, "sip:", 4)) {
        uri += 4;
        schema = "sip";
    }
    else if(String::equal(uri, "sips:", 5)) {
        uri += 5;
        schema = "sips";
    }

    cp = strchr(uri, '@');
    if(cp && user != NULL)
        uri = ++cp;

    if(user)
        snprintf(buf, size, "%s:%s@%s", schema, user, uri);
    else
        snprintf(buf, size, "%s:%s", schema, uri);
}

voip::context_t uri::route(const char *uri, char *buf, size_t size)
{
    buf[0] = 0;
    const char *schema="sip:";
    voip::context_t ctx = service::callback::out_context;
    
    if(eq(uri, "sips:", 5)) {
        ctx = service::callback::tls_context;
        schema="sips:";
        uri += 5;
    }
    else if(!strncmp(uri, "sip:", 4))
        uri += 4;
    else if(!strncmp(uri, "tcp:", 4)) {
        ctx = service::callback::tcp_context;
        uri += 4;
    }
    else if(!strncmp(uri, "udp:", 4)) {
        ctx = service::callback::udp_context;
        uri += 4;
    }

    const char *sp = strchr(uri, '@');
    if(sp)
        uri = ++sp;

    snprintf(buf, size, "%s%s", schema, uri);
    return ctx;
}

bool uri::server(struct sockaddr *addr, char *buf, size_t size)
{
    assert(addr != NULL);
    assert(buf != NULL);
    assert(size > 0);

    char host[256];

    buf[0] = 0;

    if(!Socket::query(addr, host, sizeof(host)))
        return false;

#ifdef  AF_INET6
    if(addr->sa_family == AF_INET6)
        snprintf(buf, size, "sip:[%s]:%u", host, (unsigned)ntohs(((struct sockaddr_in6 *)(addr))->sin6_port) & 0xffff);
    else
#endif
        snprintf(buf, size, "sip:%s:%u", host, (unsigned)ntohs(((struct sockaddr_in *)(addr))->sin_port) & 0xffff);
    return true;
}

void uri::identity(const struct sockaddr *addr, char *buf, const char *user, size_t size)
{
    assert(addr != NULL);
    assert(buf != NULL);
    assert(user == NULL || *user != 0);
    assert(size > 0);

    *buf = 0;
    size_t len;

    if(user) {
        String::add(buf, size, user);
        String::add(buf, size, "@");
    }

    len = strlen(buf);
    Socket::query(addr, buf + len, size - len);
}

} // end namespace
