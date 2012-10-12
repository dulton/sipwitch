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

#include <sipwitch-config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/uri.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

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

bool uri::rewrite(const char *sipuri, char *buffer, size_t size)
{
    const char *schema = "sip:";
    size_t prefix = 4;
    const char *name = strchr(sipuri, '@');
    char *ep;

    if(String::equal(sipuri, "sips:", 5)) {
        sipuri += 5;
        prefix = 5;
        schema = "sips:";
    }
    if(String::equal(sipuri, "sip:", 4))
        sipuri += 4;

    String::set(buffer, size, schema);
    buffer += prefix;
    size -= prefix;

    if(name) {
        sipuri = name + 1;
        String::set(buffer, size, sipuri);
        ep = strchr(buffer, '@');
        if(ep) {
            *(++ep) = 0;
            prefix = strlen(buffer);
            size -= prefix;
            buffer += prefix;
        }
    }
    return resolve(sipuri, buffer, size);
}

bool uri::resolve(const char *sipuri, char *buffer, size_t size)
{
    assert(sipuri != NULL);
    assert(buffer != NULL);
    assert(size > 0);

    const char *uriname;
    char *cp;
    unsigned port = 0;
    struct sockaddr *address;

    if(String::equal(sipuri, "sips:", 5))
        sipuri += 5;
    if(String::equal(sipuri, "sip:", 4))
        sipuri += 4;

    uriname = strchr(sipuri, '@');
    if(uriname)
        sipuri = ++uriname;

    if(*sipuri == '[') {
        String::set(buffer, size, ++sipuri);
        cp = strchr(buffer, ']');
        if(cp)
            *(cp++) = 0;
        if(cp && *cp == ':')
            ++cp;
        if(cp)
            port = atoi(cp);
    }
    else {
        String::set(buffer, size, sipuri);
        cp = strchr(buffer, ':');
        if(cp) {
            *(cp++) = 0;
            port = atoi(cp);
        }
    }
    if(Socket::isNumeric(buffer)) {
        if(!port)
            port = 5060;
    }
    else {
        Socket::address resolver;
        resolver.set(buffer, port);
        address = resolver.getAddr();
        if(address) {
            Socket::getaddress(address, buffer, size);
            port = Socket::getservice(address);
            if(!port)
                port = 5060;
        }
        else
            return false;
    }

    size_t len = strlen(buffer);
    if(port)
        snprintf(buffer + len, size - len, ":%u", port);
    return true;
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

void uri::identity(struct sockaddr *addr, char *buf, const char *user, size_t size)
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
    Socket::getaddress(addr, buf + len, size - len);
}

