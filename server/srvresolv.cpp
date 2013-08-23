// Copyright (C) 2007-2010 David Sugar, Tycho Softworks.
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
#include <sipwitch/sipwitch.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#ifdef  SRVRESOLV_RULI

static bool active = false;

extern "C" {
    #include <ruli.h>
}

class __LOCAL srvresolv : public modules::sipwitch
{
public:
    srvresolv();

    static srvresolv plugin;

private:
    void start(service *cfg);
    void stop(service *cfg);
    void reload(service *cfg);

    bool resolve(const char *uri, struct sockaddr_storage *addr);
};

srvresolv::srvresolv() :
modules::sipwitch()
{
    shell::log(shell::INFO, "%s\n",
        _TEXT("srv resolver plugin loaded"));
}

void srvresolv::stop(service *cfg)
{
    active = false;
}

void srvresolv::start(service *cfg)
{
    active = true;
}

void srvresolv::reload(service *cfg)
{
    active = true;
}

bool srvresolv::resolve(const char *uri, struct sockaddr_storage *addr)
{
    int protocol = sip_protocol;
    const char *svc = "sip";

    if(!uri || !addr)
        return false;

    if(uri::portid(uri))
        return false;

    if(eq(uri, "sips:", 5)) {
        protocol = IPPROTO_TCP;
        svc = "sips";
    }
    else if(!eq(uri, "sip:", 4) && sip_tlsmode)
        svc = "sips";

    char host[256];
    uri::hostid(uri, host, sizeof(host));
    if(Socket::is_numeric(host))
        return false;

    struct addrinfo hint, *list = NULL;
    memset(&hint, 0, sizeof(hint));
    hint.ai_socktype = 0;
    hint.ai_protocol = protocol;
    hint.ai_family = sip_family;
    if(hint.ai_protocol == IPPROTO_UDP)
        hint.ai_socktype = SOCK_DGRAM;
    else
        hint.ai_socktype = SOCK_STREAM;
#ifdef  PF_UNSPEC
    hint.ai_flags = AI_PASSIVE;
#endif
#if defined(AF_INET6) && defined(AI_V4MAPPED)
    if(hint.ai_family == AF_INET6)
        hint.ai_flags |= AI_V4MAPPED;
#endif
    hint.ai_flags = AI_CANONNAME;
    ruli_getaddrinfo(host, svc, &hint, &list);

    if(!list)
        return false;    
    
    Socket::store(addr, list->ai_addr);
    ruli_freeaddrinfo(list);
    return true;
}

#else

class __LOCAL srvresolv : modules::sipwitch
{
public:
    static srvresolv plugin;

    srvresolv();
};

srvresolv::srvresolv() :
modules::sipwitch()
{
    shell::log(shell::ERR, "srv resolver could not be built");
}

#endif

srvresolv srvresolv::plugin;

END_NAMESPACE
