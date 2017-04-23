// Copyright (C) 2007-2014 David Sugar, Tycho Softworks.
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
#include <sipwitch/sipwitch.h>
#include <ucommon/secure.h>
#include <stddef.h>

namespace sipwitch {

static class __LOCAL subscriber : private modules::sipwitch
{
private:
    static subscriber _sub;

    void registration(voip::reg_t, modules::regmode_t mode);
    bool authenticate(voip::reg_t id, const char *remote_realm);
    void update(void);

public:
    subscriber();

    void reload(service *cfg);
    void start(service *cfg);
    void stop(service *cfg);
    void snapshot(FILE *fp);
} _sub;

static volatile bool changed = false;
static volatile timeout_t interval = 50;
static volatile time_t refresh = 60;
static volatile time_t updated = 0;
static int priority = 0;
static const char *iface = NULL;
static char *server = NULL;
static char *proxy = NULL;
static char *userid = NULL;
static char *schema = (char *)"sip";
static char *volatile secret = NULL;
static char *identity = NULL;
static voip::context_t context = NULL;
static MappedRegistry provider; // fake provider record to be used...
static unsigned short port = 9000;

subscriber::subscriber() :
modules::sipwitch()
{
    zero_unsafe<MappedRegistry>(provider);
    provider.rid = -1;
    provider.type = MappedRegistry::EXTERNAL;
    // we already know provider is normally external / outside NAT....
    String::set(provider.network, sizeof(provider.network), "*");
}

void subscriber::update(void)
{
    char contact[MAX_URI_SIZE];
    char uri[MAX_URI_SIZE];
    char reg[MAX_URI_SIZE];
    unsigned len;
    Socket::address dest = server;

    Random::uuid(provider.remote);
    snprintf(uri, sizeof(uri), "%s:%s@%s", schema, userid, server);
    snprintf(reg, sizeof(reg), "%s:%s", schema, server);
    snprintf(contact, sizeof(contact), "%s:%s@", schema, provider.remote);

    changed = false;
    len = strlen(contact);
    Socket::via((struct sockaddr *)&provider.contact, dest.getAddr());
    Socket::query((struct sockaddr *)&provider.contact, contact + len, sizeof(contact) - len);
    len = strlen(contact);
    snprintf(contact + len, sizeof(contact) - len, ":%u", sip_port);
    shell::debug(3, "registering %s with %s", contact, server);

    voip::msg_t msg = NULL;
    provider.rid = voip::make_registry_request(context, uri, reg, contact, (unsigned)refresh, &msg);
    if(provider.rid == -1 || !msg)
        provider.status = MappedRegistry::OFFLINE;
    else {
        voip::server_supports(msg, "100rel");
        voip::header(msg, "Event", "Registration");
        voip::header(msg, "Allow-Events", "presence");
        voip::send_registry_request(context, provider.rid, msg);
        provider.status = MappedRegistry::IDLE;
    }
}

void subscriber::start(service *cfg)
{
    assert(cfg != NULL);

    if(count) {
        provider.source.external.statnode = stats::request("provider");

        if(changed)
            update();
    }
}

void subscriber::stop(service *cfg)
{
    if(provider.rid != -1)
        voip::release_registry(context, provider.rid);

    assert(cfg != NULL);
}

void subscriber::snapshot(FILE *fp)
{
    assert(fp != NULL);

    fprintf(fp, "subscriber:\n");
}

void subscriber::reload(service *cfg)
{
    assert(cfg != NULL);

    char *temp;
    const char *key = NULL, *value;
    linked_pointer<service::keynode> sp = cfg->getList("subscriber");
    char buffer[160];
    srv resolver;
    voip::context_t tmp_context = NULL;

    updated = 0l;

    while(is(sp)) {
        key = sp->getId();
        value = sp->getPointer();
        if(key && value) {
            if(!stricmp(key, "count") && !is_configured())
                count = atoi(value);
            else if(!stricmp(key, "interface") && !is_configured())
                iface = strdup(value);
            else if(!stricmp(key, "interval"))
                interval = atol(value);
            else if(!stricmp(key, "priority") && !is_configured())
                priority = atoi(value);
            else if(!stricmp(key, "port") && !is_configured())
                port = atoi(value);
            // very rare we may wish to override provider network/nat state
            else if(!stricmp(key, "network"))
                String::set(provider.network, sizeof(provider.network), value);
            else if(!stricmp(key, "refresh"))
                refresh = atoi(value);
            else if(!stricmp(key, "registrar") || !stricmp(key, "server")) {
                tmp_context = resolver.route(value, buffer, sizeof(buffer));
                if(tmp_context) {
                    changed = true;
                    server = cfg->dup(buffer);
                    shell::debug(2, "subscriber provider is %s", buffer);
                }
                else {
                    changed = false;
                    shell::log(shell::ERR, "subscriber: %s: cannot resolve", value);
                }
            }
            else if(!stricmp(key, "proxy")) {
                temp = proxy;
                proxy = strdup(value);
                if(temp)
                    free(temp);
            }
            else if(!stricmp(key, "userid")) {
                temp = userid;
                userid = strdup(value);
                if(temp)
                    free(temp);
            }
            else if(!stricmp(key, "secret")) {
                temp = secret;
                secret = strdup(value);
                if(temp)
                    free(temp);
            }
            else if(!stricmp(key, "identity")) {
                temp = identity;
                identity = strdup(value);
                if(temp)
                    free(temp);
            }
        }
        sp.next();
    }

    if(tmp_context)
        context = tmp_context;

    if(!is_configured() && count)
        stats::allocate(1);
}

void subscriber::registration(voip::reg_t id, modules::regmode_t mode)
{
    if(id == -1 || id != provider.rid)
        return;

    switch(mode) {
    case modules::REG_FAILED:
        shell::log(shell::ERR, "service provider failed");
        provider.rid = -1;
        provider.status = MappedRegistry::OFFLINE;
        if(changed)
            update();
        return;
    case modules::REG_SUCCESS:
        shell::log(shell::NOTIFY, "service provider active");
        provider.status = MappedRegistry::IDLE;
        return;
    }
}

bool subscriber::authenticate(voip::reg_t id, const char *remote_realm)
{
    if(id == -1 || id != provider.rid)
        return false;

    if(secret && *secret)
        shell::debug(3, "authorizing %s for %s", userid, remote_realm);
    else {
        shell::debug(3, "cannot authorize %s for %s", userid, remote_realm);
        return false;
    }

    voip::add_authentication(context, userid, secret, remote_realm, true);
    return true;
}

} // end namespace
