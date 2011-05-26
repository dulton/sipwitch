// Copyright (C) 2010 David Sugar, Tycho Softworks.
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

static class __LOCAL proto : private modules::protocols
{
public:
    inline proto() : modules::protocols() {};

private:
    virtual int create_registration(const char *uri, const char *server, const char *contact, int expires);

    virtual bool release_registration(int rid);

    virtual bool add_authentication(const char *userid, const char *secret, const char *realm);

    virtual void random_uuid(char *uuid);

    virtual bool publish(const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body);


} _protocols_;

int proto::create_registration(const char *uri, const char *server, const char *contact, int expires)
{
    osip_message_t *msg = NULL;
    int rid;

    eXosip_lock();
    rid = eXosip_register_build_initial_register(uri, server, contact, (int)expires, &msg);
    if(msg) {
        osip_message_set_supported(msg, "100rel");
        osip_message_set_header(msg, "Event", "Registration");
        osip_message_set_header(msg, "Allow-Events", "presence");
        eXosip_register_send_register(rid, msg);
    }
    else
        rid = -1;
    eXosip_unlock();
    return rid;
}

bool proto::release_registration(int rid)
{
    osip_message_t *msg = NULL;
    bool result = true;

    eXosip_lock();

    eXosip_register_build_register(rid, 0, &msg);
    if(msg)
        eXosip_register_send_register(rid, msg);
    else
        result = false;
    eXosip_unlock();
    return result;
}

bool proto::add_authentication(const char *userid, const char *secret, const char *realm)
{
    eXosip_lock();
    eXosip_add_authentication_info(userid, userid, secret, NULL, realm);
    eXosip_automatic_action();
    eXosip_unlock();
    return true;
}

void proto::random_uuid(char *uuid)
{
    Random::uuid(uuid);
}

bool proto::publish(const char *uri, const char *contact, const char *event, const char *duration, const char *type, const char *body)
{
    bool result = true;
    osip_message_t *msg = NULL;

    eXosip_lock();
    eXosip_build_publish(&msg, uri, contact, NULL, event, duration, type, body);
    if(msg)
        eXosip_publish(msg, uri);
    else
        result = false;
    eXosip_unlock();
    return result;
}

END_NAMESPACE

