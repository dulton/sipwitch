// Copyright (C) 2007-2008 David Sugar, Tycho Softworks.
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

#include <sipwitch/sipwitch.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#ifdef	ZEROCONF_AVAHI

extern "C" {
	#include <avahi-client/client.h>
	#include <avahi-client/publish.h>
	#include <avahi-common/alternative.h>
	#include <avahi-common/thread-watch.h>
	#include <avahi-common/malloc.h>
	#include <avahi-common/error.h>
	#include <avahi-common/timeval.h>
}

class __LOCAL zeroconf : public modules::generic
{
public:
	zeroconf();

    void setClient(AvahiClientState state);
    void setGroup(AvahiEntryGroupState state);

	inline void setClient(AvahiClient *c)
		{client = c;};

	static zeroconf plugin;

private:
	void start(service *cfg);
	void stop(service *cfg);
	void reload(service *cfg);

    AvahiThreadedPoll *poller;
    AvahiClient *client;
    AvahiEntryGroup *group;
    char *name;
	const char *protocol;
    int error;
	int family;
	int port;
};

extern "C" {

	static void client_callback(AvahiClient *c, AvahiClientState state, void *userdata)
	{
		if(!c)
			return;

		zeroconf::plugin.setClient(c);
		zeroconf::plugin.setClient(state);
	}

	static void group_callback(AvahiEntryGroup *g, AvahiEntryGroupState state, void *userdata)
	{
		zeroconf::plugin.setGroup(state);
	}
}

zeroconf::zeroconf() :
modules::generic()
{
	family = AF_INET;
	protocol = "_sip._udp";
	port = 5060;
	poller = NULL;
	client = NULL;
	name = avahi_strdup("sipwitch");
	process::errlog(ERRLOG, "zeroconf plugin using avahi");
}

void zeroconf::setGroup(AvahiEntryGroupState state)
{
    char *newname;

    switch(state)
    {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        process::errlog(INFO, "zeroconf %s service(s) established", name);
        break;
    case AVAHI_ENTRY_GROUP_COLLISION:
        newname = avahi_alternative_service_name(name);
        process::errlog(NOTICE, "zeroconf service %s renamed %s", name, newname);
        avahi_free(name);
        name = newname;
        setClient(AVAHI_CLIENT_S_RUNNING);
		break;
    case AVAHI_ENTRY_GROUP_FAILURE:
        process::errlog(ERRLOG, "zeroconf service failure; error=%s",
            avahi_strerror(avahi_client_errno(client)));
        // avahi_thread_poll_quit(poller);
    default:
        break;
    }
}

void zeroconf::setClient(AvahiClientState state)
{
    int ret;
    AvahiProtocol avifamily = AVAHI_PROTO_UNSPEC;

	switch(state) {
	case AVAHI_CLIENT_S_RUNNING:
		goto add;
	case AVAHI_CLIENT_FAILURE:
failed:
		process::errlog(ERRLOG, "zeroconf failure; error=%s",
            avahi_strerror(avahi_client_errno(client)));
		break;
    case AVAHI_CLIENT_S_COLLISION:
    case AVAHI_CLIENT_S_REGISTERING:
        if(group)
            avahi_entry_group_reset(group);
    default:
        break;
    }
    return;
add:
	if(!group)
        group = avahi_entry_group_new(client, group_callback, NULL);
    if(!group)
        goto failed;

	process::errlog(INFO, "zeroconf adding sip on port %d", port);
	ret = avahi_entry_group_add_service(group, AVAHI_IF_UNSPEC,
		avifamily, (AvahiPublishFlags)0, name, protocol, NULL, NULL, port, NULL);

	if(ret < 0)
		process::errlog(ERRLOG, "zeroconf %s failed; error=%s", 
			protocol, avahi_strerror(ret));

	ret = avahi_entry_group_commit(group);
	if(ret >= 0)
		return;

	process::errlog(ERRLOG, "zeroconf service commit failure; error=%s",
		avahi_strerror(ret));
}

void zeroconf::stop(service *cfg)
{
	if(poller)
		avahi_threaded_poll_stop(poller);
	if(client)
		avahi_client_free(client);
    if(name)
        avahi_free(name);
//	if(poller)
//		avahi_threaded_poll_free(poller);
    client = NULL;
    poller = NULL;
    name = NULL;
}

void zeroconf::start(service *cfg)
{
	poller = avahi_threaded_poll_new();

	if(!poller) {
		process::errlog(ERRLOG, "zeroconf service failed to start");
		return;
	}

	client = avahi_client_new(avahi_threaded_poll_get(poller),
        (AvahiClientFlags)0, client_callback, NULL, &error);

	process::errlog(INFO, "zeroconf service started");
    avahi_threaded_poll_start(poller);
}

void zeroconf::reload(service *cfg)
{
	assert(cfg != NULL);

	linked_pointer<service::keynode> sp = cfg->getList("stack");
    const char *key = NULL, *value;
	static bool started = false;

	if(started)
		return;

	started = true;

	while(sp) {
        key = sp->getId();
        value = sp->getPointer();
        if(key && value) {
			if(!stricmp(key, "port"))
				port = atoi(value);
            else if(!stricmp(key, "transport")) {
                if(!stricmp(value, "tcp") || !stricmp(value, "tls"))
                    protocol = "_sip._tcp";
			}
#ifdef	AF_INET6
			else if(!stricmp(key, "interface")) {
                if(strchr(value, ':') != NULL)
                    family = AF_INET6;
			}
#endif
		}
		sp.next();
	}
}

#else

class __LOCAL zeroconf : modules::generic
{
public:
	static zeroconf plugin;

	zeroconf();
};

zeroconf::zeroconf() :
modules::generic()
{
	process::errlog(ERRLOG, "zeroconf plugin could not be built");
}

#endif

zeroconf zeroconf::plugin;

END_NAMESPACE
