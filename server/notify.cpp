// Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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

#ifdef	HAVE_LIBNOTIFY

#include <libnotify/notify.h>
#include <glib.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __LOCAL notify : public modules::sipwitch
{
public:
	notify();

private:
	void start(service *cfg);
	void stop(service *cfg);
	void reload(service *cfg);
	void activating(MappedRegistry *rr);
	void expiring(MappedRegistry *rr);
};

static notify notify_plugin;

notify::notify() :
modules::sipwitch()
{
	g_type_init();
	g_set_prgname("sipwitch");
	notify_init("sipwitch");

	process::errlog(INFO, "notify plugin loaded");
}

void notify::reload(service *cfg)
{
	assert(cfg != NULL);
	char summary[80];
	char body[128];
	static bool started = false;

	const char *state = cfg->getRoot()->getPointer();
	if(!state)
		state = "up";

	if(started)
		snprintf(summary, sizeof(summary),
			"sipwitch reloading %s", state);
	else
		snprintf(summary, sizeof(summary),
			"sipwitch starting %s", state);

	snprintf(body, sizeof(body),
		"domain=%s", sip_domain);

	started = true;	
	NotifyNotification *notice = notify_notification_new(summary, body, NULL, NULL);
	notify_notification_set_category(notice, NULL);
	notify_notification_set_urgency(notice, NOTIFY_URGENCY_NORMAL);
	notify_notification_set_timeout(notice, NOTIFY_EXPIRES_DEFAULT);
	notify_notification_show(notice, NULL);
	g_object_unref(G_OBJECT(notice));
}

void notify::start(service *cfg)
{
}

void notify::stop(service *cfg)
{
	notify_uninit();
}

void notify::activating(MappedRegistry *rr)
{
	char addr[128];

	Socket::getaddress((struct sockaddr *)&rr->contact, addr, sizeof(addr));
}

void notify::expiring(MappedRegistry *rr)
{
	// process::system("%s/sipdown %s %d", dirpath, rr->userid, rr->ext);
}

END_NAMESPACE

#endif
