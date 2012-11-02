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

#include <sipwitch-config.h>
#include <sipwitch/sipwitch.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static const char *dirpath = NULL;
static char prior[65] = "down";

class __LOCAL scripting : public modules::sipwitch
{
public:
    scripting();

private:
    void start(service *cfg);
    void reload(service *cfg);
    void activating(MappedRegistry *rr);
    void expiring(MappedRegistry *rr);
};

static scripting scripting_plugin;

scripting::scripting() :
modules::sipwitch()
{
    shell::log(shell::INFO, "scripting plugin loaded");
}

void scripting::reload(service *cfg)
{
    assert(cfg != NULL);

    if(dirpath == NULL)
        start(cfg);

    if(!dirpath)
        return;

    const char *state = cfg->getRoot()->getPointer();
    if(!state)
        state = "up";

    if(String::equal(state, prior))
        return;

    control::libexec("%s/sipstate %s", dirpath, state);

    String::set(prior, sizeof(prior), state);
}

void scripting::start(service *cfg)
{
    assert(cfg != NULL);

    static char buf[256];
    const char *home = control::env("HOME");

    if(fsys::is_dir(DEFAULT_CFGPATH "/sysconfig/sipwitch-scripts"))
        dirpath = DEFAULT_CFGPATH "/sysconfig/sipwitch-scripts";
    else if(fsys::is_dir(DEFAULT_LIBEXEC "/sipwitch"))
        dirpath = DEFAULT_LIBEXEC "/sipwitch";
    else if(home) {
        snprintf(buf, sizeof(buf), "%s/.sipwitch-scripts", home);
        if(fsys::is_dir(buf))
            dirpath = buf;
    }

    if(dirpath)
        shell::log(shell::INFO, "scripting plugin path %s", dirpath);
    else
        shell::log(shell::ERR, "scripting plugin disabled; no script directory");
}

void scripting::activating(MappedRegistry *rr)
{
    char addr[128];
    if(!dirpath)
        return;

    Socket::query((struct sockaddr *)&rr->contact, addr, sizeof(addr));
    control::libexec("%s/sipup %s %d %s:%d %d", dirpath, rr->userid, rr->ext,
        addr, Socket::service((struct sockaddr *)&rr->contact),
        (int)(rr->type - MappedRegistry::EXPIRED));
}

void scripting::expiring(MappedRegistry *rr)
{
    if(!dirpath)
        return;

    control::libexec("%s/sipdown %s %d", dirpath, rr->userid, rr->ext);
}

END_NAMESPACE
