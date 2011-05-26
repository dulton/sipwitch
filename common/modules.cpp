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

#include <config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/modules.h>
#include <sipwitch/control.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

modules::protocols *modules::protocols::instance = NULL;

modules::protocols::protocols()
{
    assert(instance == NULL);

    instance = this;
}

modules::sipwitch::sipwitch() :
service::callback(MODULE_RUNLEVEL)
{
}

modules::generic::generic() :
service::callback(GENERIC_RUNLEVEL)
{
}

void modules::sipwitch::activating(MappedRegistry *rr)
{
}

void modules::sipwitch::expiring(MappedRegistry *rr)
{
}

void modules::sipwitch::period(long slice)
{
}

bool modules::sipwitch::announce(MappedRegistry *rr, const char *msgtype, const char *event, const char *expires, const char *msgbody)
{
    return false;
}

void modules::sipwitch::registration(int id, regmode_t mode)
{
}

bool modules::sipwitch::authenticate(int id, const char *realm)
{
    return false;
}

char *modules::sipwitch::referLocal(MappedRegistry *rr, const char *target, char *buffer, size_t size)
{
    return NULL;
}

char *modules::sipwitch::referRemote(MappedRegistry *rr, const char *target, char *buffer, size_t size)
{
    return NULL;
}

void modules::errlog(shell::loglevel_t level, const char *text)
{
    linked_pointer<service::callback> cb = service::getModules();

    while(is(cb)) {
        cb->errlog(level, text);
        cb.next();
    }
}

void modules::cdrlog(FILE *fp, cdr *call)
{
    DateTimeString dt(call->starting);
    const char *buf = dt.c_str();

    if(call->type == cdr::STOP) {
        shell::debug(1, "call %08x:%u %s %s %s %ld %s %s %s %s",
            call->sequence, call->cid, call->network, call->reason, buf,
            call->duration, call->ident, call->dialed, call->joined, call->display);
    }

    linked_pointer<service::callback> cb = service::getModules();

    while(is(cb)) {
        cb->cdrlog(call);
        cb.next();
    }

    if(!fp || call->type != cdr::STOP)
        return;

    fprintf(fp, "%08x:%u %s %s %s %ld %s %s %s %s\n",
        call->sequence, call->cid, call->network, call->reason, buf,
        call->duration, call->ident, call->dialed, call->joined, call->display);
}


