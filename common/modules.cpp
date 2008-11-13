// Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
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
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

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

bool modules::sipwitch::classifier(rtpproxy::session *sid, rtpproxy::session *src, struct sockaddr *addr)
{
	return false;
}

void modules::sipwitch::registration(int id, regmode_t mode)
{
}


