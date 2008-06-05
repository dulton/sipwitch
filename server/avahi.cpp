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

#include <sipwitch/sipwitch.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#ifdef	MODULE_AVAHI

#else

class __LOCAL avahi : public service::callback
{
public:
	avahi();
};

static avahi avahi_plugin;

avahi::avahi() :
service::callback(0)
{
	process::errlog(FAILURE, "avahi plugin could not be built");
}

#endif

END_NAMESPACE
