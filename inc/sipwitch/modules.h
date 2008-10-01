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

/**
 * Used for definitions of plugin modules.
 * @file sipwitch/modules.h
 */

#ifndef _SIPWITCH_MODULES_H_
#define	_SIPWITCH_MODULES_H_

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	__SIPWITCH_SERVICE_H_
#include <sipwitch/service.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT modules
{
public:
	class __EXPORT sipwitch : public service::callback
	{
	protected:
		sipwitch();

	public:
		virtual bool classifier(rtpproxy::session *session, rtpproxy::session *source, struct sockaddr *addr); 
		virtual void activating(MappedRegistry *rr);
		virtual void expiring(MappedRegistry *rr);
	};

	class __EXPORT sipapps : public service::callback
	{
	protected:
		sipapps();
	};
};

END_NAMESPACE

#endif
