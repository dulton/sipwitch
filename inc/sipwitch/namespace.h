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

/**
 * GNU SIP Witch library namespace.  This gives the server it's own
 * private namespace for plugins, etc.
 * @file sipwitch/namespace.h
 */

#ifndef _SIPWITCH_NAMESPACE_H_
#define _SIPWITCH_NAMESPACE_H_

namespace sipwitch {
using namespace ucommon;
}

#define SIPWITCH_NAMESPACE   sipwitch
#define NAMESPACE_SIPWITCH   namespace sipwitch {

/**
 * Common namespace for sipwitch server.
 * We use a sipwitch specific namespace to easily seperate sipwitch
 * interfaces from other parts of GNU Telephony.  This namespace
 * is controlled by the namespace macros (SIPWITCH_NAMESPACE and
 * NAMESPACE_SIPWITCH) and are used in place of direct namespace
 * declarations to make parsing of tab levels simpler and to allow easy
 * changes to the namespace name later if needed.
 * @namespace sipwitch
 */

#endif
