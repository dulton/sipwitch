// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015 Cherokees of Idaho.
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
 * Manipulate address strings.
 * This is a utility class to help manipulate addresses and SIP uri's or
 * to resolve uri's into physical addresses.  SIP Witch prefers physical
 * (ip) addresses to avoid redundent dns lookups.  This is also placed in
 * common to better support plugin development.
 * @file sipwitch/uri.h
 */

#ifndef _SIPWITCH_URI_H_
#define _SIPWITCH_URI_H_

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef _UCOMMON_PLATFORM_H_
#include <ucommon/platform.h>
#endif

#ifndef _UCOMMON_SOCKET_H_
#include <ucommon/socket.h>
#endif

#ifndef __SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

#ifndef __SIPWITCH_VOIP_H_
#include <sipwitch/voip.h>
#endif

namespace sipwitch {

/**
 * Some convenience methods for manipulating SIP uri's.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT uri
{
public:
    static voip::context_t route(const char *uri, char *buf, size_t size);
    static void serviceid(const char *sipuri, char *buffer, size_t size);
    static bool server(struct sockaddr *address, char *buffer, size_t size);
    static bool userid(const char *sipuri, char *buffer, size_t size);
    static bool hostid(const char *sipuri, char *buffer, size_t size);
    static unsigned short portid(const char *sipuri);
    static void identity(struct sockaddr *address, char *buffer, const char *user, size_t size);
    static void publish(const char *uri, char *buffer, const char *user, size_t size);
    static voip::context_t context(const char *uri);
};

class __EXPORT srv : protected Socket::address
{
public:
    class address
    {
    public:
	    struct sockaddr_storage addr;
	    uint16_t weight, priority;
    };

protected:
    address *srvlist;
    struct sockaddr *entry;
    uint16_t pri;
    unsigned count;

public:
    srv(const char *uri);
    srv();
    ~srv();

    void set(const char *uri);

    void clear(void);

    inline struct sockaddr *operator*() const
        {return entry;}

    inline operator bool() const
	    {return entry != NULL;}

    inline bool operator!() const
	    {return entry == NULL;}

    struct sockaddr *next(void);

    voip::context_t route(const char *uri, char *buf, size_t size);

};

} // namespace sipwitch

#endif
