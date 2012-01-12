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
 * Manipulate address strings.
 * This is a utility class to help manipulate addresses and SIP uri's or
 * to resolve uri's into physical addresses.  SIP Witch prefers physical
 * (ip) addresses to avoid redundent dns lookups.  This is also placed in
 * common to better support plugin development.
 * @file sipwitch/uri.h
 */

#ifndef _SIPWITCH_CACHE_H_
#define _SIPWITCH_CACHE_H_

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef _UCOMMON_SOCKET_H_
#include <ucommon/socket.h>
#endif

#ifndef __SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

#ifndef __SIPWITCH_MAPPED_H_
#include <sipwitch/mapped.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

/**
 * URI cache for tags, local, and remote id's.  This is used by both the
 * server and plugin.  Cache entries are used to help resolve known names and
 * id's to related and remote sipwitch servers.
 */
class __EXPORT Cache : public LinkedObject
{
protected:
    Cache();

    static void expire(LinkedObject **list, LinkedObject **free);

public:
    time_t created;
    time_t expires;
};

/**
 * Cache management functions.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT cache : private Cache
{
public:
    static void init(void);
    static void cleanup(void);
    static void userdump(void);
};

/**
 * User caches may be used to contact nearby users in multicast registries.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT UserCache : public Cache
{
protected:
    UserCache();

    static UserCache *request(const char *id);

public:
    char userid[32];
    struct sockaddr_internet address;

    inline void set(struct sockaddr *addr)
        {memcpy(&address, addr, sizeof(address));};

    /**
     * Add or refresh user in cache.
     * @param id of user to update.
     * @param address of sipwitch peer who has this user.
     * @param create time of registration if multiple peers.
     * @param expire record in seconds.
     */
    static void add(const char *id, struct sockaddr *addr, time_t create, unsigned expire = 130);

    /**
     * Find user record.
     * @param id to find.
     * @return found cache entry.
     */
    static UserCache *find(const char *id);

    /**
     * Release a found user record.
     * @param entry to release or NULL if none.
     */
    static void release(UserCache *entry);
};

END_NAMESPACE

#endif
