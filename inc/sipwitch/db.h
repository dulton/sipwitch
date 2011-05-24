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
 * Compute cryptographic hashes and cipher memory.
 * This is used for the sipwitch database files such as the user digest
 * hashes, future user programmable speed dials, etc.
 * @file sipwitch/db.h
 */

#ifndef _SIPWITCH_DB_H_
#define _SIPWITCH_DB_H_

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef __SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

/**
 * Access to sipwitch database of user digests.  This is used as an
 * authentication database by user id and is most often used for sharing
 * sipwitch user ids with system logins.  SIP digest hashes include the
 * current sip realm.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT digests
{
public:
    /**
     * Clear out all digests.  This is needed when the realm is changed.
     */
    static void clear(void);

    /**
     * Lookup a digest for a specific user id.  If a string is returned,
     * the digest database is also locked, so that the contents of the
     * pointer cannot be modified by another thread.  You must use release()
     * after a get() when done with using the hash.
     * @param id of user to find.
     * @return digest string for given user or NULL if not found.
     */
    static const char *get(const char *id);

    /**
     * Set digest id for a given user.
     * @param id of user to set.
     * @param hash digest to store for given user.
     * @return true if saved.
     */
    static bool set(const char *id, const char *hash);

    /**
     * Used to release a hash digest that was acquired by get and unlock db.
     * @param hash digest we got.
     */
    static void release(const char *hash);

    /**
     * Load database file.
     */
    static void load(void);
};

END_NAMESPACE

#endif
