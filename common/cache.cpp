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
#include <sipwitch/cache.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

#define USER_KEY_SIZE   177

static mempager cache_heap(16384);
static LinkedObject *user_freelist = NULL;
static condlock_t   user_lock;
static LinkedObject *user_keys[USER_KEY_SIZE];

Cache::Cache() :
LinkedObject()
{
    time(&created);
}

UserCache::UserCache() :
Cache()
{
}

void Cache::expire(LinkedObject **root, LinkedObject **freelist)
{
    Cache *prior = NULL;
    Cache *node = (Cache *)*root;
    Cache *next;
    time_t now;

    time(&now);

    while(node) {
        next = (Cache *)node->next;
        if(node->expires && now > node->expires) {
            if(!prior)
                *root = next;
            else
                prior->next = next;
            node->enlist(freelist);
        }
        else
            prior = node;
        node = next;
    }
}

void cache::init(void)
{
    memset(&user_keys, 0, sizeof(user_keys));
}

void cache::check(void)
{
    for(unsigned i = 0; i < USER_KEY_SIZE; ++i) {
        user_lock.modify();
        expire(&user_keys[i], &user_freelist);
        user_lock.release();
    }
}

UserCache *UserCache::request(const char *id)
{
    assert(id != NULL && *id != 0);

    linked_pointer<UserCache> up;
    unsigned path = NamedObject::keyindex(id, USER_KEY_SIZE);
    up = user_keys[path];
    while(up) {
        if(eq(up->userid, id))
            break;
        up.next();
    }
    return *up;
}

UserCache *UserCache::find(const char *id)
{
    time_t now;
    time(&now);

    user_lock.access();
    UserCache *cp = request(id);
    if(cp) {
        if(!cp->expires || cp->expires > now)
            return cp;
    }
    user_lock.release();
    return NULL;
}

void UserCache::release(UserCache *entry)
{
    if(entry)
        user_lock.release();
}

void UserCache::add(const char *id, struct sockaddr *addr, time_t create, unsigned expire)
{
    assert(id != NULL && *id != 0);

    unsigned path = NamedObject::keyindex(id, USER_KEY_SIZE);

    user_lock.modify();
    UserCache *cp = request(id);
    if(cp) {
        // only update if not trumped by existing entry...
        if(create >= cp->created)
            goto update;
        goto release;
    }

    if(user_freelist) {
        cp = (UserCache *)user_freelist;
        user_freelist = cp->next;
    }
    else
        cp = (UserCache *)cache_heap.alloc(sizeof(UserCache));

    cp->enlist(&user_keys[path]);
    String::set(cp->userid, sizeof(cp->userid), id);

update:
    cp->created = create;
    if(expire) {
        time(&cp->expires);
        cp->expires += expire;
    }
    else
        cp->expires = 0;
    cp->set(addr);

release:
    user_lock.release();
}
