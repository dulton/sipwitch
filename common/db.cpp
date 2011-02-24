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
#include <sipwitch/db.h>

#define     INDEX_KEYSIZE   177

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

class __LOCAL key : public LinkedObject
{
public:
    key(const char *keyid, const char *keyhash);

    const char *id;
    char *hash;
};

static memalloc cache;
static LinkedObject *paths[INDEX_KEYSIZE];
static condlock_t locking;

key::key(const char *keyid, const char *keyhash) :
LinkedObject(&paths[NamedObject::keyindex(keyid, INDEX_KEYSIZE)])
{
    id = cache.dup(keyid);
    hash = cache.dup(keyhash);
}

void digests::clear(void)
{
    locking.modify();
    memset(paths, 0, sizeof(paths));
    cache.purge();
    locking.commit();
}

const char *digests::get(const char *id)
{
    assert(id != NULL);

    locking.access();
    unsigned path = NamedObject::keyindex(id, INDEX_KEYSIZE);
    linked_pointer<key> keys = paths[path];
    while(is(keys)) {
        if(String::equal(id, keys->id))
            return keys->hash;
        keys.next();
    }
    locking.release();
    return NULL;
}

void digests::release(const char *id)
{
    if(id)
        locking.release();
}

bool digests::set(const char *id, const char *hash)
{
    assert(id != NULL && hash != NULL);

    caddr_t mp;
    size_t len = strlen(hash);

    locking.access();
    unsigned path = NamedObject::keyindex(id, INDEX_KEYSIZE);
    linked_pointer<key> keys = paths[path];
    while(is(keys)) {
        if(String::equal(id, keys->id)) {
            if(len == strlen(keys->hash)) {
                String::set(keys->hash, ++len, hash);
                locking.commit();
                return true;
            }
            return false;
        }
        keys.next();
    }
    mp = (caddr_t)cache.alloc(sizeof(key));
    new(mp) key(id, hash);
    locking.commit();
    return true;
}

void digests::load(void)
{
    FILE *fp = fopen(DEFAULT_VARPATH "/lib/sipwitch/digests.db", "r");
    char buffer[256];
    char *cp, *ep;

    if(!fp)
        return;

    while(NULL != fgets(buffer, sizeof(buffer), fp)) {
        if(feof(fp))
            break;

        cp = strchr(buffer, ':');
        if(!cp)
            continue;

        *(cp++) = 0;

        ep = strchr(cp, '\r');
        if(!ep)
            ep = strchr(cp, '\n');

        if(ep)
            *ep = 0;

        set(buffer, cp);
    }
    fclose(fp);
}

