// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015-2017 Cherokees of Idaho.
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

#include "server.h"

#define     INDEX_KEYSIZE   177

namespace sipwitch {

class __LOCAL key : public LinkedObject
{
public:
    key(const char *keyid, const char *keyhash);

    const char *id;
    char *hash;
};

static memalloc private_cache;
static LinkedObject *private_paths[INDEX_KEYSIZE];
static condlock_t private_lock;

key::key(const char *keyid, const char *keyhash) :
LinkedObject(&private_paths[NamedObject::keyindex(keyid, INDEX_KEYSIZE)])
{
    id = private_cache.dup(keyid);
    hash = private_cache.dup(keyhash);
}

void digests::reload(void)
{
    private_lock.modify();
    memset(private_paths, 0, sizeof(private_paths));
    private_cache.purge();
    private_lock.commit();
    load();
}

const char *digests::get(const char *id)
{
    assert(id != NULL);

    private_lock.access();
    unsigned path = NamedObject::keyindex(id, INDEX_KEYSIZE);
    linked_pointer<key> keys = private_paths[path];
    while(is(keys)) {
        if(String::equal(id, keys->id))
            return keys->hash;
        keys.next();
    }
    private_lock.release();
    return NULL;
}

void digests::release(const char *id)
{
    if(id)
        private_lock.release();
}

bool digests::set(const char *id, const char *hash)
{
    assert(id != NULL && hash != NULL);

    void *mp;
    size_t len = strlen(hash);

    private_lock.access();
    unsigned path = NamedObject::keyindex(id, INDEX_KEYSIZE);
    linked_pointer<key> keys = private_paths[path];
    while(is(keys)) {
        if(String::equal(id, keys->id)) {
            if(len == strlen(keys->hash)) {
                String::set(keys->hash, ++len, hash);
                private_lock.commit();
                return true;
            }
            return false;
        }
        keys.next();
    }
    mp = private_cache.alloc(sizeof(key));
    new(mp) key(id, hash);
    private_lock.commit();
    return true;
}

void digests::load(void)
{
    FILE *fp;
    char buffer[256];
    char *cp, *ep;

    dir::create(DEFAULT_VARPATH "/lib/sipwitch/digests", fsys::GROUP_PRIVATE);
    string_t path = str(DEFAULT_VARPATH "/lib/sipwitch/digests/") + registry::getRealm();
    fp = fopen(*path, "r");

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

} // end namespace
