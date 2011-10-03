// Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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
#include <signal.h>
#include <ctype.h>

#ifdef  HAVE_PWD_H
#include <pwd.h>
#include <grp.h>
#endif

#ifdef  HAVE_NET_IF_H
#include <net/if.h>
#include <arpa/inet.h>
#ifdef  HAVE_IOCTL_H
#include <ioctl.h>
#else
#include <sys/ioctl.h>
#endif
#endif

#ifdef  HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static mempager mempool(PAGING_SIZE);
static bool running = true;

static bool activating(int argc, char **args)
{
    assert(args != NULL);

    registry::mapped *reg;
    bool rtn = true;

    Socket::address *addr;
    if(argc < 2 || argc > 3)
        return false;
    if(argc == 3)
        addr = stack::getAddress(args[2]);
    else
        addr = server::getContact(args[1]);
    if(!addr)
        return false;
    if(NULL == (reg = registry::allocate(args[1]))) {
        delete addr;
        return false;
    }
    time(&reg->created);
    if(!reg->setTargets(*addr))
        rtn = false;
    server::activate(reg);
    registry::detach(reg);
    delete addr;
    return rtn;
}

unsigned server::uid = 1000;
const char *server::sipusers = "sipusers";
const char *server::sipadmin = "wheel";
shell::logmode_t server::logmode = shell::SYSTEM_LOG;
int server::exit_code = 0;

server::server(const char *id) :
service(id, PAGING_SIZE)
{
    assert(id != NULL && *id != 0);

    memset(keys, 0, sizeof(keys));
    acl = NULL;
}

const char *server::referRemote(MappedRegistry *rr, const char *target, char *buffer, size_t size)
{
    assert(target != NULL && *target != 0);
    assert(buffer != NULL);
    assert(size > 0);

    const char *refer = NULL;
    linked_pointer<modules::sipwitch> cb = getModules();

    if(!rr)
        return NULL;

    while(!refer && is(cb)) {
        refer = cb->referRemote(rr, target, buffer, size);
        cb.next();
    }
    return refer;
}

const char *server::referLocal(MappedRegistry *rr, const char *target, char *buffer, size_t size)
{
    assert(target != NULL && *target != 0);
    assert(buffer != NULL);
    assert(size > 0);

    const char *refer = NULL;
    linked_pointer<modules::sipwitch> cb = getModules();

    if(!rr)
        return NULL;

    while(!refer && is(cb)) {
        refer = cb->referLocal(rr, target, buffer, size);
        cb.next();
    }
    return refer;
}

bool server::authenticate(int id, const char *realm)
{
    linked_pointer<modules::sipwitch> cb = getModules();

    while(is(cb)) {
        if(cb->authenticate(id, realm))
            return true;
        cb.next();
    }
    return false;
}

void server::registration(int id, modules::regmode_t mode)
{
    linked_pointer<modules::sipwitch> cb = getModules();

    while(is(cb)) {
        cb->registration(id, mode);
        cb.next();
    }
}

void server::activate(MappedRegistry *rr)
{
    linked_pointer<modules::sipwitch> cb = getModules();
    logging(rr, "activating");

    events::activate(rr);

    while(is(cb)) {
        cb->activating(rr);
        cb.next();
    }
}

void server::expire(MappedRegistry *rr)
{
    linked_pointer<modules::sipwitch> cb = getModules();

    logging(rr, "releasing");

    while(is(cb)) {
        cb->expiring(rr);
        cb.next();
    }
    events::release(rr);
}

void server::logging(MappedRegistry *rr, const char *reason)
{
    DateTimeString dt;
    printlog("%s %s %s\n", reason, rr->userid, (const char *)dt);
}

bool server::announce(MappedRegistry *rr, const char *msgtype, const char *event, const char *expires, const char *body)
{
    linked_pointer<modules::sipwitch> cb = getModules();
    bool rtn = false;

    while(!rtn && is(cb)) {
        rtn = cb->announce(rr, msgtype, event, expires, body);
        cb.next();
    }
    return rtn;
}

service::keynode *server::find(const char *id)
{
    assert(id != NULL && *id != 0);

    unsigned path = NamedObject::keyindex(id, CONFIG_KEY_SIZE);
    linked_pointer<keymap> map = keys[path];

    while(map) {
        if(!stricmp(map->id, id))
            return map->node;
        map.next();
    }
    return NULL;
}

bool server::create(const char *id, keynode *node)
{
    assert(id != NULL && *id != 0);
    assert(node != NULL);

    keymap *map = (keymap *)alloc(sizeof(keymap));
    unsigned path = NamedObject::keyindex(id, CONFIG_KEY_SIZE);

    if(find(id))
        return true;

    map->id = id;
    map->node = node;
    map->enlist(&keys[path]);
    return false;
}

void server::confirm(void)
{
    fsys_t dir;
    keynode *access = getPath("access");
    char *id = NULL, *secret = NULL;
    const char *ext;
    linked_pointer<service::keynode> node;
    service::keynode *leaf;
    FILE *fp;
    char buf[128];
    char filename[65];
    caddr_t mp;
    profile *pp, *ppd;
    const char *state = root.getPointer();
    const char *realm = registry::getRealm();
    unsigned prefix = registry::getPrefix();
    unsigned range = registry::getRange();
    unsigned number;
    const char *dirpath = ".";
    const char *fn;
    digest_t digest = registry::getDigest();

    // add any missing keys
    getPath("devices");

    // construct default profiles

    provision = getPath("provision");
    extmap = NULL;
    if(range) {
        extmap = new keynode*[range];
        memset(extmap, 0, sizeof(keynode *) * range);
    }
    profiles = NULL;
    mp = (caddr_t)alloc(sizeof(profile));
    ppd = new(mp) profile(&profiles);
    String::set(ppd->value.id, sizeof(ppd->value.id), "*");
    ppd->value.level = 1;
    ppd->value.features = USER_PROFILE_DEFAULT;

    mp = (caddr_t)alloc(sizeof(profile));
    pp = new(mp) profile(&profiles);
    memcpy(&pp->value, &ppd->value, sizeof(profile_t));
    String::set(pp->value.id, sizeof(pp->value.id), "restricted");
    pp->value.level = 0;
    pp->value.features = USER_PROFILE_RESTRICTED;

    mp = (caddr_t)alloc(sizeof(profile));
    pp = new(mp) profile(&profiles);
    memcpy(&pp->value, &ppd->value, sizeof(profile_t));
    String::set(pp->value.id, sizeof(pp->value.id), "local");
    pp->value.level = 1;
    pp->value.features = USER_PROFILE_LOCAL;

    mp = (caddr_t)alloc(sizeof(profile));
    pp = new(mp) profile(&profiles);
    memcpy(&pp->value, &ppd->value, sizeof(profile_t));
    String::set(pp->value.id, sizeof(pp->value.id), "device");
    pp->value.level = 0;
    pp->value.features = USER_PROFILE_DEVICE;

    mp = (caddr_t)alloc(sizeof(profile));
    pp = new(mp) profile(&profiles);
    memcpy(&pp->value, &ppd->value, sizeof(profile_t));
    String::set(pp->value.id, sizeof(pp->value.id), "service");
    pp->value.level = 0;
    pp->value.features = USER_PROFILE_SERVICE;

    mp = (caddr_t)alloc(sizeof(profile));
    pp = new(mp) profile(&profiles);
    memcpy(&pp->value, &ppd->value, sizeof(profile_t));
    String::set(pp->value.id, sizeof(pp->value.id), "admin");
    pp->value.level = 9;
    pp->value.features = USER_PROFILE_ADMIN;

#ifdef  _MSWINDOWS_
    dirpath = _STR(control::path("prefix") + "\\users");
#else
    dirpath = control::env("users");    // /etc/sipwitch.d
    if(!dirpath)
        dirpath = control::env("prefix");
#endif
    fsys::open(dir, dirpath, fsys::ACCESS_DIRECTORY);
    shell::log(DEBUG1, "scanning config from %s", dirpath);
    while(is(dir) && fsys::read(dir, filename, sizeof(filename)) > 0) {
        ext = strrchr(filename, '.');
        if(!ext || !String::equal(ext, ".xml"))
            continue;
        if(state) {
            snprintf(buf, sizeof(buf), "%s/%s/%s", dirpath, state, filename);
            fp = fopen(buf, "r");
        }
        else
            fp = NULL;
        if(!fp) {
            snprintf(buf, sizeof(buf), "%s/%s", dirpath, filename);
            fp = fopen(buf, "r");
        }
        fn = strrchr(buf, '/');
        if(fn)
            ++fn;
        else
            fn = buf;
        if(fp) {
            if(!load(fp, provision))
                shell::log(shell::ERR, "cannot load %s", fn);
            else
                shell::log(DEBUG1, "loaded %s", fn);
        }
    }

    fsys::close(dir);

    mp = (caddr_t)alloc(sizeof(stack::subnet));
    new(mp) stack::subnet(&acl, "127.0.0.0/8", "loopback");

    mp = (caddr_t)alloc(sizeof(stack::subnet));
    new(mp) stack::subnet(&acl, "::1", "loopback");

    int ifcount = 0, index = 0;

#ifdef  HAVE_NET_IF_H
    char ifbuf[8192];
    struct ifconf ifc;
    struct ifreq *ifr;

    ifc.ifc_len = sizeof(ifbuf);
    ifc.ifc_buf = ifbuf;
    int ifd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if(ifd < 0)
        shell::log(shell::FAIL, "cannot access network");
    else if(ioctl(ifd, SIOCGIFCONF, &ifc) == -1) {
        ::close(ifd);
        ifd = -1;
        shell::log(shell::ERR, "cannot list interfaces");
    }
    if(ifd > 0)
        ifcount = ifc.ifc_len / sizeof(ifreq);

    while(index < ifcount) {
        ifr = &ifc.ifc_req[index++];
        if(ifr->ifr_addr.sa_family != AF_INET)
            continue;
        struct sockaddr_in *saddr = (struct sockaddr_in *)&(ifr->ifr_addr);
        snprintf(buf, sizeof(buf), "%s/", inet_ntoa(saddr->sin_addr));
        if(ioctl(ifd, SIOCGIFNETMASK, ifr) == 0) {
            saddr = (struct sockaddr_in *)&(ifr->ifr_addr);
            String::add(buf, sizeof(buf), inet_ntoa(saddr->sin_addr));
            mp = (caddr_t)alloc(sizeof(stack::subnet));
            new(mp) stack::subnet(&acl, buf, ifr->ifr_name);
        }
    }
    ::close(ifd);
#endif

    node = access->getFirst();
    while(node) {
        id = node->getId();
        leaf = NULL;
        if(id && node->getPointer()) {
            mp = (caddr_t)alloc(sizeof(stack::subnet));
            new(mp) stack::subnet(&acl, node->getPointer(), id);
        }
        node.next();
    }

    node = provision->getFirst();
    while(is(node)) {
        number = 0;
        leaf = node->leaf("id");
        id = NULL;
        if(leaf)
            id = leaf->getPointer();

        if(leaf && !registry::isUserid(id))
            id = NULL;

        if(leaf && id && !strcmp(node->getId(), "profile")) {
            mp = (caddr_t)alloc(sizeof(profile));
            pp = new(mp) profile(&profiles);
            memcpy(&pp->value, &ppd->value, sizeof(profile_t));
            String::set(pp->value.id, sizeof(pp->value.id), id);
            leaf = node->leaf("trs");
            if(leaf && leaf->getPointer())
                pp->value.level = atoi(leaf->getPointer());
            shell::debug(2, "adding profile %s", id);
            if(!stricmp(id, "*"))
                ppd = pp;
        }
        else if(leaf && id) {
            id = leaf->getPointer();
            if(create(id, *node)) {
                shell::log(shell::WARN, "duplicate identity %s", id);
                node->setPointer((char *)"duplicate");
            }
            else {
                shell::debug(2, "adding %s %s", node->getId(), id);
                if(!stricmp(node->getId(), "reject"))
                    registry::remove(id);
            }
            leaf = node->leaf("secret");
            if(leaf)
                secret = leaf->getPointer();
            if(leaf && secret && *secret && !node->leaf("digest")) {
                if(digest.puts((string_t)id + ":" + (string_t)realm + ":" + (string_t)secret)) {
                    mp = (caddr_t)alloc(sizeof(keynode));
                    leaf = new(mp) keynode(node, (char *)"digest");
                    leaf->setPointer(dup(*digest));
                }
                digest.reset();
            }
            leaf = node->leaf("extension");
            if(leaf && range && leaf->getPointer())
                number = atoi(leaf->getPointer());
            if(number >= prefix && number < prefix + range)
                extmap[number - prefix] = *node;
        }
        node.next();
    }

#ifdef  HAVE_PWD_H
    ifcount = 0;
    char *member;
    const char *tempname;
    keynode *base = getPath("accounts");
    keyclone *clone, *entry;
    linked_pointer<keynode> temp;
    char *cp;

    struct passwd *pwd;
    struct group *grp = NULL;

    if(sipusers)
        grp = getgrnam(sipusers);

    // if no separated privilege, then use sipadmin
    if(!grp)
        grp = getgrnam(sipadmin);

    if(grp && !grp->gr_mem)
        goto final;

    if(uid || grp)
        shell::log(DEBUG1, "scanning users and groups");

    // if no groups at all, try to add base user if enabled....
    // this allows fully automated service for primary desktop user...
    if(!grp && uid) {
        pwd = getpwuid(uid);
        if(!pwd)
            return;
        leaf = addNode(base, "user", NULL);
        addNode(leaf, "id", pwd->pw_name);
    }
    else while(NULL != (member = grp->gr_mem[ifcount++])) {
        leaf = addNode(base, "user", NULL);
        addNode(leaf, "id", member);
    }

    grp = getgrnam(sipadmin);

    node = base->getFirst();
    while(is(node)) {
        ifcount = 0;
        id = NULL;
        leaf = node->leaf("id");
        if(leaf && leaf->getPointer())
            id = leaf->getPointer();

        pwd = NULL;
        if(id)
            pwd = getpwnam(id);

        if(!pwd) {
            node->setPointer((char *)"invalid");
            goto skip;
        }

        if(create(id, *node)) {
            node->setPointer((char *)"duplicate");
            goto skip;
        }

        id = pwd->pw_gecos;

        cp = strchr(id, ',');
        if(cp)
            *(cp++) = 0;
        addNode(*node, "display", id);

        // add extension node only if prefix is used...
        if(prefix && range) {
            if(cp)
                number = atoi(cp);
            else
                number = 0;
            if(!number && pwd->pw_uid >= uid && uid > 0)
                number = pwd->pw_uid - uid + prefix;

            if(number >= prefix && number < prefix + range && extmap[number - prefix] == NULL)
                extmap[number - prefix] = *node;

            if(number) {
                snprintf(buf, 16, "%d", number);
                addNode(*node, "extension", buf);
            }
        }

        entry = (keyclone *)(*node);
        ifcount = 0;
        tempname = "templates.user";
        while(grp && grp->gr_mem && NULL != (member = grp->gr_mem[ifcount++])) {
            if(String::equal(member, pwd->pw_name)) {
                tempname = "templates.admin";
                entry->reset("admin");
                break;
            }
        }

        shell::debug(2, "adding %s %s", node->getId(), pwd->pw_name);

        clone = (keyclone *)getPath(tempname);
        if(!clone)
            goto skip;

        temp = clone->getFirst();
        while(is(temp)) {
            clone = (keyclone *)alloc(sizeof(keynode));
            memcpy(clone, *temp, sizeof(keynode));
            clone->splice(entry);
            temp.next();
        }

skip:
        node.next();
    }

final:
    endpwent();
    endgrent();
#endif
}

void server::release(keynode *node)
{
    if(node)
        locking.release();
}

void server::release(usernode& user)
{
    if(user.heap)
        delete user.heap;
    else
        service::release(user.keys);

    user.keys = NULL;
    user.heap = NULL;
}

void server::release(stack::subnet *access)
{
    if(access)
        locking.release();
}

bool server::isLocal(struct sockaddr *addr)
{
    bool rtn = false;

    assert(addr != NULL);
    assert(cfg != NULL);
    cidr *access = getPolicy(addr);
    if(access) {
        rtn = true;
        locking.release();
    }
    return rtn;
}

stack::subnet *server::getSubnet(const char *id)
{
    locking.access();

    linked_pointer<stack::subnet> np = (((server *)(cfg))->acl);

    while(is(np)) {
        if(String::equal(np->getId(), id))
            return *np;
        np.next();
    }
    locking.release();
    return NULL;
}

stack::subnet *server::getPolicy(struct sockaddr *addr)
{
    assert(addr != NULL);
    assert(cfg != NULL);

    stack::subnet *policy;

    if(!cfg)
        return NULL;

    locking.access();
    policy = (stack::subnet *)cidr::find(((server *)(cfg))->acl, addr);
    if(!policy)
        locking.release();
    return policy;
}

profile_t *server::getProfile(const char *pro)
{
    assert(pro != NULL);
    assert(cfg != NULL);

    server *cfgp;
    linked_pointer<profile> pp;
    profile_t *ppd = NULL;

    cfgp = static_cast<server*>(cfg);
    if(!cfgp) {
        return NULL;
    }
    pp = cfgp->profiles;
    while(pp) {
        // we depend on default always being last...
        if(!ppd && !stricmp(pp->value.id, "*"))
            ppd = &pp->value;
        if(!stricmp(pp->value.id, pro))
            break;
        pp.next();
    }
    if(!ppd && !*pp) {
        return NULL;
    }
    if(pp)
        return &(pp->value);
    return ppd;
}

service::keynode *server::getConfig(void)
{
    locking.access();
    if(!cfg) {
        locking.release();
        return NULL;
    }

    return (keynode *)cfg;
}

Socket::address *server::getContact(const char *cuid)
{
    assert(cuid != NULL && *cuid != 0);
    assert(cfg != NULL);

    usernode user;

    getProvision(cuid, user);
    Socket::address *addr = NULL;

    if(!user.keys)
        return NULL;

    service::keynode *node = user.keys->leaf("contact");
    if(node)
        addr = stack::getAddress(node->getPointer());
    server::release(user);
    return addr;
}

service::keynode *server::getRouting(const char *id)
{
    assert(id != NULL && *id != 0);
    assert(cfg != NULL);

    linked_pointer<keynode> node;
    const char *cp;

    // never re-route in-dialing nodes...

    if(registry::isExtension(id))
        return NULL;

    if(!cfg)
        return NULL;

    locking.access();
    node = cfg->getList("routing");
    while(is(node)) {
        cp = getValue(*node, "pattern");
        if(cp && match(id, cp, false))
            return *node;
        // we can use fixed identities instead of patterns...
        cp = getValue(*node, "identity");
        if(cp && !stricmp(cp, id))
            return *node;
        node.next();
    }
    locking.release();
    return NULL;
}

bool server::checkId(const char *cuid)
{
    assert(cuid != NULL && *cuid != 0);
    assert(cfg != NULL);
    keynode *node = NULL;
    server *cfgp;

    locking.access();
    cfgp = static_cast<server*>(cfg);
    if(!cfgp) {
        locking.release();
        return false;
    }
    node = cfgp->find(cuid);
    locking.release();
    if(node)
        return true;
    return false;
}

void server::getDialing(const char *cuid, usernode& user)
{
    assert(cuid != NULL && *cuid != 0);
    assert(cfg != NULL);

    keynode *leaf = NULL;
    keynode *node;
    server *cfgp;
    unsigned range = registry::getRange();
    unsigned prefix = registry::getPrefix();
    unsigned ext = atoi(cuid);

    server::release(user);

    locking.access();
    cfgp = static_cast<server*>(cfg);
    if(!cfgp) {
        locking.release();
        return;
    }
    node = cfgp->find(cuid);
    if(node)
        leaf = node->leaf("extension");
    if(node && leaf && service::dialmode == service::EXT_DIALING)
        node = NULL;

    if(!node && service::dialmode != service::USER_DIALING && range && ext >= prefix && ext < prefix + range)
        node = cfgp->extmap[ext - prefix];

    if(!node)
        locking.release();
    user.keys = node;
}

void server::getProvision(const char *cuid, usernode& user)
{
    assert(cuid != NULL && *cuid != 0);
    assert(cfg != NULL);

    keynode *node;
    server *cfgp;
    unsigned range = registry::getRange();
    unsigned prefix = registry::getPrefix();
    unsigned ext = atoi(cuid);

    server::release(user);

    locking.access();
    cfgp = static_cast<server*>(cfg);
    if(!cfgp) {
        locking.release();
        return;
    }
    node = cfgp->find(cuid);
    if(!node && range && ext >= prefix && ext < prefix + range)
        node = cfgp->extmap[ext - prefix];
    if(!node)
        locking.release();
    user.keys = node;
}

bool server::check(void)
{
    shell::log(shell::INFO, "checking config...");
    locking.modify();
    locking.commit();
    shell::log(shell::INFO, "checking components...");
    if(service::check()) {
        shell::log(shell::INFO, "checking complete");
        return true;
    }
    shell::log(shell::WARN, "checking failed");
    return false;
}

void server::dump(FILE *fp)
{
    assert(fp != NULL);
    assert(cfg != NULL);

    fprintf(fp, "Server:\n");
    fprintf(fp, "  allocated pages: %d\n", server::allocate());
    fprintf(fp, "  configure pages: %d\n", cfg->getPages());
    fprintf(fp, "  memory paging:   %ld\n", (long)PAGING_SIZE);
    keynode *reg = getPath("registry");
    if(reg && reg->getFirst()) {
        fprintf(fp, "  registry keys:\n");
        service::dump(fp, reg->getFirst(), 4);
    }
    reg = getPath("sip");
    if(reg && reg->getFirst()) {
        fprintf(fp, "  sip stack keys:\n");
        service::dump(fp, reg->getFirst(), 4);
    }
}

void server::reload(void)
{
    char buf[256];
    FILE *state = NULL;
    const char *cp;

#ifdef _MSWINDOWS_
    GetEnvironmentVariable("APPDATA", buf, 192);
    unsigned len = strlen(buf);
    snprintf(buf + len, sizeof(buf) - len, "\\sipwitch\\state.xml");
    state = fopen(buf, "r");
#else
    snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch/state.xml");
    state = fopen(buf, "r");
#endif

    server *cfgp = new server("sipwitch");

    crit(cfgp != NULL, "reload without config");

    if(state) {
        shell::log(DEBUG1, "pre-loading state configuration");
        if(!cfgp->load(state))
            shell::log(shell::ERR, "invalid state");
    }

    FILE *fp = fopen(control::env("config"), "r");
    if(fp)
        if(!cfgp->load(fp)) {
            shell::log(shell::ERR, "invalid config %s", control::env("config"));
            delete cfgp;
            return;
        }

    shell::log(shell::NOTIFY, "loaded config from %s", control::env("config"));
    cp = cfgp->root.getPointer();
    if(cp)
        shell::log(shell::INFO, "activating for state \"%s\"", cp);

    cfgp->commit();
    if(!cfg) {
        shell::log(shell::FAIL, "no configuration");
        exit(2);
    }
}

unsigned server::allocate(void)
{
    return mempool.getPages();
}

caddr_t server::allocate(size_t size, LinkedObject **list, volatile unsigned *count)
{
    assert(size > 0);
    caddr_t mp;
    if(list && *list) {
        mp = (caddr_t)*list;
        *list = (*list)->getNext();
    }
    else {
        if(count)
            ++(*count);
        mp = (caddr_t)mempool.alloc(size);
    }
    memset(mp, 0, size);
    return mp;
}

#ifdef  _MSWINDOWS_
#define LIB_PREFIX  "_libs"
#else
#define LIB_PREFIX  ".libs"
#endif

void server::plugins(const char *prefix, const char *list)
{
    char buffer[256];
    char path[256];
    char *tp = NULL;
    const char *cp;
    fsys    module;
    fsys    dir;
    char *ep;
    unsigned el;

    if(!list || !*list || !stricmp(list, "none"))
        return;

    if(case_eq(list, "auto") || case_eq(list, "all")) {
        String::set(path, sizeof(path), prefix);
        el = strlen(path);
        fsys::open(dir, path, fsys::ACCESS_DIRECTORY);
        while(is(dir) && fsys::read(dir, buffer, sizeof(buffer)) > 0) {
            ep = strrchr(buffer, '.');
            if(!ep || !case_eq(ep, MODULE_EXT))
                continue;
            if(case_eq(buffer, "lib", 3))
                continue;
            snprintf(path + el, sizeof(path) - el, "/%s", buffer);
            shell::log(shell::INFO, "loading %s%s", buffer, MODULE_EXT);
            if(fsys::load(path))
                shell::log(shell::ERR, "failed loading %s", path);
        }
        fsys::close(dir);
    }
    else {
        String::set(buffer, sizeof(buffer), list);
        while(NULL != (cp = String::token(buffer, &tp, ", ;:\r\n"))) {
            snprintf(path, sizeof(path), "%s/%s%s", prefix, cp, MODULE_EXT);
            shell::log(shell::INFO, "loading %s" MODULE_EXT, cp);
            if(fsys::load(path))
                shell::log(shell::ERR, "failed loading %s", path);
        }
    }
}

void server::stop(void)
{
    running = false;
}

void server::run(void)
{
    int argc;
    char *argv[65];
    char *state;
    char *cp, *tokens;
    FILE *fp;

    DateTimeString logtime;

    // initial load of digest cache
    digests::load();

    printlog("server starting %s\n", (const char *)logtime);

    while(running && NULL != (cp = control::receive())) {
        shell::debug(9, "received request %s\n", cp);

        logtime.set();

        if(ieq(cp, "reload")) {
            printlog("server reloading %s\n", (const char *)logtime);
            reload();
            continue;
        }

        if(ieq(cp, "check")) {
            if(!check())
                control::reply("check failed");
            continue;
        }

        if(ieq(cp, "stop") || ieq(cp, "down") || ieq(cp, "exit"))
            break;

        if(ieq(cp, "restart")) {
            exit_code = SIGABRT;
            break;
        }

        if(ieq(cp, "snapshot")) {
            service::snapshot();
            continue;
        }

        if(ieq(cp, "dump")) {
            service::dumpfile();
            continue;
        }

        if(ieq(cp, "siplog")) {
            FILE *out = control::output(NULL);
            if(!out)
                continue;
            FILE *log = fopen(control::env("siplogs"), "r");
            if(!log) {
                fclose(out);
                continue;
            }

            char buf[256];

            while(fgets(buf, sizeof(buf), log) != NULL) {
                cp = String::strip(buf, " \t\r\n");
                fprintf(out, "%s\n", cp);
            }
            fclose(out);
            fclose(log);
            continue;
        }

        if(ieq(cp, "abort")) {
            abort();
            continue;
        }

        argc = 0;
        tokens = NULL;
        while(argc < 64 && NULL != (cp = const_cast<char *>(String::token(cp, &tokens, " \t", "{}")))) {
            argv[argc++] = cp;
        }
        argv[argc] = NULL;
        if(argc < 1)
            continue;

        if(ieq(argv[0], "ifup")) {
            if(argc != 2)
                goto invalid;
            printlog("server reloading %s\n", (const char *)logtime);
            reload();
            continue;
        }

        if(ieq(argv[0], "ifdown")) {
            if(argc != 2)
                goto invalid;
            printlog("server reloading %s\n", (const char *)logtime);
            reload();
            continue;
        }

        if(ieq(argv[0], "drop")) {
            if(argc != 2)
                goto invalid;
            continue;
        }

        if(ieq(argv[0], "trace")) {
            if(argc != 2)
                goto invalid;
            if(!stricmp(argv[1], "on"))
                stack::enableDumping();
            else if(!stricmp(argv[1], "off"))
                stack::disableDumping();
            else if(!stricmp(argv[1], "clear"))
                stack::clearDumping();
            else
                goto invalid;
            continue;
        }

        if(ieq(argv[0], "uid")) {
            if(argc != 2) {
invalid:
                control::reply("invalid argument");
                continue;
            }
            server::uid = atoi(argv[1]);
            printlog("uid %d %s\n", server::uid, (const char *)logtime);
            reload();
            continue;
        }

        if(ieq(argv[0], "history")) {
            if(argc > 2)
                goto invalid;
            else if(argc == 2)
                history::set(atoi(argv[1]));
            else
                history::out();
            continue;
        }

        if(ieq(argv[0], "verbose")) {
            if(argc != 2)
                goto invalid;

            shell::log("sipwitch", (shell::loglevel_t)(atoi(argv[1])), logmode);            continue;
        }

        if(ieq(argv[0], "digest")) {
            if(argc != 3)
                goto invalid;

            if(!digests::set(argv[1], argv[2]))
                control::reply("invalid digest");
            continue;
        }

        if(ieq(argv[0], "realm")) {
            if(argc != 2)
                goto invalid;

            printlog("realm %s %s\n", argv[1], (const char *)logtime);
            reload();
            continue;
        }

        if(ieq(argv[0], "period")) {
            if(argc != 2)
                goto invalid;
            if(service::period(atol(argv[1])))
                printlog("server period %s\n", (const char *)logtime);
            continue;
        }

        if(ieq(argv[0], "address")) {
            if(argc != 2)
                goto invalid;
            state = String::unquote(argv[1], "\"\"\'\'()[]{}");
            service::publish(state);
            shell::log(shell::NOTIFY, "published address is %s", state);
            continue;
        }

        if(ieq(argv[0], "state")) {
            if(argc != 2)
                goto invalid;
            state = String::unquote(argv[1], "\"\"\'\'()[]{}");
            if(!control::state(state))
                control::reply("invalid state");
            fp = fopen(DEFAULT_VARPATH "/run/sipwitch/state.def", "w");
            if(fp) {
                fputs(state, fp);
                fclose(fp);
            }
            printlog("state %s %s\n", state, (const char *)logtime);
            shell::log(shell::NOTIFY, "state changed to %s", state);
            events::state(state);
            reload();
            continue;
        }

        if(ieq(argv[0], "concurrency")) {
            if(argc != 2)
                goto invalid;
            Thread::concurrency(atoi(argv[1]));
            continue;
        }

        if(ieq(argv[0], "message")) {
            if(argc != 3)
                goto invalid;
            if(messages::system(argv[1], argv[2]) != SIP_OK)
                control::reply("cannot message");
            continue;
        }

        if(ieq(argv[0], "activate")) {
            if(!activating(argc, argv))
                control::reply("cannot activate");
            continue;
        }

        if(ieq(argv[0], "release")) {
            if(argc != 2)
                goto invalid;
            if(!registry::remove(argv[1]))
                control::reply("cannot release");
            continue;
        }

        control::reply("unknown command");
    }

    logtime.set();
    printlog("server shutdown %s\n", (const char *)logtime);
}

void server::printlog(const char *fmt, ...)
{
    assert(fmt != NULL && *fmt != 0);

    fsys_t log;
    va_list vargs;
    char buf[1024];
    int len;
    char *cp;

    va_start(vargs, fmt);

    fsys::create(log, control::env("logfile"), fsys::ACCESS_APPEND, 0660);
    vsnprintf(buf, sizeof(buf) - 1, fmt, vargs);
    len = strlen(buf);
    if(buf[len - 1] != '\n')
        buf[len++] = '\n';

    if(is(log)) {
        fsys::write(log, buf, strlen(buf));
        fsys::close(log);
    }
    cp = strchr(buf, '\n');
    if(cp)
        *cp = 0;

    shell::debug(2, "logfile: %s", buf);
    va_end(vargs);
}

END_NAMESPACE
