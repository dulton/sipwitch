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

#include "server.h"
#include <signal.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static mempager mempool(PAGING_SIZE);
static bool running = true;

#ifdef	USES_COMMANDS
static void paddress(struct sockaddr_internet *a1, struct sockaddr_internet *a2)
{
	assert(a1 != NULL);

	char sep = '\n';
	char buf[64];
	unsigned len;
	unsigned p1 = 0, p2 = 0;

	if(!a1)
		return;

	Socket::getaddress((struct sockaddr *)a1, buf, sizeof(buf));
	len = strlen(buf);
	switch(a1->address.sa_family) {
	case AF_INET:
		p1 = (unsigned)ntohs(a1->ipv4.sin_port);
		break;
#ifdef	AF_INET6
	case AF_INET6:
		p1 = (unsigned)ntohs(a1->ipv6.sin6_port);
		break;
#endif
	}

	if(a2) {
		switch(a2->address.sa_family) {
		case AF_INET:
			p2 = (unsigned)ntohs(a2->ipv4.sin_port);
			break;
#ifdef	AF_INET6
		case AF_INET6:
			p2 = (unsigned)ntohs(a2->ipv6.sin6_port);
			break;
#endif
		}
	}

	if(a2 && p2)
		sep = ',';

	if(p1)
		printf("%s:%u%c", buf, p1, sep);
	else
		printf("none%c", sep);

	if(!a2 || !p2)
		return;

	Socket::getaddress((struct sockaddr *)a2, buf, sizeof(buf));
	printf("%s:%u\n", buf, p2);
}
#endif

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
	if(NULL == (reg = registry::create(args[1]))) {
		delete addr;
		return false;
	}
	time(&reg->created);
	if(!reg->setTargets(*addr))
		rtn = false;
	registry::detach(reg);
	service::activate(reg);
	delete addr;
	return rtn;
}

server::server(const char *id) :
service(id, PAGING_SIZE)
{
	assert(id != NULL && *id != 0);

	memset(keys, 0, sizeof(keys));
	acl = NULL;
}

unsigned server::forwarding(keynode *leaf)
{
	unsigned mask = 0;
	const char *cp;

	if(!leaf)
		return 0;

	cp = service::getValue(leaf, "all");
	if(cp && *cp)
		mask |= FWD_ALL_ENABLED;
	cp = service::getValue(leaf, "busy");
	if(cp && *cp)
		mask |= FWD_BUSY_ENABLED;
	cp = service::getValue(leaf, "bna");
	if(cp && *cp)
		mask |= FWD_BNA_ENABLED;
	cp = service::getValue(leaf, "dnd");
	if(cp && *cp)
		mask |= FWD_DND_ENABLED;
	cp = service::getValue(leaf, "away");
	if(cp && *cp)
		mask |= FWD_AWAY_ENABLED;
	cp = service::getValue(leaf, "public");
	if(cp && *cp)
		mask |= FWD_PUBLIC_ENABLED;

	return mask;
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

	keymap *map = (keymap *)alloc_locked(sizeof(keymap));
	unsigned path = NamedObject::keyindex(id, CONFIG_KEY_SIZE);
	
	if(find(id))
		return true;
	
	map->id = id;
	map->node = node;
	map->enlist(&keys[path]);
	return false;
}

bool server::confirm(const char *user)
{
	assert(user == NULL || *user != 0);

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
	const char *realm = registry::getRealm();
	unsigned prefix = registry::getPrefix();
	unsigned range = registry::getRange();
	unsigned number;
	string_t digest;
	const char *dirpath = ".";
	const char *fn;

	snprintf(buf, sizeof(buf), "- welcome prefix=%d range=%d", prefix, range);
	setHeader(buf);

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
	mp = (caddr_t)alloc_locked(sizeof(profile));
	ppd = new(mp) profile(&profiles);
	String::set(ppd->value.id, sizeof(ppd->value.id), "*");
	ppd->value.level = 1;
	ppd->value.features = USER_PROFILE_DEFAULT;
	
	mp = (caddr_t)alloc_locked(sizeof(profile));
	pp = new(mp) profile(&profiles);
	memcpy(&pp->value, &ppd->value, sizeof(profile_t));
	String::set(pp->value.id, sizeof(pp->value.id), "restricted");
	pp->value.level = 0;
	pp->value.features = USER_PROFILE_RESTRICTED;

#ifdef	_MSWINDOWS_
	char dbuf[256];
	unsigned len;
	GetEnvironmentVariable("APPDATA", dbuf, 192);
	len = strlen(dbuf);
	snprintf(dbuf + len, sizeof(dbuf) - len, "\\sipwitch\\users");
	fsys::open(dir, dbuf, fsys::ACCESS_DIRECTORY);
	if(is(dir))
		dirpath = dbuf;
	else {
		GetEnvironmentVariable("USERPROFILE", dbuf, 192);
		len = strlen(dbuf);
		snprintf(dbuf + len, sizeof(dbuf) - len, "\\gnutelephony\\sipusers");
		dirpath = dbuf;
		fsys::create(dir, dbuf, fsys::ACCESS_DIRECTORY, 0700);
	} 
#else
	if(user) {
		dirpath = DEFAULT_VARPATH "/lib/sipwitch";
		fsys::open(dir, dirpath, fsys::ACCESS_DIRECTORY);
		if(!dir)
			dirpath = DEFAULT_CFGPATH "/sipwitch.d";
	}		
	if(!is(dir))
		fsys::open(dir, dirpath, fsys::ACCESS_DIRECTORY);
#endif
	if(!stricmp(dirpath, "."))
		dirpath = getenv("PWD");
	process::errlog(DEBUG1, "scanning config from %s", dirpath);
	while(is(dir) && fsys::read(dir, filename, sizeof(filename)) > 0) {
		ext = strrchr(filename, '.');
		if(!ext || stricmp(ext, ".xml"))
			continue;
		snprintf(buf, sizeof(buf), "%s/%s", dirpath, filename);
		fp = fopen(buf, "r");
		fn = strrchr(buf, '/');
		if(fn)
			++fn;
		else
			fn = buf;
		if(fp) {
			if(!load(fp, provision))
				process::errlog(ERRLOG, "cannot load %s", fn);		
			else
				process::errlog(DEBUG1, "loaded %s", fn);
		}
	}

	fsys::close(dir);

	mp = (caddr_t)alloc_locked(sizeof(cidr));
	new(mp) cidr(&acl, "127.0.0.0/8", "loopback");

	mp = (caddr_t)alloc_locked(sizeof(cidr));
	new(mp) cidr(&acl, "::1", "loopback");

	node = access->getFirst();
	while(node) {
		id = node->getId();
		if(id && node->getPointer()) {
			mp = (caddr_t)alloc_locked(sizeof(cidr));
			new(mp) cidr(&acl, node->getPointer(), id);
		}
		node.next();
	}

	node = provision->getFirst();
	while(node) {
		number = 0;
		leaf = node->leaf("id");
		id = NULL;
		if(leaf)
			id = leaf->getPointer();

		if(leaf && !registry::isUserid(id))
			id = NULL;

		if(leaf && id && !strcmp(node->getId(), "profile")) {
			mp = (caddr_t)alloc_locked(sizeof(profile));
			pp = new(mp) profile(&profiles);
			memcpy(&pp->value, &ppd->value, sizeof(profile_t));
			String::set(pp->value.id, sizeof(pp->value.id), id);
			leaf = node->leaf("trs");
			if(leaf && leaf->getPointer())
				pp->value.level = atoi(leaf->getPointer());
			debug(2, "adding profile %s", id);
			if(!stricmp(id, "*"))
				ppd = pp;
		}
		else if(leaf && id) {
			id = leaf->getPointer();
			if(create(id, *node))
				process::errlog(WARN, "duplicate identity %s", id);
			else {
				debug(2, "adding %s %s", node->getId(), id);
				if(!stricmp(node->getId(), "reject"))
					registry::remove(id);
			}
			leaf = node->leaf("secret");
			if(leaf)
				secret = leaf->getPointer();
			if(leaf && secret && *secret && !node->leaf("digest")) {
				digest = (string_t)id + ":" + (string_t)realm + ":" + (string_t)secret;
				if(!stricmp(registry::getDigest(), "sha1"))
					digest::sha1(digest);
				else if(!stricmp(registry::getDigest(), "rmd160"))
					digest::rmd160(digest);
				else
					digest::md5(digest);
				if(digest[0]) {
					mp = (caddr_t)alloc_locked(sizeof(keynode));
					leaf = new(mp) keynode(node, (char *)"digest");
					leaf->setPointer(dup_locked(*digest));
				}
			}
			leaf = node->leaf("extension");
			if(leaf && range && leaf->getPointer())
				number = atoi(leaf->getPointer());
			if(number >= prefix && number < prefix + range)
				extmap[number - prefix] = *node;
		}
		node.next();	
	}
	return true;
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

void server::release(cidr *access)
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

cidr *server::getPolicy(struct sockaddr *addr)
{
	assert(addr != NULL);
	assert(cfg != NULL);

	cidr *policy;

	if(!cfg)
		return NULL;

	locking.access();
	policy = cidr::find(((server *)(cfg))->acl, addr);
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

void server::getExtension(const char *id, usernode& user)
{
	assert(id != NULL && *id != 0);
	assert(cfg != NULL);

	unsigned ext = atoi(id);
	unsigned range = registry::getRange();
	unsigned prefix = registry::getPrefix();
	server *cfgp;
	keynode *node = NULL;
	const char *cp;

	server::release(user);

	locking.access();
	cfgp = static_cast<server *>(cfg);
	if(!cfgp) {
		locking.release();
		return;
	}

	if(range && ext >= prefix && ext < prefix + range)
		node = cfgp->extmap[ext - range];
	if(!node) {
		node = cfgp->find(id);
		cp = NULL;
		if(node)
			cp = node->getPointer();
		if(!cp || !stricmp(cp, "route") || !stricmp(cp, "gateway"))
			node = NULL;
	}
	if(!node)
		locking.release();
	user.keys = node;
}

Socket::address *server::getContact(const char *uid)
{
	assert(uid != NULL && *uid != 0);
	assert(cfg != NULL);

	usernode user;

	getProvision(uid, user);
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
	keynode *routing;
	server *cfgp;
	const char *cp;

	if(!cfg)
		return NULL;

	locking.access();
	cfgp = static_cast<server*>(cfg);
	routing = cfgp->root.getLeaf("routing");
	if(!routing) {
		locking.release();
		return NULL;
	}

	node = routing->getFirst();
	while(node) {
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
	
unsigned server::getForwarding(const char *uid)
{
	assert(uid != NULL);

	usernode user;
	getProvision(uid, user);
	unsigned mask = forwarding(user.keys);
	
	server::release(user);
	return mask;
}

void server::getProvision(const char *uid, usernode& user)
{
	assert(uid != NULL && *uid != 0);
	assert(cfg != NULL);

	keynode *node;
	server *cfgp;
	unsigned range = registry::getRange();
	unsigned prefix = registry::getPrefix();
	unsigned ext = atoi(uid);

	server::release(user);

	locking.access();
	cfgp = static_cast<server*>(cfg);
	if(!cfgp) {
		locking.release();
		return;
	}
	node = cfgp->find(uid);
	if(!node && range && ext >= prefix && ext < prefix + range)
		node = cfgp->extmap[ext - prefix];
	if(!node)
		locking.release();
	user.keys = node;
}

void server::utils(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	FILE *fp = service::open(uid);
	const char *key = NULL, *value;
	linked_pointer<keynode> sp;

	cfg = new server("sipwitch");
	
	crit(cfg != NULL, "util has no config");

	if(fp)
		if(!cfg->load(fp)) {
			process::errlog(ERRLOG, "invalid config");
			delete cfg;
			return;
		}

	setenv("REALM", registry::getRealm(), 1);
	setenv("DIGEST", "md5", 1);
	sp = cfg->getList("registry");
	while(sp) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value && !strcmp(key, "realm"))
			setenv("REALM", value, 1);
		else if(key && value && !strcmp(key, "digest"))
			setenv("DIGEST", value, 1);
		sp.next();
	}
}

bool server::check(void)
{
	process::errlog(INFO, "checking config...");
	locking.modify();
	locking.commit();
	process::errlog(INFO, "checking components...");
	if(service::check()) {
		process::errlog(INFO, "checking complete");
		return true;
	}
	process::errlog(WARN, "checking failed");
	return false;
}

void server::dump(FILE *fp)
{
	assert(fp != NULL);
	assert(cfg != NULL);

	fprintf(fp, "Server:\n");
	fprintf(fp, "  allocated pages: %d\n", server::allocate());
	fprintf(fp, "  configure pages: %d\n", cfg->getPages());
	fprintf(fp, "  memory paging:   %d\n", PAGING_SIZE);
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
		
void server::reload(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	char buf[256];
	FILE *state = NULL;

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

	static server *reclaim = NULL;
	
	crit(cfgp != NULL, "reload without config");

	if(state) {
		process::errlog(DEBUG1, "pre-loading state configuration");
		if(!cfgp->load(state))
			process::errlog(ERRLOG, "invalid state");
	}

	FILE *fp = service::open(uid);
	if(fp)
		if(!cfgp->load(fp)) {
			process::errlog(ERRLOG, "invalid config");
			delete cfgp;
			return;
		}

	if(!cfgp->commit(uid)) {
		process::errlog(ERRLOG, "config rejected");
		if(reclaim) {
			locking.modify();
			delete reclaim;
			locking.commit();
		}
		reclaim = cfgp;
	}
	if(!cfg) {
		process::errlog(FAILURE, "no configuration");
		exit(2);
	}
	if(reclaim) {
		delete reclaim;
		reclaim = NULL;
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

#ifdef	_MSWINDOWS_
#define	DLL_SUFFIX	".dll"
#define	LIB_PREFIX	"_libs"
#else
#define	LIB_PREFIX	".libs"
#define	DLL_SUFFIX	".so"
#endif

void server::plugins(const char *argv0, const char *list)
{
	char buffer[256];
	char path[256];
	char *tp = NULL;
	char *ep;
	const char *cp;
	fsys	module;
	fsys	dir;
	unsigned el;

	if(!list || !*list || !stricmp(list, "none"))
		return;

	if(!stricmp(list, "auto")) {
		string::set(path, sizeof(path), argv0);
		ep = strstr(path, LIB_PREFIX + 1);
		if(ep)
			ep[strlen(LIB_PREFIX)] = 0;
		else 
			string::set(path, sizeof(path), DEFAULT_LIBPATH "/sipwitch");
		el = strlen(path);
		fsys::open(dir, path, fsys::ACCESS_DIRECTORY);
		while(is(dir) && fsys::read(dir, buffer, sizeof(buffer)) > 0) {
			ep = strrchr(buffer, '.');
			if(!ep || stricmp(ep, DLL_SUFFIX))
				continue;
			snprintf(path + el, sizeof(path) - el, "/%s", buffer);
			process::errlog(INFO, "loading %s", buffer);
			if(fsys::load(path)) 
				process::errlog(ERRLOG, "failed loading %s", path);
		}
		fsys::close(dir);
	}
	else {
		string::set(buffer, sizeof(buffer), list);
		while(NULL != (cp = string::token(buffer, &tp, ", ;:\r\n"))) {
			string::set(path, sizeof(path), argv0);
			ep = strstr(path, LIB_PREFIX + 1);
			if(ep) {
				ep[strlen(LIB_PREFIX)] = 0;
				string::add(path, sizeof(path), cp);
				string::add(path, sizeof(path), DLL_SUFFIX);
				if(fsys::isfile(path)) {
					process::errlog(INFO, "loading %s" DLL_SUFFIX " locally", cp);
					goto loader;
				}
			}
			snprintf(path, sizeof(path), DEFAULT_LIBPATH "/sipwitch/%s" DLL_SUFFIX, cp);
			process::errlog(INFO, "loading %s", path);
loader:
			if(fsys::load(path)) 
				process::errlog(ERRLOG, "failed loading %s", path);
		}
	}
}

void server::regdump(void)
{
#ifdef	USES_COMMANDS
	mapped_view<MappedRegistry> reg("sipwitch.regmap");
	unsigned count = reg.getCount();
	unsigned found = 0, index = 0;
	volatile const MappedRegistry *member;
	MappedRegistry buffer;
	time_t now;
	char ext[8], exp[8], use[8];
	const char *type;

	if(!count) {
		fprintf(stderr, "*** sipw: cannot access mapped registry\n");
		exit(-1);
	}

	time(&now);
	while(index < count) {
		member = reg(index++);
		do {	
			memcpy(&buffer, (const void *)member, sizeof(buffer));
		} while(memcmp(&buffer, (const void *)member, sizeof(buffer)));
		if(buffer.type == MappedRegistry::EXPIRED)
			continue;
		else if(buffer.type == MappedRegistry::TEMPORARY && !buffer.inuse)
			continue;
		if(!found++)
			printf("%7s %-30s type %-30s  use expires address\n", "ext", "user", "profile");
		ext[0] = 0;
		if(buffer.ext)
			snprintf(ext, sizeof(ext), "%7d", buffer.ext); 
		exp[0] = '-';
		exp[1] = 0;
		snprintf(use, sizeof(use), "%u", buffer.inuse);
		if(buffer.expires && buffer.type != MappedRegistry::TEMPORARY)
			snprintf(exp, sizeof(exp), "%ld", buffer.expires - now);
		switch(buffer.type) {
		case MappedRegistry::REJECT:
			type = "rej";
			break;
		case MappedRegistry::REFER:
			type = "ref";
			break;
		case MappedRegistry::GATEWAY:
			type = "gw";
			break;
		case MappedRegistry::SERVICE:
			type = "peer";
			break;
		case MappedRegistry::TEMPORARY:
			type = "temp";
			break;
		default:
			type = "user";
		};
		printf("%7s %-30s %-4s %-30s %4s %7s ", ext, buffer.userid, type, buffer.profile.id, use, exp);
		paddress(&buffer.contact, NULL);
		fflush(stdout);
	}

	printf("found %d entries active of %d\n", found, count);  
	exit(0);

#endif
}

void server::stop(void)
{
	running = false;
}

void server::run(const char *user)
{
	int argc;
	char *argv[65];
	char *state;
	char *cp, *tokens;
	static int exit_code = 0;
	time_t now;
	struct tm *dt, hold;
	FILE *fp;

	time(&now);
	dt = localtime_r(&now, &hold);
	if(dt->tm_year < 1900)
		dt->tm_year += 1900;

	process::printlog("server startup %04d-%02d-%02d %02d:%02d:%02d\n",
		dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
		dt->tm_hour, dt->tm_min, dt->tm_sec);

	while(running && NULL != (cp = process::receive())) {
		debug(9, "received request %s\n", cp);

        if(!stricmp(cp, "reload")) {
            reload(user);
            continue;
        }

		if(!stricmp(cp, "check")) {
			if(!check())
				process::reply("check failed");
			continue;
		}

        if(!stricmp(cp, "stop") || !stricmp(cp, "down") || !strcmp(cp, "exit"))
            break;

		if(!stricmp(cp, "restart")) {
			exit_code = SIGABRT;
			break;
		}

		if(!stricmp(cp, "snapshot")) {
			service::snapshot(user);
			continue;
		}

		if(!stricmp(cp, "dump")) {
			service::dumpfile(user);
			continue;
		}

		if(!stricmp(cp, "abort")) {
			abort();
			continue;
		}

		argc = 0;
		tokens = NULL;
		while(argc < 64 && NULL != (cp = const_cast<char *>(String::token(cp, &tokens, " \t", "{}")))) {
			printf("TOKEN %s\n", cp);
			argv[argc++] = cp;
		}
		argv[argc] = NULL;
		if(argc < 1)
			continue;

		if(!stricmp(argv[0], "verbose")) {
			if(argc > 2) {
invalid:
				process::reply("invalid argument");
				continue;
			}
			process::setVerbose(errlevel_t(atoi(argv[1])));
			continue;
		}

		if(!stricmp(argv[0], "address")) {
			if(argc != 2)
				goto invalid;
			state = String::unquote(argv[1], "\"\"\'\'()[]{}");
			rtpproxy::publish(state);
			process::errlog(NOTICE, "published address is %s", state);
			continue;
		}

		if(!stricmp(argv[0], "state")) {
			if(argc != 2)
				goto invalid;
			state = String::unquote(argv[1], "\"\"\'\'()[]{}");
			if(!service::state(state))
				process::reply("invalid state");
			fp = fopen(DEFAULT_VARPATH "/run/sipwitch/state.def", "w");
			if(fp) {
				fputs(state, fp);
				fclose(fp);
			}
			process::errlog(NOTICE, "state changed to %s", state);
			reload(user);
			continue;
		}

		if(!stricmp(argv[0], "concurrency")) {
			if(argc != 2)
				goto invalid;
			Thread::concurrency(atoi(argv[1]));
			continue;
		}

		if(!stricmp(argv[0], "message")) {
			if(argc != 3)
				goto invalid;
			messages::system(argv[1], argv[2]);
			continue;
		}

		if(!stricmp(argv[0], "activate")) {
			if(!activating(argc, argv))
				process::reply("cannot activate");
			continue;
		}

		if(!stricmp(argv[0], "release")) {
			if(argc != 2)
				goto invalid;
			if(!registry::remove(argv[1]))
				process::reply("cannot release");
			continue;
		}

		process::reply("unknown command");
	}
	time(&now);
	dt = localtime_r(&now, &hold);
	if(dt->tm_year < 1900)
		dt->tm_year += 1900;

	process::printlog("server shutdown %04d-%02d-%02d %02d:%02d:%02d\n",
		dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
		dt->tm_hour, dt->tm_min, dt->tm_sec);
}

void server::version(void)
{
	printf("SIP Witch " VERSION "\n"
        "Copyright (C) 2007-2008 David Sugar, Tycho Softworks\n"
		"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
		"This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n");
    exit(0);
}

void server::usage(void)
{
#if !defined(_MSWINDOWS_) && defined(USES_COMMANDS)
	printf("Usage: sipw [debug] [options] [command...]\n"
#elif defined(USES_COMMANDS)
	printf("Usage: sipw [options] [command...]\n"
#else
	printf("Usage: sipw [options]\n"
#endif
		"Options:\n"
		"  --help                Display this information\n"
		"  -foreground           Run server in foreground\n"
		"  -background           Run server as daemon\n"
#ifdef	_MSWINDOWS_
#else
		"  -restartable			 Run server as restartable daemon\n"
#endif
		"  -trace                Trace/dump sip messages\n"
		"  -config=<cfgfile>     Use cfgfile in place of default one\n"
#ifndef	_MSWINDOWS
		"  -plugins=<list>       List of plugins to load\n"
#endif
		"  -user=<userid>        Change to effective user from root\n" 
#ifndef	_MSWINDOWS_
		"  -concurrency=<level>  Increase thread concurrency\n"
#endif
		"  -priority=<level>     Increase process priority\n"
		"  -v[vv], -x<n>         Select verbosity or debug level\n"
#if defined(USES_COMMANDS) || defined(_MSWINDOWS_)
		"Commands:\n"
		"  stop                  Stop running server\n"
		"  reload                Reload config file\n"
#ifdef	_MSWINDOWS_
		"  register              Register as service deamon\n"
		"  release               Release service deamon registeration\n"
#endif
#endif
#ifdef	USES_COMMANDS
		"  restart               Restart server\n"
		"  address               Set published address\n"
		"  check                 Test for thread deadlocks\n"
		"  snapshot              Create snapshot file\n"
		"  dump                  Dump in-memory config tables\n"
		"  message <user> <text> Send instant message to user agent\n"
		"  digest <user> <pass>  Compute digest based on server realm\n"
		"  registry              List registrations from shared memory\n"
		"  state <level>         Set server running state\n"
		"  activate <user>       Activate static user registration\n"
		"  release <user>        Release registered user\n"
#endif
#if defined(USES_COMMANDS) && !defined(_MSWINDOWS_)
		"Debug Option:\n"
		"  -gdb                  Run server from gdb\n"
		"  -memcheck             Check for memory leaks with valgrind\n"
		"  -memleak              Find where leaks are with valgrind\n"
#endif
	);
	exit(0);
}

END_NAMESPACE
