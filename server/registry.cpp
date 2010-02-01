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

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile unsigned active_routes = 0;
static volatile unsigned active_entries = 0;
static volatile unsigned active_targets = 0;
static volatile unsigned published_routes = 0;
static volatile unsigned allocated_routes = 0;
static volatile unsigned allocated_targets = 0;
static volatile unsigned allocated_entries = 0;
static unsigned mapped_entries = 999;

static unsigned keysize = 177;
static registry::mapped **extmap = NULL;
static LinkedObject **addresses = NULL;
static LinkedObject **publishing = NULL;
static LinkedObject **contacts = NULL;
static LinkedObject **primap = NULL;
static LinkedObject *freeroutes = NULL;
static LinkedObject *freetargets = NULL;
static LinkedObject **keys = NULL;
static condlock_t locking;
static stats *statmap = NULL;
static LinkedObject *freelist = NULL;

registry registry::reg;

registry::pointer::pointer()
{
	entry = NULL;
}

registry::pointer::pointer(const char *id)
{
	assert(id != NULL && *id != 0);

	entry = registry::access(id);
}

registry::pointer::pointer(pointer const &copy)
{
	entry = copy.entry;
	locking.access();
}

registry::pointer::~pointer()
{
	registry::detach(entry);
}

void registry::pointer::operator=(mapped *rr)
{
	registry::detach(entry);
	entry = rr;
}

void *registry::target::operator new(size_t size)
{
	assert(size == sizeof(registry::target));

	++active_targets;
	return server::allocate(size, &freetargets, &allocated_targets);
}

void registry::target::operator delete(void *obj)
{
	assert(obj != NULL);

	((LinkedObject*)(obj))->enlist(&freetargets);
	--active_targets;
}

void *registry::route::operator new(size_t size)
{
	assert(size == sizeof(registry::route));

	++active_routes;
	return server::allocate(size, &freeroutes, &allocated_routes);
}

void registry::route::operator delete(void *obj)
{
	assert(obj != NULL);

	((LinkedObject*)(obj))->enlist(&freeroutes);
	--active_routes;
}

registry::registry() :
service::callback(0), mapped_array<MappedRegistry>()
{
	prefix = 100;
	range = 600;
	expires = 300l;
	routes = 10;
}

const char *registry::getDomain(void)
{
	if(!strchr(reg.realm, '.'))
		return NULL;

	if(strchr(reg.realm, ' '))
		return NULL;

	return reg.realm;
}

void registry::incUse(mapped *rr, stats::stat_t stat)
{
	if(rr) {
		Mutex::protect(rr);
		++rr->inuse;
		Mutex::release(rr);
		switch(rr->type) {
		case MappedRegistry::EXTERNAL:
			if(rr->external.statnode) {
				rr->external.statnode->assign(stat);
				break;
			}
			statmap[5].assign(stat);
			break;
		case MappedRegistry::GATEWAY:
			statmap[3].assign(stat);
			break;
		case MappedRegistry::SERVICE:
			statmap[2].assign(stat);
			break;
		default:
			statmap[1].assign(stat);
		} 
	}
	else
		statmap[4].assign(stat);
}

void registry::decUse(mapped *rr, stats::stat_t stat)
{
	if(rr) {
		Mutex::protect(rr);
		--rr->inuse;
		Mutex::release(rr);
		switch(rr->type) {
		case MappedRegistry::EXTERNAL:
			if(rr->external.statnode) {
				rr->external.statnode->release(stat);
				break;
			}
			statmap[5].release(stat);
			break;
		case MappedRegistry::GATEWAY:
			statmap[3].release(stat);
			break;
		case MappedRegistry::SERVICE:
			statmap[2].release(stat);
			break;
		default:
			statmap[1].release(stat);
		}
	}
	else
		statmap[4].release(stat);
}

registry::mapped *registry::find(const char *id)
{
	assert(id != NULL && *id != 0);

	linked_pointer<mapped> rp;
	unsigned path = NamedObject::keyindex(id, keysize);
	if(!keys)
		return NULL;
	rp = keys[path];
	while(rp) {
		if(!strcmp(rp->userid, id))
			break;
		rp.next();
	}
	return *rp;
}

unsigned registry::getIndex(mapped *rr)
{
	assert((caddr_t)rr >= reg.getStart());

	unsigned x = (unsigned)(((caddr_t)rr - reg.getStart()) / sizeof(MappedRegistry));
	return x;
}

void registry::start(service *cfg)
{
	assert(cfg != NULL);

	process::errlog(DEBUG1, "registry starting; mapping %d entries", mapped_entries);
	create(REGISTRY_MAP, mapped_entries);
	if(!reg)
		process::errlog(FAILURE, "registry could not be mapped");
	initialize();
	statmap = stats::create();
}

bool registry::check(void)
{
	process::errlog(INFO, "checking registry...");
	locking.modify();
	locking.commit();
	return true;
}

void registry::stop(service *cfg)
{
	assert(cfg != NULL);

	process::errlog(DEBUG1, "registry stopping");
	MappedMemory::release();
	MappedMemory::remove(REGISTRY_MAP);
}

void registry::snapshot(FILE *fp) 
{
	assert(fp != NULL);

	mapped *rr;
	unsigned regcount = 0;
	time_t now;
	linked_pointer<target> tp;
	linked_pointer<route> rp;
	char buffer[128];

	locking.access();
	fprintf(fp, "Registry:\n"); 
	fprintf(fp, "  mapped entries: %d\n", mapped_entries);
	fprintf(fp, "  active entries: %d\n", active_entries);
	fprintf(fp, "  active routes:  %d\n", active_routes);
	fprintf(fp, "  active targets: %d\n", active_targets);
	fprintf(fp, "  published routes:  %d\n", published_routes);
	fprintf(fp, "  allocated routes:  %d\n", allocated_routes);
	fprintf(fp, "  allocated targets: %d\n", allocated_targets);
	fprintf(fp, "  allocated entries: %d\n", allocated_entries);

	while(regcount < mapped_entries) {
		time(&now);
		rr = static_cast<mapped*>(reg(regcount++));
		if(rr->type == MappedRegistry::TEMPORARY) {
			fprintf(fp, "  temp %s; use=%d\n", rr->userid, rr->inuse);
		}
		else if(rr->type != MappedRegistry::EXPIRED && (!rr->expires || rr->expires >= now)) {
			if(rr->ext)
				snprintf(buffer, sizeof(buffer), "%d", rr->ext);
			else
				String::set(buffer, sizeof(buffer), "none");
			if(rr->type == MappedRegistry::USER)
				fprintf(fp, "  user %s; extension=%s, profile=%s, use=%d,",
					rr->userid, buffer, rr->profile.id, rr->inuse);
			else if(rr->type == MappedRegistry::GATEWAY)
				fprintf(fp, "  gateway %s; use=%d,", rr->userid, rr->inuse);
			else if(rr->type == MappedRegistry::SERVICE)
				fprintf(fp, "  service %s; use=%d", rr->userid, rr->inuse);
			else if(rr->type == MappedRegistry::REFER)
				fprintf(fp, "  refer %s; extensions=%s,",
					rr->userid, buffer);
			else if(rr->type == MappedRegistry::REJECT)
				fprintf(fp, "  reject %s; extension=%s,",
					rr->userid, buffer);
			if(!rr->count)
				fprintf(fp, " address=none\n");
			else
				fputc('\n', fp);
			tp = rr->internal.targets;
			while(is(tp)) {
				Socket::getaddress((struct sockaddr *)(&tp->address), buffer, sizeof(buffer));
				fprintf(fp, "    address=%s, contact=%s", buffer, tp->contact);		
				if(tp->expires && tp->expires <= now)
					fprintf(fp, ", expired");
				else if(tp->expires)
					fprintf(fp, ", expires %ld", tp->expires - now);
				if(tp.getNext())
					fputc(',', fp);
				fputc('\n', fp);
				tp.next();
			}
			rp = rr->internal.routes;
			if(is(rp) && rr->type == MappedRegistry::SERVICE)
				fprintf(fp, "      services=");
			else if(is(rp) && rr->type == MappedRegistry::GATEWAY)
				fprintf(fp, "      routes=");
			while(is(rp) && (rr->type == MappedRegistry::SERVICE || rr->type == MappedRegistry::GATEWAY)) {
				fputs(rp->entry.text, fp);
				if(rp->getNext())
					fputc(',', fp);
				else
					fputc('\n', fp);
				rp.next();
			}
			rp = rr->internal.published;
			if(rp)
				fprintf(fp, "      published=");
			while(rp) {
				fputs(rp->entry.text, fp);
				if(rp->getNext())
					fputc(',', fp);
				else
					fputc('\n', fp);
				rp.next();
			}
		}
		fflush(fp);
		Thread::yield();
	}
	locking.release();
} 

void registry::clear(mapped *rr)
{
	assert(rr != NULL);
	
	rr->userid[0] = 0;
	rr->display[0] = 0;
	rr->remote[0] = 0;
	rr->status = MappedRegistry::OFFLINE;
	rr->type = MappedRegistry::EXPIRED;
	rr->hidden = false;
	rr->rid = -1;
	rr->ext = 0;
	rr->count = 0;
	rr->inuse = 0;
	rr->created = 0;
	rr->expires = 0;
	// this one is safe to clear...
	memset(&rr->profile, 0, sizeof(profile_t));
	rr->internal.published = rr->internal.targets = rr->internal.routes = NULL;
}
	
bool registry::remove(const char *id)
{
	assert(id != NULL && *id != 0);

	bool rtn = true;
	mapped *rr;

	locking.modify();
	rr = find(id);
	if(rr && rr->inuse)
		rtn = false;
	else if(rr)
		expire(rr);
	else
		rtn = false;
	locking.commit();
	return rtn;
}

void registry::expire(mapped *rr)
{
	assert(rr != NULL);

	linked_pointer<target> tp = rr->internal.targets;
	linked_pointer<route> rp = rr->internal.routes;
	unsigned path;

	--active_entries;

	while(rp) {
		route *nr = rp.getNext();
		if(rr->type == MappedRegistry::SERVICE) {
			path = NamedObject::keyindex(rp->entry.text, keysize);
			rp->entry.delist(&contacts[path]);
		}
		else
			rp->entry.delist(&primap[rp->entry.priority]);
		rp->entry.text[0] = 0;
		delete *rp;
		rp = nr;
	}	
	rp = rr->internal.published;
	while(rp) {
		route *nr = rp.getNext();
		--published_routes;
		path = NamedObject::keyindex(rp->entry.text, keysize);
		rp->entry.delist(&publishing[path]);
		rp->entry.text[0] = 0;
		delete *rp;
		rp = nr;
	}		
	while(tp) {
		// if active address index, delist & clear it
		if(tp->index.address) {
			path = Socket::keyindex(tp->index.address, keysize);
			tp->index.delist(&addresses[path]);
			tp->index.address = NULL;
			tp->index.registry = NULL;
		}
		target *nt = tp.getNext();
		delete *tp;
		tp = nt;
	}
	rr->internal.routes = NULL;
	rr->internal.targets = NULL;
	rr->internal.published = NULL;
	rr->count = 0;
	rr->inuse = 0;
	rr->status = MappedRegistry::OFFLINE;
	if(rr->ext && rr->ext >= reg.prefix && rr->ext < (reg.prefix + reg.range) && extmap[rr->ext - reg.prefix] == rr)
		extmap[rr->ext - reg.prefix] = NULL;
	process::errlog(INFO, "expiring %s; extension=%d", rr->userid, rr->ext);
	path = NamedObject::keyindex(rr->userid, keysize);
	rr->display[0] = 0;
	rr->userid[0] = 0;
	rr->ext = 0;
	rr->status = MappedRegistry::OFFLINE;
	rr->type = MappedRegistry::EXPIRED;
	rr->rid = -1;
	rr->delist(&keys[path]);
	rr->enlist(&freelist);
}

void registry::cleanup(time_t period)
{
	mapped *rr;
	unsigned regcount = 0;
	time_t now;

	while(regcount < mapped_entries) {
		time(&now);
		rr = static_cast<mapped*>(reg(regcount++));
		locking.modify();
		if(rr->type != MappedRegistry::EXPIRED && rr->expires && rr->expires + period < now && !rr->inuse) {
			server::expire(rr);
			expire(rr);
		}
		else if(!rr->inuse && rr->type == MappedRegistry::EXPIRED && rr->status != MappedRegistry::OFFLINE) 
			expire(rr);
		locking.commit();
		Thread::yield();
	}
}

void registry::reload(service *cfg)
{
	assert(cfg != NULL);

	static const char *olddigest = "MD5";
	static const char *oldrealm = "-";
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("registry");
	fsys_t fd;

	digest = (char *)"MD5";
	realm = NULL;

	while(is(sp)) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			if(!stricmp(key, "mapped") && !isConfigured()) 
				mapped_entries = atoi(value);
			else if(!stricmp(key, "digest")) {
				digest = cfg->dup(value);
				String::upper((char *)digest);
			}
			else if(!stricmp(key, "realm"))
				realm = cfg->dup(value);
			else if(!stricmp(key, "prefix") && !isConfigured())
				prefix = atoi(value);
			else if(!stricmp(key, "range") && !isConfigured())
				range = atoi(value);
			else if(!stricmp(key, "priorities") && !isConfigured())
				routes = atoi(value);
			else if(!stricmp(key, "expires"))
				expires = atoi(value);
			else if(!stricmp(key, "keysize") && !isConfigured())
				keysize = atoi(value);
		}
		sp.next();
	}

// windows may use registry keys?
#ifndef	_MSWINDOWS_
	char buffer[256];
	fsys_t fs;
	char *cp;

	if(!getuid() || !realm)	
		fsys::open(fs, DEFAULT_CFGPATH "/siprealm", fsys::ACCESS_RDONLY);
	if(!is(fs) && !realm)
		fsys::open(fs, "uuid", fsys::ACCESS_RDONLY);
	if(is(fs)) {
        memset(buffer, 0, sizeof(buffer));
        fsys::read(fs, buffer, sizeof(buffer) - 1);
        fsys::close(fs);
		
		cp = strchr(buffer, '\n');
		if(cp)
			*cp = 0;

        cp = strchr(buffer, ':');
        if(cp)
            *(cp++) = 0;
		if(buffer[0])
			realm = cfg->dup(buffer);
		if(cp && cp[0]) {
			digest = cfg->dup(cp);
			String::upper(digest);
		}
	}
	// if not in config file and not set, create one...
	else if(!realm) {
		memset(buffer, 0, sizeof(buffer));
		const char *evp = getenv("HOSTNAME");
		if(!evp)
			evp = "none";
		process::uuid(buffer, sizeof(buffer), evp);
		String::add(buffer, sizeof(buffer), ":");
		String::add(buffer, sizeof(buffer), digest);
		fsys::create(fs, "uuid", fsys::ACCESS_WRONLY, 0444);
		if(is(fs)) {
			fsys::write(fs, buffer, sizeof(buffer));
			fsys::close(fs);
		}
		cp = strchr(buffer, ':');
		if(cp)
			*cp = 0;
		realm = cfg->dup(buffer);
	}
			
#endif

	if(!String::equal(realm, oldrealm)) {
		process::errlog(INFO, "new realm %s", realm);
		digest::clear();
	} else if(!String::equal(digest, olddigest)) {
		process::errlog(INFO, "digest changed to %s", digest);
		digest::clear();
	}

	oldrealm = realm;
	olddigest = digest;

	if(isConfigured())
		return;

	if(range) {
		extmap = new mapped *[range];
		memset(extmap, 0, sizeof(mapped *) * range);
	}
	primap = new LinkedObject *[routes];
	memset(primap, 0, sizeof(LinkedObject *) * routes);
	keys = new LinkedObject *[keysize];
	contacts = new LinkedObject *[keysize];
	publishing = new LinkedObject *[keysize];
	addresses = new LinkedObject *[keysize];
	memset(keys, 0, sizeof(LinkedObject *) * keysize);
	memset(contacts, 0, sizeof(LinkedObject *) * keysize);
	memset(publishing, 0, sizeof(LinkedObject *) * keysize);
	memset(addresses, 0, sizeof(LinkedObject *) * keysize);
}

unsigned registry::getEntries(void)
{
	return mapped_entries;
}

registry::mapped *registry::invite(const char *id, stats::stat_t stat)
{
	assert(id != NULL && *id != 0);

	mapped *rr = NULL;
	unsigned path = NamedObject::keyindex(id, keysize);
	service::usernode user;
	service::keynode *leaf = NULL;
	unsigned ext = 0;

	locking.access();
	rr = find(id);
	if(rr) {
		incUse(rr, stat);
		locking.release();
		return rr;
	}

	locking.exclusive();
	if(freelist) {
		rr = (mapped *)freelist;
		freelist = rr->getNext();
	}
	else if(allocated_entries < mapped_entries)
		rr = (mapped *)reg(allocated_entries++);
	else {
		locking.commit();
		return NULL;
	}

	clear(rr);
	rr->type = MappedRegistry::TEMPORARY;
	rr->expires = 0;
	rr->created = 0;
	rr->display[0] = 0;
	rr->inuse = 0;
	rr->rid = -1;

	// in case inter-nodel temporary, create properties for call use...

	server::getProvision(id, user);
	service::keynode *node = user.keys;
	if(node)
		leaf = node->leaf("extension");
	if(leaf && leaf->getPointer())
		ext = atoi(leaf->getPointer());
	if(ext && (ext < reg.prefix || ext >= (reg.prefix + reg.range))) {
		rr->ext = ext;
	}
	else
		ext = 0;
	leaf = node->leaf("display");
	if(leaf && leaf->getPointer())
		String::set(rr->display, sizeof(rr->display), leaf->getPointer());

	server::release(user);

	String::set(rr->userid, sizeof(rr->userid), id);
	rr->ext = ext;
	rr->enlist(&keys[path]);
	rr->status = MappedRegistry::OFFLINE;
	incUse(rr, stat);

	locking.commit();
	return rr;
}

registry::mapped *registry::allocate(const char *id)
{
	assert(id != NULL && *id != 0);

	mapped *rr = NULL, *prior;
	unsigned path = NamedObject::keyindex(id, keysize);
	linked_pointer<service::keynode> rp;
	service::keynode *node, *leaf;
	unsigned ext = 0;
	const char *cp = "none";
	const char *cos = "none";
	profile_t *pro = NULL;
	bool listed = false;
	service::usernode user;

	locking.modify();
	rr = find(id);
	if(rr && rr->type != MappedRegistry::TEMPORARY && rr->type != MappedRegistry::EXPIRED) {
		locking.share();
		return rr;
	}

	if(rr) 
		listed = true;
	else {
		if(freelist) {
			rr = (mapped *)freelist;
			freelist = rr->getNext();
		} else if(allocated_entries < mapped_entries)
			rr = (mapped *)reg(allocated_entries++);
		if(rr)
			clear(rr);
	}
	if(!rr) {
		locking.commit();
		return NULL;
	}

	server::getProvision(id, user);
	node = user.keys;
	cp = "none";
	rr->rid = -1;
	rr->type = MappedRegistry::EXPIRED;
	rr->expires = 0;
	rr->created = 0;
	rr->display[0] = 0;

	if(!listed)
		rr->inuse = 0;

	if(node)
		cp = node->getId();

	cos = cp;
	if(!stricmp(cp, "admin") || !stricmp(cp, "user"))
		rr->type = MappedRegistry::USER;
	else if(!stricmp(cp, "refer"))
		rr->type = MappedRegistry::REFER;
	else if(!stricmp(cp, "reject"))
		rr->type = MappedRegistry::REJECT;
	else if(!stricmp(cp, "gateway"))
		rr->type = MappedRegistry::GATEWAY;
	else if(!stricmp(cp, "service") || !stricmp(cp, "device"))
		rr->type = MappedRegistry::SERVICE;
	if(!node || rr->type == MappedRegistry::EXPIRED) {
		server::release(user);
		if(listed && rr->inuse)
			rr->type = MappedRegistry::TEMPORARY;
		else if(listed) {
			rr->delist(&keys[path]);
			listed = false;
		}
		if(!listed)
			rr->enlist(&freelist);
		locking.commit();
		return NULL;
	}

	// add static services if exist
	rp = node->leaf("contacts");
	if(rp)
		rp = rp->getFirst();

	while(rp) {
		if(!stricmp(rp->getId(), "contact") && rp->getPointer())
			rr->addContact(rp->getPointer());
		rp.next();
	}

	// add published uris
	rp = node->leaf("published");
	if(!rp)
		node->leaf("publish");

	if(is(rp) && rp->getPointer())
		rr->addPublished(rp->getPointer());

	if(is(rp) && !rp->getPointer() && !rp->getFirst())
		rr->addPublished(id);

	if(is(rp))
		rp = rp->getFirst();

	while(is(rp)) {
		if(!stricmp(rp->getId(), "contact") && rp->getPointer())
			rr->addPublished(rp->getPointer());
		rp.next();
	}
	
	rp = node->leaf("display");
	if(is(rp) && rp->getPointer())
		String::set(rr->display, sizeof(rr->display), rp->getPointer());

	// we add routes while still exclusive owner of registry since
	// they update priority indexes.
	rp = node->leaf("routes");
	if(rp)
		rp = rp->getFirst();
	
	while(rp) {
		const char *pattern = NULL, *prefix = NULL, *suffix = NULL;
		unsigned priority = 0;
		linked_pointer<service::keynode> route;

		route = static_cast<LinkedObject*>(NULL);
		if(!stricmp(rp->getId(), "route"))
			route = rp->getFirst();
		while(route) {
			const char *id = route->getId();
			const char *value = route->getPointer();

			if(id && value && !stricmp(id, "pattern"))
				pattern = value;
			else if(id && value && !stricmp(id, "priority"))
				priority = atoi(value);
			else if(id && value && !stricmp(id, "prefix"))
				prefix = value;
			else if(id && value && !stricmp(id, "suffix"))
				suffix = value;
			route.next();
		}
		if(pattern)
			rr->addRoute(pattern, priority, prefix, suffix);
		rp.next();
	}
	leaf = node->leaf("extension");
	if(leaf && leaf->getPointer())
		ext = atoi(leaf->getPointer());

	if(rr->isProfiled()) {
		pro = NULL;
		leaf = node->leaf("profile");
		if(leaf)
			pro = server::getProfile(leaf->getPointer());
		if(!pro)
			pro = server::getProfile(cos);
		if(!pro)
			pro = server::getProfile("*");
		if(pro)
			memcpy(&rr->profile, pro, sizeof(rr->profile));
	}

	server::release(user);
	rr->ext = 0;
	rr->status = MappedRegistry::IDLE;

	if(!listed) {
		String::set(rr->userid, sizeof(rr->userid), id);
		rr->enlist(&keys[path]);
	}

	if(ext >= reg.prefix && ext < (reg.prefix + reg.range)) {
		prior = extmap[ext - reg.prefix];
		if(prior && prior != rr) {
			process::errlog(INFO, "releasing %s from extension %d", prior->userid, ext);
			prior->ext = 0;
		}
		extmap[ext - reg.prefix] = rr;
		rr->ext = ext;
		process::errlog(INFO, "activating %s; extension=%d", rr->userid, ext);
	}
	++active_entries;

	// exchange exclusive mutex lock for registry to shared before return
	// when registry state is again stable.

	locking.share();

	return rr;
}	

registry::mapped *registry::address(struct sockaddr *addr)
{
	assert(addr != NULL);

	target *target;
	linked_pointer<target::indexing> ind;
	mapped *rr = NULL;
	unsigned path = Socket::keyindex(addr, keysize);
	time_t now;

	locking.access();

	time(&now);
	ind = addresses[path];

	while(ind) {
		target = ind->getTarget();
		if(target && target->expires > now && Socket::equal(addr, ind->address)) {
			rr = ind->registry;
			break;
		}
		ind.next();
	}

	if(!rr)
		locking.release();
	return rr;
}

registry::mapped *registry::contact(const char *uri)
{
	assert(uri != NULL && *uri != 0);

	mapped *rr = NULL;
	struct sockaddr *addr = NULL;
	Socket::address *target = NULL;
	char buffer[MAX_USERID_SIZE];
	char *cp;

	if(!strnicmp(uri, "sip:", 4))
		uri += 4;
	else if(!strnicmp(uri, "sips:", 5))
		uri += 5;

	String::set(buffer, sizeof(buffer), uri);
	cp = strchr(buffer, '@');
	if(cp)
		*cp = 0;
	if(strchr(uri, '@')) {
		target = stack::getAddress(uri);
		if(target)
			addr = target->getAddr();
	}

	if(addr)
		rr = contact(addr, buffer);

	if(target)
		delete target;

	return rr;
}

registry::mapped *registry::contact(struct sockaddr *addr, const char *uid)
{
	assert(addr != NULL);
	assert(uid != NULL && *uid != 0);

	mapped *rr;
	linked_pointer<route> rp;
	unsigned path = NamedObject::keyindex(uid, keysize);
	locking.access();
	rp = contacts[path];
	while(rp) {
		if(!stricmp(uid, rp->entry.text) && Socket::equal(addr, (struct sockaddr *)(&rp->entry.registry->contact)))
			break;
		rp.next();
	}

	if(!rp) {
		locking.release();
		return NULL;
	}
	rr = rp->entry.registry;
	return rr;
}

bool registry::isUserid(const char *id)
{
	assert(id != NULL && *id != 0);

	if(!id || !*id)
		return false;

	if(strlen(id) >= MAX_USERID_SIZE)
		return false;

	if(strchr(id, '@') || strchr(id, ':'))
		return false;

	return true;
}

bool registry::isExtension(const char *id)
{
	assert(id != NULL && *id != 0);
	 
	unsigned ext = atoi(id);
	
	while(*id) {
		if(*id < '0' || *id > '9')
			return false;
		++id;
	}

	if(!reg.range)
		return false;

	if(ext >= reg.prefix && ext < (reg.prefix + reg.range))
		return true;

	return false;
}

registry::pattern *registry::getRouting(unsigned trs, const char *id)
{
	assert(id != NULL && *id != 0);

	linked_pointer<pattern> pp;
	if(trs > reg.routes)
		trs = reg.routes;

	if(!trs)
		return NULL;

	locking.access();
	while(trs--) {
		pp = primap[trs];
		while(pp) {
			if(service::match(id, pp->text, false) && pp->registry)
				return *pp;
			pp.next();
		}
	}
	locking.release();
	return NULL;
}
	
registry::mapped *registry::getExtension(const char *id)
{
	assert(id != NULL && *id != 0);
	
	unsigned ext = atoi(id);
	registry::mapped *rr = NULL;
	time_t now;

	locking.access();
	time(&now);
	rr = extmap[ext - reg.prefix];
	if(rr->expires && rr->expires < now)
		rr = NULL;
	if(!rr)
		locking.release();
	return rr;
}

bool registry::exists(const char *id)
{
	bool rtn = true;
	time_t now;

	mapped *rr = access(id);
	if(!rr)
		return false;

	time(&now);
	if(rr->expires && rr->expires < now)
		rtn = false;

	if(rr->status == MappedRegistry::OFFLINE)
		rtn = false;
	
	detach(rr);
	return rtn;
}

registry::mapped *registry::dialing(const char *id)
{
	assert(id != NULL && *id != 0);

	mapped *rr;
	unsigned ext = 0;

	if(isExtension(id))
		ext = atoi(id);

	locking.access();
	rr = find(id);

	// if extension dialing, and we find by id but have ext #, then ignore
	if(rr && service::dialmode == service::EXT_DIALING && rr->ext != 0)
		rr = NULL;

	// assuming not user id exclusive dialing, then we can try ext...
	if(!rr && service::dialmode != service::USER_DIALING && reg.range && ext >= reg.prefix && ext < (reg.prefix + reg.range))
		rr = extmap[ext - reg.prefix];
	if(!rr)
		locking.release();
	return rr;
}


registry::mapped *registry::access(const char *id)
{
	assert(id != NULL && *id != 0);

	mapped *rr;
	unsigned ext = 0;

	if(isExtension(id))
		ext = atoi(id);

	locking.access();
	rr = find(id);
	if(!rr && reg.range && ext >= reg.prefix && ext < (reg.prefix + reg.range))
		rr = extmap[ext - reg.prefix];
	if(!rr)
		locking.release();
	return rr;
}

void registry::detach(mapped *rr)
{
	// External registries are created in plugins, are not in shared memory,
	// and are not locked or otherwise managed under the registry.  They are
	// used to give an artificial "local call leg" registration entity when
	// call legs are extended through plugins, such as for service providers.

	if(!rr || rr->type == MappedRegistry::EXTERNAL)
		return;

	locking.release();
}

unsigned registry::mapped::setTarget(Socket::address& target_addr, time_t lease, const char *target_contact, const char *target_network, struct sockaddr *target_peering)
{
	assert(!isnull(target_addr));
	assert(target_contact != NULL && *target_contact != 0);

	Socket::address *origin = NULL;
	struct sockaddr *ai, *oi = NULL;
	linked_pointer<target> tp;
	socklen_t len;
	bool creating = false;

	ai = target_addr.getAddr();
	if(!ai)
		return 0;

	len = Socket::getlen(ai);

	locking.exclusive();
	tp = internal.targets;
	while(is(tp) && count > 1) {
		delete *tp;
		tp.next();
		--count;
	}

	if(!tp) {
		tp = new target;
		time(&tp->created);
		tp->enlist(&internal.targets);
		count = 1;
		tp->status = registry::target::READY;
		tp->address.address.sa_family = 0;
		creating = true;
	}
	expires = tp->expires = lease;
	if(!Socket::equal((struct sockaddr *)(&tp->address), ai)) {
		if(tp->index.address) {
			tp->index.delist(&addresses[Socket::keyindex(tp->index.address, keysize)]);
			tp->index.address = NULL;
			tp->index.registry = NULL;
			creating = true;
		}
		
		origin = stack::getAddress(target_contact);
		if(origin)
			oi = origin->getAddr();
		if(!oi)
			oi = ai;
		memcpy(&tp->address, ai, len);
		memcpy(&contact, oi, len);
		if(creating) {
			tp->index.registry = this;
			tp->index.address = (struct sockaddr *)(&tp->address);
			tp->index.enlist(&addresses[Socket::keyindex(tp->index.address, keysize)]);
		}
		if(origin) 
			delete origin;
	}
	Socket::store(&tp->peering, target_peering);
	String::set(tp->network, sizeof(tp->network), target_network);
	String::set(tp->contact, sizeof(tp->contact), target_contact);
	String::set(network, sizeof(network), target_network);
	uri::userid(target_contact, remote, sizeof(remote));
	locking.share();
	return 1;
}

void registry::mapped::addRoute(const char *route_pattern, unsigned route_priority, const char *route_prefix, const char *route_suffix)
{
	assert(route_pattern != NULL && *route_pattern != 0);

	locking.exclusive();
	route *rp = new route;

	if(!route_prefix)
		route_prefix = "";
	if(!route_suffix)
		route_suffix = "";

	String::set(rp->entry.text, MAX_USERID_SIZE, route_pattern);
	String::set(rp->entry.prefix, MAX_USERID_SIZE, route_prefix);
	String::set(rp->entry.suffix, MAX_USERID_SIZE, route_suffix);
	rp->entry.priority = route_priority;
	rp->entry.registry = this;
	rp->entry.enlist(&primap[route_priority]);
	rp->enlist(&internal.routes);
	locking.share();
}

void registry::mapped::addPublished(const char *published_id)
{
	assert(published_id != NULL && *published_id != 0);

	unsigned path = NamedObject::keyindex(published_id, keysize);
	locking.exclusive();
	route *rp = new route;
	String::set(rp->entry.text, MAX_USERID_SIZE, published_id);
	rp->entry.priority = 0;
	rp->entry.registry = this;
	rp->entry.enlist(&publishing[path]);
	rp->enlist(&internal.published);
	++published_routes;
	locking.share();
}

void registry::mapped::addContact(const char *contact_id)
{
	assert(contact_id != NULL && *contact_id != 0);

	unsigned path = NamedObject::keyindex(contact_id, keysize);

	locking.exclusive();
	route *rp = new route;
	String::set(rp->entry.text, MAX_USERID_SIZE, contact_id);
	rp->entry.priority = 0;
	rp->entry.registry = this;
	rp->entry.enlist(&contacts[path]);
	rp->enlist(&internal.routes);
	locking.share();
}

void registry::mapped::update(void)
{
	linked_pointer<target> tp = internal.targets;
	time_t now;
	status_t prior = status;
	const char *text;

	unsigned total = 0, busy = 0, away = 0, dnd = 0, offline = 0;

	time(&now);

	if(type != USER)
		return;

	if(type == EXPIRED || !is(tp)) {
		offline = total = 1;
	}
	else while(is(tp)) {
		++total;
		if(tp->expires < now || tp->status == registry::target::OFFLINE)
			++offline;
		else if(tp->status == registry::target::AWAY)
			++away;
		else if(tp->status == registry::target::DND)
			++dnd;
		else if(tp->status == registry::target::BUSY)
			++busy;
		else if(tp->status == registry::target::UNKNOWN)
			--total;
		tp.next();
	}

	if(offline == total) {
		status = OFFLINE;
		text = "offline";
	}
	else if(away + offline == total) {
		status = AWAY;
		text = "away";
	}
	else if(away + dnd + offline == total) {
		status = DND;
		text = "dnd";
	}
	else if(busy + dnd + offline + away == total) {
		status = BUSY;
		text = "busy";
	}
	else {
		status = IDLE;
		text = "ready";
	}

	if(status == prior)
		return;

	debug(3, "update: %s changed to %s", userid, text);	
}
		
bool registry::mapped::expire(Socket::address& saddr)
{
	unsigned active_count = 0;
	time_t now;
	linked_pointer<target> tp;

	time(&now);

	if(!saddr.getAddr() || !expires || expires < now || type == MappedRegistry::EXPIRED || type == MappedRegistry::TEMPORARY)
		return false;

	tp = internal.targets;
	while(tp) {
		if(Socket::equal(saddr.getAddr(), (struct sockaddr *)(&tp->address))) 
			tp->expires = now - 10;
		else if(tp->expires >= now)
			++active_count;
		tp.next();
	}
	if(!active_count) {
		Mutex::protect(this);
		type = MappedRegistry::EXPIRED;
		expires = 0;
		Mutex::release(this);
	}
	if(!active_count)
		return true;

	return false;
}

void registry::mapped::update(Socket::address& saddr, int changed)
{
	time_t now;
	linked_pointer<target> tp;

	time(&now);

	if(changed == registry::target::UNKNOWN || !saddr.getAddr() || !expires || expires < now || !isUser())
		return;

	tp = internal.targets;
	while(tp) {
		if(Socket::equal(saddr.getAddr(), (struct sockaddr *)(&tp->address))) {
			if(tp->status != changed) {
				tp->status = (registry::target::status_t)changed;
				update();
				return;
			}
		}
		tp.next();
	}
}

bool registry::mapped::refresh(Socket::address& saddr, time_t lease, const char *target_contact)
{
	assert(lease > 0);

	time_t now;
	linked_pointer<target> tp;

	time(&now);

	if(!saddr.getAddr() || !expires || expires < now || type == MappedRegistry::EXPIRED || type == MappedRegistry::TEMPORARY)
		return false;

	tp = internal.targets;
	while(tp) {
		if(Socket::equal(saddr.getAddr(), (struct sockaddr *)(&tp->address))) {
			char target_userid[MAX_USERID_SIZE];
			char contact_userid[MAX_USERID_SIZE];

			uri::userid(target_contact, target_userid, sizeof(target_userid));
			uri::userid(tp->contact, contact_userid, sizeof(contact_userid));
			if(String::equal(target_userid, contact_userid)) {
				Mutex::protect(this);
				if(lease > expires)
					expires = lease;
				Mutex::release(this);
				tp->expires = lease;
				return true;
			}
		}
		tp.next();
	}
	return false;
}

unsigned registry::mapped::addTarget(Socket::address& target_addr, time_t lease, const char *target_contact, const char *target_network, struct sockaddr *target_peering)
{
	assert(!isnull(target_addr));
	assert(target_contact != NULL && *target_contact != 0);
	assert(lease > 0);

	Socket::address *origin;
	struct sockaddr *ai, *oi = NULL;
	linked_pointer<target> tp;
	target *expired = NULL;
	time_t now;
	socklen_t len;

	ai = target_addr.getAddr();
	if(!ai)
		return 0;

	locking.exclusive();
	tp = internal.targets;
	if(lease > expires)
		expires = lease;

	len = Socket::getlen(ai);
	time(&now);
	while(tp) {
		if(tp->expires < now)
			expired = *tp;
		if(Socket::equal((struct sockaddr *)(&tp->address), ai))
			break;
		tp.next();
	} 
	if(tp) {
		if(expired && expired != *tp) {
			if(expired->index.address) {
				expired->index.delist(&addresses[Socket::keyindex(expired->index.address, keysize)]);
				expired->index.address = NULL;
				expired->index.registry = NULL;
			}
			expired->delist(&internal.targets);
			--count;
			delete expired;
		}
		if(tp->expires < now)
			time(&tp->created);
		tp->expires = lease;
		Socket::store(&tp->peering, target_peering);
		String::set(tp->contact, sizeof(tp->contact), target_contact);
		String::set(tp->network, sizeof(tp->network), target_network);
		locking.share();
		return count;
	}
	if(!expired) {
		origin = stack::getAddress(target_contact);
		if(origin)
			oi = origin->getAddr();
			
		if(!oi)
			oi = ai;
		expired = new target;
		expired->enlist(&internal.targets);
		expired->status = registry::target::READY;
		memcpy(&contact, oi, len);
		String::set(network, sizeof(network), target_network);
		uri::userid(target_contact, remote, sizeof(remote));
		if(origin)
			delete origin;
		++count;
	}
	time(&expired->created);
	expired->expires = lease;
	memcpy(&expired->address, ai, len);
	Socket::store(&expired->peering, target_peering);
	String::set(expired->contact, sizeof(expired->contact), target_contact);
	String::set(expired->network, sizeof(expired->network), target_network);
	expired->index.registry = this;
	expired->index.address = (struct sockaddr *)(&expired->address);
	expired->index.enlist(&addresses[Socket::keyindex(expired->index.address, keysize)]); 
	locking.share();
	update();
	return count;
}

unsigned registry::mapped::setTargets(Socket::address& target_addr)
{
	assert(!isnull(target_addr));

	stack::subnet *subnet;
	struct addrinfo *al;
	linked_pointer<target> tp;
	socklen_t len;

	al = target_addr.getList();
	if(!al)
		return 0;

	locking.exclusive();
	if(expires) {
		locking.share();
		return 0;
	}

	tp = internal.targets;
	while(tp) {
		delete *tp;
		tp.next();
	}	
	internal.targets = NULL;
	count = 0;
	while(al) {
		len = Socket::getlen(al->ai_addr);

		tp = new target;
		time(&tp->created);
		subnet = server::getPolicy(al->ai_addr);
		if(subnet) {
			tp->peering = subnet->iface;
			String::set(tp->network, sizeof(tp->network), subnet->getId());
		}
		else {
			service::published(&tp->peering);
			String::set(tp->network, sizeof(tp->network), "*");
		}
		server::release(subnet);
		String::set(network, sizeof(network), tp->network);
		memcpy(&tp->address, al->ai_addr, len);
		memcpy(&contact, &tp->address, len);
		remote[0] = 0;
		stack::sipAddress(&tp->address, tp->contact, userid);

		tp->expires = 0l;
		tp->status = registry::target::READY;
		tp->enlist(&internal.targets);
		++count;
		al = al->ai_next;
	}
	expires = 0;
	locking.share();
	update();
	return count;
}

registry::target *registry::target::indexing::getTarget(void)
{
	caddr_t cp = (caddr_t)address;
	target *tp = NULL;
	size_t offset = (size_t)(&tp->address);

	if(!address)
		return NULL;


	cp -= offset;
	return reinterpret_cast<target *>(cp);
}
	
END_NAMESPACE
