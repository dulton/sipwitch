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

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile unsigned active_routes = 0;
static volatile unsigned active_entries = 0;
static volatile unsigned active_targets = 0;
static volatile unsigned published_routes = 0;
static volatile unsigned allocated_routes = 0;
static volatile unsigned allocated_targets = 0;
static unsigned mapped_entries = 999;

static unsigned keysize = 177;
static MappedRegistry **extmap = NULL;
static LinkedObject **addresses = NULL;
static LinkedObject **published = NULL;
static LinkedObject **contacts = NULL;
static LinkedObject **primap = NULL;
static LinkedObject *freeroutes = NULL;
static LinkedObject *freetargets = NULL;
static LinkedObject **keys = NULL;
static condlock_t locking;

registry registry::reg;

registry::registry() :
service::callback(0), mapped_reuse<MappedRegistry>()
{
	realm = "Local Telephony";
	digest = "md5";
	prefix = 100;
	range = 600;
	expires = 300l;
	routes = 10;
}

MappedRegistry *registry::find(const char *id)
{
	linked_pointer<MappedRegistry> rp;
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

unsigned registry::getIndex(MappedRegistry *rr)
{
	unsigned x = (unsigned)(((caddr_t)rr - reg.getStart()) / sizeof(MappedRegistry));
	return x;
}

void registry::start(service *cfg)
{
	process::errlog(DEBUG1, "registry starting; mapping %d entries", mapped_entries);
	MappedReuse::create("sipwitch.regmap", mapped_entries);
	if(!reg)
		process::errlog(FAILURE, "registry could not be mapped");
	initialize();
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
	process::errlog(DEBUG1, "registry stopping");
	MappedMemory::release();
	MappedMemory::remove("sipwitch.regmap");
}

void registry::snapshot(FILE *fp) 
{
	MappedRegistry *rr;
	unsigned count = 0;
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

	while(count < mapped_entries) {
		time(&now);
		rr = reg.pos(count++);
		if(rr->type != MappedRegistry::EXPIRED && (!rr->expires || rr->expires >= now)) {
			if(rr->ext)
				snprintf(buffer, sizeof(buffer), "%d", rr->ext);
			else
				string::set(buffer, sizeof(buffer), "none");
			if(rr->type == MappedRegistry::USER)
				fprintf(fp, "  user %s; extension=%s, profile=%s,",
					rr->userid, buffer, rr->profile.id);
			else if(rr->type == MappedRegistry::GATEWAY)
				fprintf(fp, "  gateway %s;", rr->userid);
			else if(rr->type == MappedRegistry::SERVICE)
				fprintf(fp, "  service %s;", rr->userid);
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
			tp = rr->targets;
			while(tp) {
				Socket::getaddress((struct sockaddr *)(&tp->address), buffer, sizeof(buffer));
				fprintf(fp, "    address=%s, contact=%s", buffer, tp->contact);		
				if(tp->expires && tp->expires <= now)
					fprintf(fp, ", expired");
				else if(tp->expires)
					fprintf(fp, ", expires %ld second(s)", tp->expires - now);
				if(tp.getNext())
					fputc(',', fp);
				fputc('\n', fp);
				tp.next();
			}
			rp = rr->routes;
			if(rp && rr->type == MappedRegistry::SERVICE)
				fprintf(fp, "      services=");
			else if(rp && rr->type == MappedRegistry::GATEWAY)
				fprintf(fp, "      routes=");
			while(rp && (rr->type == MappedRegistry::SERVICE || rr->type == MappedRegistry::GATEWAY)) {
				fputs(rp->entry.text, fp);
				if(rp->getNext())
					fputc(',', fp);
				else
					fputc('\n', fp);
				rp.next();
			}
			rp = rr->published;
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

bool registry::remove(const char *id)
{
	bool rtn = true;
	MappedRegistry *rr;

	locking.modify();
	rr = find(id);
	if(rr)
		expire(rr);
	else
		rtn = false;
	locking.commit();
	return rtn;
}

void registry::expire(MappedRegistry *rr)
{
	linked_pointer<target> tp = rr->targets;
	linked_pointer<route> rp = rr->routes;
	unsigned path;

	--active_entries;

	while(rp) {
		route *nr = rp.getNext();
		--active_routes;
		if(rr->type == MappedRegistry::SERVICE) {
			path = NamedObject::keyindex(rp->entry.text, keysize);
			rp->entry.delist(&contacts[path]);
		}
		else
			rp->entry.delist(&primap[rp->entry.priority]);
		rp->entry.text[0] = 0;
		rp->enlist(&freeroutes);
		rp = nr;
	}	
	rp = rr->published;
	while(rp) {
		route *nr = rp.getNext();
		--active_routes;
		--published_routes;
		path = NamedObject::keyindex(rp->entry.text, keysize);
		rp->entry.delist(&published[path]);
		rp->entry.text[0] = 0;
		rp->enlist(&freeroutes);
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
		--active_targets;
		tp->enlist(&freetargets);
		tp = nt;
	}
	rr->routes = NULL;
	rr->targets = NULL;
	rr->published = NULL;
	rr->count = 0;
	rr->status = MappedRegistry::OFFLINE;
	if(rr->ext && extmap[rr->ext - reg.prefix] == rr)
		extmap[rr->ext - reg.prefix] = NULL;
	process::errlog(INFO, "expiring %s; extension=%d", rr->userid, rr->ext);
	path = NamedObject::keyindex(rr->userid, keysize);
	rr->userid[0] = 0;
	rr->ext = 0;
	rr->status = MappedRegistry::OFFLINE;
	rr->type = MappedRegistry::EXPIRED;
	rp->delist(&keys[path]);
	reg.removeLocked(rr);
}

void registry::cleanup(void)
{
	MappedRegistry *rr;
	unsigned count = 0;
	time_t now;

	while(count < mapped_entries) {
		time(&now);
		rr = reg.pos(count++);
		locking.modify();
		if(rr->type != MappedRegistry::EXPIRED && rr->expires && rr->expires < now)
			expire(rr);
		locking.commit();
		Thread::yield();
	}
}

bool registry::reload(service *cfg)
{
	const char *key = NULL, *value;
	linked_pointer<service::keynode> sp = cfg->getList("registry");

	while(sp) {
		key = sp->getId();
		value = sp->getPointer();
		if(key && value) {
			if(!stricmp(key, "mapped") && !isConfigured()) 
				mapped_entries = atoi(value);
			else if(!stricmp(key, "digest") && !isConfigured()) {
				digest = strdup(value);
				string::upper((char *)digest);
			}
			else if(!stricmp(key, "realm") && !isConfigured())
				realm = strdup(value);
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

	if(isConfigured())
		return true;

	if(range) {
		extmap = new MappedRegistry *[range];
		memset(extmap, 0, sizeof(MappedRegistry *) * range);
	}
	primap = new LinkedObject *[routes];
	memset(primap, 0, sizeof(LinkedObject *) * routes);
	keys = new LinkedObject *[keysize];
	contacts = new LinkedObject *[keysize];
	published = new LinkedObject *[keysize];
	addresses = new LinkedObject *[keysize];
	memset(keys, 0, sizeof(LinkedObject *) * keysize);
	memset(contacts, 0, sizeof(LinkedObject *) * keysize);
	memset(published, 0, sizeof(LinkedObject *) * keysize);
	memset(addresses, 0, sizeof(LinkedObject *) * keysize);
	process::errlog(INFO, "realm %s", realm);
	return true;
}

unsigned registry::getEntries(void)
{
	return mapped_entries;
}

MappedRegistry *registry::create(const char *id)
{
	MappedRegistry *rr, *prior;
	unsigned path = NamedObject::keyindex(id, keysize);
	linked_pointer<service::keynode> rp;
	service::keynode *node, *leaf;
	unsigned ext = 0;
	const char *cp = "none";
	profile_t *pro = NULL;

	locking.modify();
	rr = find(id);
	if(rr) {
		locking.share();
		return rr;
	}

	rr = reg.getLocked();
	if(!rr) {
		locking.commit();
		return NULL;
	}

	node = config::getProvision(id);
	cp = "none";
	rr->type = MappedRegistry::EXPIRED;
	rr->expires = 0;
	rr->created = 0;

	if(node)
		cp = node->getId();
	if(!stricmp(cp, "user"))
		rr->type = MappedRegistry::USER;
	else if(!stricmp(cp, "refer"))
		rr->type = MappedRegistry::REFER;
	else if(!stricmp(cp, "reject"))
		rr->type = MappedRegistry::REJECT;
	else if(!stricmp(cp, "gateway"))
		rr->type = MappedRegistry::GATEWAY;
	else if(!stricmp(cp, "service"))
		rr->type = MappedRegistry::SERVICE;
	if(!node || rr->type == MappedRegistry::EXPIRED) {
		config::release(node);
		reg.removeLocked(rr);
		locking.commit();
		return NULL;
	}

	// add static services if exist
	rp = node->leaf("contacts");
	if(rp)
		rp = rp->getFirst();

	while(rp) {
		if(!stricmp(rp->getId(), "contact") && rp->getPointer())
			addContact(rr, rp->getPointer());
		rp.next();
	}

	// add published uris
	rp = node->leaf("published");
	if(!rp)
		node->leaf("publish");

	if(rp && rp->getPointer())
		addPublished(rr, rp->getPointer());

	if(rp && !rp->getPointer() && !rp->getFirst())
		addPublished(rr, rr->userid);

	if(rp)
		rp = rp->getFirst();

	while(rp) {
		if(!stricmp(rp->getId(), "contact") && rp->getPointer())
			addPublished(rr, rp->getPointer());
		rp.next();
	}
	
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
			addRoute(rr, pattern, priority, prefix, suffix);
		rp.next();
	}

	leaf = node->leaf("extension");
	if(leaf && leaf->getPointer())
		ext = atoi(leaf->getPointer());

	if(rr->type == MappedRegistry::USER) {
		pro = NULL;
		leaf = node->leaf("profile");
		if(leaf)
			pro = config::getProfile(leaf->getPointer());
		if(!pro)
			pro = config::getProfile("*");
		if(pro)
			memcpy(&rr->profile, pro, sizeof(rr->profile));
	}

	config::release(node);
	strcpy(rr->userid, id);
	rr->ext = 0;
	rr->enlist(&keys[path]);
	rr->status = MappedRegistry::IDLE;
	if(ext >= reg.prefix && ext < reg.prefix + reg.range) {
		prior = extmap[ext - reg.prefix];
		if(prior && prior != rr) {
			process::errlog(INFO, "releasing %s from extension %d", prior->userid, ext);
			prior->ext = 0;
		}
		if(ext && extmap[ext - reg.prefix] != rr)
			service::publish(NULL, "- map %d %d", ext, getIndex(rr));
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

MappedRegistry *registry::address(struct sockaddr *addr)
{
	target *target;
	linked_pointer<target::indexing> ind;
	MappedRegistry *rr = NULL;
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


MappedRegistry *registry::contact(const char *uri)
{
	MappedRegistry *rr = NULL;
	struct sockaddr *addr = NULL;
	stack::address *target = NULL;
	char buffer[MAX_USERID_SIZE];
	char *cp;

	if(!strnicmp(uri, "sip:", 4))
		uri += 4;
	else if(!strnicmp(uri, "sips:", 5))
		uri += 5;

	string::set(buffer, sizeof(buffer), uri);
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

MappedRegistry *registry::contact(struct sockaddr *addr, const char *uid)
{
	MappedRegistry *rr;
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
	unsigned ext = atoi(id);
	
	while(*id) {
		if(*id < '0' || *id > '9')
			return false;
		++id;
	}

	if(!reg.range)
		return false;

	if(ext >= reg.prefix && ext < reg.prefix + reg.range)
		return true;

	return false;
}

registry::pattern *registry::getRouting(unsigned trs, const char *id)
{
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
	
MappedRegistry *registry::getExtension(const char *id)
{
	unsigned ext = atoi(id);
	MappedRegistry *rr = NULL;
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

MappedRegistry *registry::access(const char *id)
{
	MappedRegistry *rr;
	unsigned ext = 0;

	if(isExtension(id))
		ext = atoi(id);

	locking.access();
	rr = find(id);
	if(!rr && reg.range && ext >= reg.prefix && ext < reg.prefix + reg.range)
		rr = extmap[ext - reg.prefix];
	if(!rr)
		locking.release();
	return rr;
}

void registry::release(MappedRegistry *rr)
{
	if(!rr)
		return;

	locking.release();
}

unsigned registry::setTarget(MappedRegistry *rr, stack::address *addr, time_t expires, const char *contact)
{
	stack::address *origin = NULL;
	struct sockaddr *ai, *oi = NULL;
	linked_pointer<target> tp;
	socklen_t len;
	bool created = false;

	if(!addr)
		return 0;
	ai = addr->getAddr();
	if(!ai)
		return 0;

	len = Socket::getlen(ai);

	locking.exclusive();
	tp = rr->targets;
	while(tp && rr->count > 1) {
		--active_targets;
		tp->enlist(&freetargets);
		tp.next();
		--rr->count;
	}

	if(!tp) {
		tp = createTarget();
		tp->enlist(&rr->targets);
		rr->count = 1;
		tp->address.sa_family = 0;
		created = true;
	}
	rr->expires = tp->expires = expires;
	if(!Socket::equal((struct sockaddr *)(&tp->address), ai)) {
		if(tp->index.address) {
			tp->index.delist(&addresses[Socket::keyindex(tp->index.address, keysize)]);
			tp->index.address = NULL;
			tp->index.registry = NULL;
			created = true;
		}
		
		origin = stack::getAddress(contact);
		if(origin)
			oi = origin->getAddr();
		if(!oi)
			oi = ai;
		memcpy(&tp->address, ai, len);
		memcpy(&rr->contact, oi, len);
		if(created) {
			tp->index.registry = rr;
			tp->index.address = (struct sockaddr *)(&tp->address);
			tp->index.enlist(&addresses[Socket::keyindex(tp->index.address, keysize)]);
		}
		stack::getInterface((struct sockaddr *)(&tp->interface), (struct sockaddr *)(&tp->address));
		if(origin)
			delete origin;
	}
	string::set(tp->contact, MAX_URI_SIZE, contact);
	locking.share();
	return 1;
}

void registry::addRoute(MappedRegistry *rr, const char *pat, unsigned pri, const char *prefix, const char *suffix)
{
	locking.exclusive();
	route *rp = createRoute();

	if(!prefix)
		prefix = "";
	if(!suffix)
		suffix = "";

	string::set(rp->entry.text, MAX_USERID_SIZE, pat);
	string::set(rp->entry.prefix, MAX_USERID_SIZE, prefix);
	string::set(rp->entry.suffix, MAX_USERID_SIZE, suffix);
	rp->entry.priority = pri;
	rp->entry.registry = rr;
	rp->entry.enlist(&primap[pri]);
	rp->enlist(&rr->routes);
	locking.share();
}

void registry::addPublished(MappedRegistry *rr, const char *id)
{
	unsigned path = NamedObject::keyindex(id, keysize);
	locking.exclusive();
	route *rp = createRoute();
	string::set(rp->entry.text, MAX_USERID_SIZE, id);
	rp->entry.priority = 0;
	rp->entry.registry = rr;
	rp->entry.enlist(&published[path]);
	rp->enlist(&rr->published);
	++published_routes;
	locking.share();
}

void registry::addContact(MappedRegistry *rr, const char *id)
{
	unsigned path = NamedObject::keyindex(id, keysize);

	locking.exclusive();
	route *rp = createRoute();
	string::set(rp->entry.text, MAX_USERID_SIZE, id);
	rp->entry.priority = 0;
	rp->entry.registry = rr;
	rp->entry.enlist(&contacts[path]);
	rp->enlist(&rr->routes);
	locking.share();
}

bool registry::refresh(MappedRegistry *rr, stack::address *addr, time_t expires)
{
	linked_pointer<target> tp;

	if(!addr || !addr->getAddr() || !rr || !rr->expires || rr->type == MappedRegistry::EXPIRED)
		return false;

	tp = rr->targets;
	while(tp) {
		if(Socket::equal(addr->getAddr(), (struct sockaddr *)(&tp->address))) {
			if(expires > rr->expires)
				rr->expires = expires;
			tp->expires = expires;
			return true;
		}
		tp.next();
	}
	return false;
}

unsigned registry::addTarget(MappedRegistry *rr, stack::address *addr, time_t expires, const char *contact)
{
	stack::address *origin;
	struct sockaddr *ai, *oi = NULL;
	linked_pointer<target> tp;
	target *expired = NULL;
	time_t now;
	socklen_t len;

	if(!addr)
		return 0;
	ai = addr->getAddr();
	if(!ai)
		return 0;

	locking.exclusive();
	tp = rr->targets;
	if(expires > rr->expires)
		rr->expires = expires;

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
		string::set(tp->contact, MAX_URI_SIZE, contact);
		if(expired && expired != *tp) {
			if(expired->index.address) {
				expired->index.delist(&addresses[Socket::keyindex(expired->index.address, keysize)]);
				expired->index.address = NULL;
				expired->index.registry = NULL;
			}
			expired->delist(&rr->targets);
			--rr->count;
			--active_targets;
			expired->enlist(&freetargets);
		}
		tp->expires = expires;
		locking.share();
		return rr->count;
	}
	if(!expired) {
		origin = stack::getAddress(contact);
		if(origin)
			oi = origin->getAddr();
		if(!oi)
			oi = ai;
		expired = createTarget();
		expired->enlist(&rr->targets);
		memcpy(&rr->contact, oi, len);
		if(origin)
			delete origin;
		++rr->count;
	}
	string::set(expired->contact, sizeof(expired->contact), contact);
	expired->expires = expires;
	memcpy(&expired->address, ai, len);
	stack::getInterface((struct sockaddr *)(&expired->interface), (struct sockaddr *)(&expired->address));
	expired->index.registry = rr;
	expired->index.address = (struct sockaddr *)(&expired->address);
	expired->index.enlist(&addresses[Socket::keyindex(expired->index.address, keysize)]); 
	locking.share();
	return rr->count;
}

unsigned registry::setTargets(MappedRegistry *rr, stack::address *addr)
{
	struct addrinfo *al;
	linked_pointer<target> tp;
	socklen_t len;

	if(!addr)
		return 0;

	al = addr->getList();
	if(!al)
		return 0;

	locking.exclusive();
	if(rr->expires) {
		locking.share();
		return 0;
	}

	tp = rr->targets;
	while(tp) {
		--active_targets;
		tp->enlist(&freetargets);
		tp.next();
	}	
	rr->targets = NULL;
	rr->count = 0;
	while(al) {
		len = Socket::getlen(al->ai_addr);

		tp = createTarget();
		memcpy(&tp->address, al->ai_addr, len);
		memcpy(&rr->contact, &tp->address, len);
		stack::getInterface((struct sockaddr *)(&tp->interface), (struct sockaddr *)(&tp->address));
		stack::sipAddress(&tp->address, tp->contact, rr->userid);
		tp->expires = 0l;
		tp->enlist(&rr->targets);
		++rr->count;
		al = al->ai_next;
	}
	rr->expires = 0;
	locking.share();
	return rr->count;
}

registry::route *registry::createRoute(void)
{
	route *r;
	r = static_cast<route *>(freeroutes);
	if(r)
		freeroutes = r->getNext();
	if(!r) {
		++allocated_routes;
		r = static_cast<route *>(config::allocate(sizeof(route)));
	}
	++active_routes;
	return r;
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
	
registry::target *registry::createTarget(void)
{
	target *t;
	t = static_cast<target *>(freetargets);
	if(t)
		freetargets = t->getNext();
	if(!t) {
		++allocated_targets;
		t = static_cast<target *>(config::allocate(sizeof(target)));
	}
	++active_targets;
	return t;
}

END_NAMESPACE
