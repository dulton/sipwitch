#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static volatile unsigned active_entries = 0;
static volatile unsigned active_targets = 0;
static volatile unsigned allocated_targets = 0;
static unsigned mapped_entries = 999;

static unsigned priorities = 10;
static unsigned keysize = 177;
static MappedRegistry **extmap = NULL;
static LinkedObject **primap = NULL;
static LinkedObject *freeroutes = NULL;
static LinkedObject *freetargets = NULL;
static LinkedObject **keys = NULL;
static mutex_t targetlock;
static mutex_t *reglock;

registry registry::reg;

registry::registry() :
service::callback(0), mapped_reuse<MappedRegistry>()
{
	realm = "Local Telephony";
	digest = "md5";
	prefix = 100;
	range = 600;
	expires = 300l;
}

void registry::exclusive(MappedRegistry *rr)
{
	unsigned idx;
	if(!rr || !reglock) {
		service::errlog(service::DEBUG, "invalid lock reference");
		return;
	}
	idx = getIndex(rr);
	if(idx >= mapped_entries) {
		service::errlog(service::ERROR, "lock out of range");
		return;
	}
	reglock[idx].acquire();
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
	service::errlog(service::DEBUG, "registry starting; mapping %d entries", mapped_entries);
	MappedReuse::create("sipwitch.regmap", mapped_entries);
	if(!reg)
		service::errlog(service::FAILURE, "registry could not be mapped");
	initialize();
	reglock = new mutex_t[mapped_entries];
}

bool registry::check(void)
{
	service::errlog(service::INFO, "checking registry...");
	reg.exlock();
	reg.unlock();
	return true;
}

void registry::stop(service *cfg)
{
	service::errlog(service::DEBUG, "registry stopping");
	MappedMemory::release();
	MappedMemory::remove("sipwitch.regmap");
}

void registry::snapshot(FILE *fp) 
{
	MappedRegistry *rr;
	unsigned count = 0;
	time_t now;
	linked_pointer<target> tp;
	char buffer[128];

	access();
	fprintf(fp, "Registry:\n"); 
	fprintf(fp, "  mapped entries: %d\n", mapped_entries);
	fprintf(fp, "  active entries: %d\n", active_entries);
	fprintf(fp, "  active targets: %d\n", active_targets);
	fprintf(fp, "  allocated targets: %d\n", allocated_targets);

	while(count < mapped_entries) {
		time(&now);
		rr = reg.pos(count++);
		exclusive(rr);
		if(rr->type != REG_EXPIRED && (!rr->expires || rr->expires >= now)) {
			if(rr->ext)
				snprintf(buffer, sizeof(buffer), "%d", rr->ext);
			else
				string::set(buffer, sizeof(buffer), "none");
			if(rr->type == REG_USER)
				fprintf(fp, "  user %s; extension=%s, profile=%s,",
					rr->userid, buffer, rr->profile.id);
			else if(rr->type == REG_GATEWAY)
				fprintf(fp, "  gateway %s;",
					rr->userid);
			else if(rr->type == REG_REFER)
				fprintf(fp, "  refer %s; extensions=%s,",
					rr->userid, buffer);
			if(!rr->count)
				fprintf(fp, " address=none\n");
			else
				fputc('\n', fp);
			tp = rr->targets;
			while(tp) {
				Socket::getaddress((struct sockaddr *)(&tp->address), buffer, sizeof(buffer));
				fprintf(fp, "    address=%s", buffer);		
				Socket::getaddress((struct sockaddr *)(&tp->interface), buffer, sizeof(buffer));
				fprintf(fp, " using %s", buffer);
				if(tp->expires && tp->expires <= now)
					fprintf(fp, " expired");
				else if(tp->expires)
					fprintf(fp, " expires %ld second(s)", tp->expires - now);
				if(tp.getNext())
					fputc(',', fp);
				fputc('\n', fp);
				tp.next();
			}
		}
		reglock[getIndex(rr)].release();
		fflush(fp);
		Thread::yield();
	}
	release();
} 

bool registry::remove(const char *id)
{
	bool rtn = true;
	MappedRegistry *rr;

	reg.exlock();
	rr = find(id);
	if(rr)
		expire(rr);
	else
		rtn = false;
	reg.unlock();
	return rtn;
}

void registry::expire(MappedRegistry *rr)
{
	linked_pointer<target> tp = rr->targets;
	linked_pointer<route> rp = rr->routes;
	unsigned path = NamedObject::keyindex(rr->userid, keysize);

	--active_entries;

	while(rp) {
		route *nr = rp.getNext();
		rp->entry.delist(&primap[rp->entry.priority]);
		rp->entry.text[0] = 0;
		rp->enlist(&freeroutes);
		rp = nr;
	}			
	while(tp) {
		target *nt = tp.getNext();
		--active_targets;
		targetlock.acquire();
		tp->enlist(&freetargets);
		targetlock.release();
		tp = nt;
	}
	rr->routes = NULL;
	rr->targets = NULL;
	rr->count = 0;
	if(reg.range && rr->ext) {
		if(extmap[rr->ext - reg.prefix] == rr) {
			service::errlog(service::INFO, "expiring %s from extension %u", rr->userid, rr->ext);
			service::publish(NULL, "- release %u %s %u", rr->ext, rr->userid, getIndex(rr));
			extmap[rr->ext - reg.prefix] = NULL;
		}
		else
			goto hold;
	}
	else
		service::errlog(service::INFO, "expiring %s", rr->userid);

	rr->ext = 0;
	rr->userid[0] = 0;
	rr->type = REG_EXPIRED;
	rp->delist(&keys[path]);

hold:
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
		reg.exlock();
		if(rr->type != REG_EXPIRED && rr->expires && rr->expires < now)
			expire(rr);
		reg.unlock();
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
				priorities = atoi(value);
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
	primap = new LinkedObject *[priorities];
	memset(primap, 0, sizeof(LinkedObject *) * priorities);
	keys = new LinkedObject *[keysize];
	memset(keys, 0, sizeof(LinkedObject *) * keysize);
	service::errlog(service::INFO, "realm %s", realm);
	return true;
}

unsigned registry::getEntries(void)
{
	return mapped_entries;
}

MappedRegistry *registry::modify(const char *id)
{
	MappedRegistry *rr;
	unsigned ext = atoi(id);

	reg.exlock();
	rr = find(id);
	if(!rr && reg.range && ext >= reg.prefix && ext < reg.prefix + reg.range)
		rr = extmap[ext - reg.prefix];

	if(!rr)
		reg.unlock();
	return rr;
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

	reg.exlock();
	rr = find(id);
	if(rr) {
		exclusive(rr);
		reg.share();
		return rr;
	}

	rr = reg.getLocked();
	if(!rr) {
		reg.unlock();
		return NULL;
	}

	node = config::getProvision(id);
	cp = "none";
	rr->type = REG_EXPIRED;
	rr->expires = 0;

	if(node)
		cp = node->getId();
	if(!stricmp(cp, "user"))
		rr->type = REG_USER;
	else if(!stricmp(cp, "refer"))
		rr->type = REG_REFER;
	else if(!stricmp(cp, "gateway"))
		rr->type = REG_GATEWAY;
	if(!node || rr->type == REG_EXPIRED) {
		config::release(node);
		reg.removeLocked(rr);
		reg.unlock();
		return NULL;
	}

	// we add routes while still exclusive owner of registry since
	// they update priority indexes.
	rp = node->leaf("routes");
	
	while(rp) {
		rp.next();
	}

	leaf = node->leaf("extension");
	if(leaf && leaf->getPointer())
		ext = atoi(leaf->getPointer());

	if(rr->type == REG_USER) {
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
	if(ext >= reg.prefix && ext < reg.prefix + reg.range) {
		prior = extmap[ext - reg.prefix];
		if(prior && prior != rr) {
			service::errlog(service::INFO, "releasing %s from extension %d", prior->userid, ext);
			service::publish(NULL, "- release %u %s %u", ext, prior->userid, getIndex(rr)); 
			prior->ext = 0;
		}
		extmap[ext - reg.prefix] = rr;
		rr->ext = ext;
		service::errlog(service::INFO, "activating %s as extension %d", rr->userid, ext);
		service::publish(NULL, "- activate %u %s %u", ext, rr->userid, getIndex(rr));
	}
	else
		service::errlog(service::INFO, "registering %s", rr->userid);
	++active_entries;

	// exchange exclusive mutex lock for registry to shared before return
	// when registry state is again stable.

	exclusive(rr);
	reg.share();

	return rr;
}	

MappedRegistry *registry::extension(const char *id)
{
	MappedRegistry *rr = NULL;
	unsigned ext = atoi(id);

	reg.access();
	if(reg.range && ext >= reg.prefix && ext < reg.prefix + reg.range)
		rr = extmap[ext - reg.prefix];
	if(!rr) {
		rr = find(id);
		if(rr && rr->type != REG_USER && (rr->type != REG_REFER || !rr->routes))
			rr = NULL;
	}
	if(!rr)
		reg.MappedReuse::release();
	else
		exclusive(rr);
	return rr;
}

MappedRegistry *registry::access(const char *id)
{
	MappedRegistry *rr;
	unsigned ext = atoi(id);

	reg.access();
	rr = find(id);
	if(!rr && reg.range && ext >= reg.prefix && ext < reg.prefix + reg.range)
		rr = extmap[ext - reg.prefix];
	if(!rr)
		reg.release();
	else
		exclusive(rr);
	return rr;
}

void registry::update(MappedRegistry *rr)
{
	if(!rr)
		return;

	reg.unlock();
}

void registry::release(MappedRegistry *rr)
{
	if(!rr)
		return;

	reglock[getIndex(rr)].release();
	reg.release();
}

unsigned registry::setTarget(MappedRegistry *rr, stack::address *addr, time_t expires)
{
	struct sockaddr *ai;
	linked_pointer<target> tp = rr->targets;
	socklen_t len;

	if(!addr)
		return 0;
	ai = addr->getAddr();
	if(!ai)
		return 0;

	len = Socket::getlen(ai);

	while(tp && rr->count > 1) {
		--active_targets;
		targetlock.acquire();
		tp->enlist(&freetargets);
		targetlock.release();
		tp.next();
		--rr->count;
	}

	if(!tp) {
		tp = createTarget();
		tp->enlist(&rr->targets);
		rr->count = 1;
		tp->address.sa_family = 0;
	}
	rr->expires = tp->expires = expires;
	if(!Socket::equal((struct sockaddr *)(&tp->address), ai)) {
		memcpy(&tp->address, ai, len);
		memcpy(&rr->latest, ai, len);
		Socket::getinterface((struct sockaddr *)&tp->interface, (struct sockaddr *)&tp->address);
	}
	return 1;
}

unsigned registry::addTarget(MappedRegistry *rr, stack::address *addr, time_t expires)
{
	struct sockaddr *ai;
	linked_pointer<target> tp = rr->targets;
	target *expired = NULL;
	time_t now;
	socklen_t len;

	if(!addr)
		return 0;
	ai = addr->getAddr();
	if(!ai)
		return 0;

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
		if(expired && expired != *tp) {
			expired->delist(&rr->targets);
			--rr->count;
			--active_targets;
			targetlock.acquire();
			expired->enlist(&freetargets);
			targetlock.release();
		}
		tp->expires = expires;
		return rr->count;
	}
	if(!expired) {
		expired = createTarget();
		expired->enlist(&rr->targets);
		memcpy(&rr->latest, ai, len);
		++rr->count;
	}
	expired->expires = expires;
	memcpy(&expired->address, ai, len);
	Socket::getinterface((struct sockaddr *)&expired->interface, (struct sockaddr *)&expired->address);
	return rr->count;
}

unsigned registry::setTargets(MappedRegistry *rr, stack::address *addr)
{
	struct addrinfo *al;
	linked_pointer<target> tp = rr->targets;
	socklen_t len;

	if(!addr)
		return 0;

	al = addr->getList();
	if(!al)
		return 0;

	if(rr->expires)
		return 0;

	while(tp) {
		--active_targets;
		targetlock.acquire();
		tp->enlist(&freetargets);
		targetlock.release();
		tp.next();
	}
	rr->targets = NULL;
	rr->count = 0;
	while(al) {
		len = Socket::getlen(al->ai_addr);

		tp = createTarget();
		memcpy(&tp->address, al->ai_addr, len);
		memcpy(&rr->latest, &tp->address, len);
		Socket::getinterface((struct sockaddr *)&tp->interface, (struct sockaddr *)&tp->address);
		tp->expires = 0l;
		tp->enlist(&rr->targets);
		++rr->count;
		al = al->ai_next;
	}
	rr->expires = 0;
	return rr->count;
}
	
registry::target *registry::createTarget(void)
{
	target *t;
	targetlock.acquire();
	t = static_cast<target *>(freetargets);
	if(t)
		freetargets = t->getNext();
	targetlock.release();
	if(!t) {
		++allocated_targets;
		t = static_cast<target *>(config::allocate(sizeof(target)));
	}
	++active_targets;
	return t;
}

END_NAMESPACE
