#include "server.h"

#define	PAGING	8192

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static mempager mempool(PAGING);

config::config(char *id) :
service(id, PAGING)
{
	memset(keys, 0, sizeof(keys));
}

service::keynode *config::find(const char *id)
{
	unsigned path = NamedObject::keyindex(id, CONFIG_KEY_SIZE);
	linked_pointer<keymap> map = keys[path];

	while(map) {
		if(!stricmp(map->id, id))
			return map->node;
		map.next();
	}
	return NULL;
} 

void *config::allocate(size_t size)
{
	return mempool.alloc(size);
}

bool config::create(const char *id, keynode *node)
{
	keymap *map = (keymap *)alloc_locked(sizeof(keymap));
	unsigned path = NamedObject::keyindex(id, CONFIG_KEY_SIZE);
	
	if(find(id))
		return true;
	
	map->id = id;
	map->node = node;
	map->enlist(&keys[path]);
	return false;
}

bool config::confirm(void)
{
	provision = getPath("provision");
	char *id = NULL, *secret = NULL;
	const char *ext;
	linked_pointer<service::keynode> node;
 	service::keynode *leaf;
	struct dirent *dno;
	FILE *fp;
	DIR *dir;
	char buf[128];
	caddr_t mp;
	profile *pp, *ppd;
	const char *realm = registry::getRealm();
	unsigned prefix = registry::getPrefix();
	unsigned range = registry::getRange();
	unsigned number;
	string_t digest;

	// construct default profiles

	extmap = NULL;
	if(range) {
		extmap = new keynode*[range];
		memset(extmap, 0, sizeof(keynode *) * range);
	}
	profiles = NULL;
	mp = (caddr_t)alloc_locked(sizeof(profile));
	ppd = new(mp) profile(&profiles);
	string::set(ppd->value.id, sizeof(ppd->value.id), "*");
	ppd->value.level = 1;
	ppd->value.features = USER_PROFILE_DEFAULT;
	
	mp = (caddr_t)alloc_locked(sizeof(profile));
	pp = new(mp) profile(&profiles);
	memcpy(&pp->value, &ppd->value, sizeof(profile_t));
	string::set(pp->value.id, sizeof(pp->value.id), "restricted");
	pp->value.level = 0;
	pp->value.features = USER_PROFILE_RESTRICTED;

	mkdir("provision", 0770);
	dir = opendir("provision");

	while(dir && NULL != (dno = readdir(dir))) {
		ext = strrchr(dno->d_name, '.');
		if(!ext || stricmp(ext, ".xml"))
			continue;
		snprintf(buf, sizeof(buf), "provision/%s", dno->d_name);
		fp = fopen(buf, "r");
		if(fp)
			if(!load(fp, provision))
				errlog(ERROR, "cannot load %s", buf);		
			else
				errlog(DEBUG, "loaded %s", buf);
	}

	if(dir)
		closedir(dir);

	node = provision->getFirst();
	while(node) {
		number = 0;
		leaf = node->leaf("id");
		if(leaf)
			id = leaf->getPointer();
		if(leaf && id && !strcmp(node->getId(), "profile")) {
			mp = (caddr_t)alloc_locked(sizeof(profile));
			pp = new(mp) profile(&profiles);
			memcpy(&pp->value, &ppd->value, sizeof(profile_t));
			string::set(pp->value.id, sizeof(pp->value.id), id);
			leaf = node->leaf("trs");
			if(leaf && leaf->getPointer())
				pp->value.level = atoi(leaf->getPointer());
			service::errlog(service::DEBUG, "adding profile %s", id);
			if(!stricmp(id, "*"))
				ppd = pp;
		}
		else if(leaf && id) {
			id = leaf->getPointer();
			if(create(id, *node))
				service::errlog(service::WARN, "duplicate identity %s", id);
			else
				service::errlog(service::DEBUG, "adding %s %s", node->getId(), id);
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
					leaf = new(mp) keynode(node, "digest");
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

void config::release(keynode *node)
{
	if(node)
		locking.release();
}

profile_t *config::getProfile(const char *pro)
{
	config *cfgp;
	linked_pointer<profile> pp;
	profile_t *ppd = NULL;

	cfgp = static_cast<config*>(cfg);
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

service::keynode *config::getExtension(const char *id)
{
	unsigned ext = atoi(id);
	unsigned range = registry::getRange();
	unsigned prefix = registry::getPrefix();
	config *cfgp;
	keynode *node = NULL;
	const char *cp;

	locking.access();
	cfgp = static_cast<config *>(cfg);
	if(!cfgp) {
		locking.release();
		return NULL;
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
	return node;
}

stack::address *config::getContact(const char *uid)
{
	keynode *node = getProvision(uid);
	stack::address *addr = NULL;

	if(!node)
		return NULL;

	node = node->leaf("contact");
	if(node)
		addr = stack::getAddress(node->getPointer());
	locking.release();
	return addr;
}

service::keynode *config::getProvision(const char *uid)
{
	keynode *node;
	config *cfgp;
	unsigned range = registry::getRange();
	unsigned prefix = registry::getPrefix();
	unsigned ext = atoi(uid);

	locking.access();
	cfgp = static_cast<config*>(cfg);
	if(!cfgp) {
		locking.release();
		return NULL;
	}
	node = cfgp->find(uid);
	if(!node && range && ext >= prefix && ext < prefix + range)
		node = cfgp->extmap[ext - prefix];
	if(!node)
		locking.release();
	return node;
}

void config::utils(void)
{
	FILE *fp = service::open("sipwitch");
	const char *key = NULL, *value;
	linked_pointer<keynode> sp;

	cfg = new config("sipwitch");
	
	crit(cfg != NULL);

	if(fp)
		if(!cfg->load(fp)) {
			errlog(ERROR, "invalid config");
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

bool config::check(void)
{
	errlog(INFO, "checking config...");
	locking.modify();
	locking.commit();
	errlog(INFO, "checking components...");
	if(service::check()) {
		errlog(INFO, "checking complete");
		return true;
	}
	errlog(WARN, "checking failed");
	return false;
}

void config::dump(FILE *fp)
{
	fprintf(fp, "Config Database:\n");
	fprintf(fp, "  Allocated pages: %d\n", mempool.getPages());
	fprintf(fp, "  Configured pages: %d\n", cfg->getPages());
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
		
void config::reload(void)
{
	FILE *fp = service::open("sipwitch");
	config *cfgp = new config("sipwitch");
	
	crit(cfgp != NULL);

	if(fp)
		if(!cfgp->load(fp)) {
			errlog(ERROR, "invalid config");
			delete cfgp;
			return;
		}

	if(!cfgp->commit()) {
		errlog(ERROR, "config rejected");
		delete cfgp;
	}
	if(!cfg) {
		errlog(FAILURE, "no configuration");
		exit(2);
	}
}

END_NAMESPACE
