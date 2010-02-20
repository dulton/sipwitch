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

#include <config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/process.h>
#include <sipwitch/service.h>
#include <sipwitch/modules.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>

#define	RUNLEVELS	(sizeof(callback::runlevels) / sizeof(LinkedObject *))

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

LinkedObject *service::callback::runlevels[4] = {NULL, NULL, NULL, NULL};
unsigned service::callback::count = 0;
unsigned short service::callback::sip_port = 5060;
int service::callback::sip_protocol = IPPROTO_UDP;
int service::callback::sip_family = AF_INET;
int service::callback::sip_tlsmode = 0;
const char *service::callback::sip_domain = NULL;
condlock_t service::locking;
service *service::cfg = NULL;
volatile service::dialmode_t service::dialmode = service::ALL_DIALING;

static struct sockaddr_storage peering;
static char header[80] = "- welcome";
static time_t started = 0l;
static time_t periodic = 0l;

static size_t xmldecode(char *out, size_t limit, const char *src)
{
	assert(out != NULL);
	assert(limit > 0);
	assert(src != NULL);

	char *ret = out;

	if(*src == '\'' || *src == '\"')
		++src;
	while(src && limit-- > 1 && !strchr("<\'\">", *src)) {
		if(!strncmp(src, "&amp;", 5)) {
			*(out++) = '&';
			src += 5;
		}
		else if(!strncmp(src, "&lt;", 4)) {
			src += 4;
			*(out++) = '<';
		}
		else if(!strncmp(src, "&gt;", 4)) {
			src += 4;
			*(out++) = '>';
		}
		else if(!strncmp(src, "&quot;", 6)) {
			src += 6;
			*(out++) = '\"';
		}
		else if(!strncmp(src, "&apos;", 6)) {
			src += 6;
			*(out++) = '\'';
		}
		else
			*(out++) = *(src++);
	}
	*out = 0;
	return out - ret;
}

service::usernode::usernode()
{
	keys = NULL;
	heap = NULL;
}

service::pointer::pointer()
{
	node = NULL;
}

service::pointer::pointer(const char *id)
{
	assert(id != NULL && *id != 0);

	locking.access();
	node = service::path(id);
}

service::pointer::pointer(pointer const &copy)
{
	node = copy.node;
	locking.access();
}

service::pointer::~pointer()
{
	service::release(node);
}

void service::pointer::operator=(keynode *p)
{
	service::release(node);
	node = p;
}	

service::callback::callback(int rl) :
OrderedObject()
{
	crit(rl < (int)RUNLEVELS, "service runlevel invalid");
	if(rl < 0) {
		rl += RUNLEVELS;
		crit(rl > 0, "service runlevel invalid");
	}
	LinkedObject::enlist(&runlevels[rl]);
	active_flag = false;
	runlevel = rl;
	++count;
}

service::callback::~callback()
{
	LinkedObject::delist(&runlevels[runlevel]);
}

void service::callback::snapshot(FILE *fp)
{
}

bool service::callback::check(void)
{
	return true;
}

void service::callback::errlog(errlevel_t level, const char *text)
{
}

void service::callback::cdrlog(cdr *cdr)
{
}

void service::callback::reload(service *keys)
{
}

void service::callback::start(service *keys)
{
}

void service::callback::stop(service *keys)
{
}

service::instance::instance()
{
	service::locking.access();
}

service::instance::~instance()
{
	service::locking.release();
}

void service::keyclone::enlist(keyclone *trunk)
{
	parent = trunk;
	if(parent)
		enlistTail(&trunk->child);
}

service::service(const char *name, size_t s) :
memalloc(s), root()
{
	assert(name != NULL && *name != 0);

	keynode *env;
	
	static const char *vars[] = {"HOME", "USER", "IDENT", "PATH", "LANG", "PWD", "TZ", "TMP", "SHELL", "CFG", NULL};
	const char **varp = vars;
	const char *cp;

	root.setId((char *)name);
	root.setPointer(NULL);
	if(!started) {
		time(&started);
		time(&periodic);
	}

	env = addNode(&root, "environ", NULL);
	while(varp && *varp) {
		cp = getenv(*varp);
		if(cp)
			addNode(env, *varp, dup(cp));
		++varp;
	}
}

service::~service()
{
	// we must zap the xml tree root node, lest it try to delete it's "id"
	// or child nodes, since all was allocated from the "pager" heap.
	memset(&root, 0, sizeof(root));
	memalloc::purge();
}

void service::setHeader(const char *h)
{
	String::set(header, sizeof(header) - 1, h);
}

void service::publish(const char *addr)
{
	Socket::address resolver;
	struct sockaddr *host;

	if(!addr)
		memset(&peering, 0, sizeof(peering));
	
	int i = 0;
	resolver.set(addr, i);
	host = resolver.getAddr();
	if(host)
		Socket::store(&peering, host);
}
	
void service::published(struct sockaddr_storage *peer)
{
	memcpy(peer, &peering, sizeof(peering));
}

long service::uptime(void)
{
	time_t now;
	time(&now);
	if(!started)
		return 0l;

	return now - started;
}

service::keynode *service::path(const char *id)
{
	assert(id != NULL && *id != 0);

	if(!cfg)
		return NULL;

	return cfg->getPath(id);
}

service::keynode *service::list(const char *id)
{
	assert(id != NULL && *id != 0);

	keynode *node;

	if(!cfg)
		return NULL;

	node = cfg->getPath(id);
	if(node)
		return node->getFirst();
	return NULL;
}

service::keynode *service::getUser(const char *id)
{
	assert(id != NULL && *id != 0);
	unsigned path;
	linked_pointer<keymap> map;

	if(!cfg)
		goto bail;

	locking.access();

	path = NamedObject::keyindex(id, CONFIG_KEY_SIZE);
	map = cfg->keys[path];
	
	while(map) {
		if(!stricmp(map->id, id))
			return map->node;
		map.next();
	}

bail:
	locking.release();
	return NULL;
}

service::keynode *service::getProtected(const char *id)
{
	assert(id != NULL && *id != 0);
	
	keynode *node;

	if(!cfg)
		return NULL;

	locking.access();
	node = cfg->getPath(id);
	if(!node)
		locking.release();
	return node;
}

service::keynode *service::getList(const char *path)
{
	assert(path != NULL && *path != 0);

	keynode *base = getPath(path);
	if(!base)
		return NULL;

	return base->getFirst();
}

service::keynode *service::get(void)
{
	if(cfg)
		locking.access();
	return &cfg->root;
}

void service::release(keynode *node)
{
	if(node)
		locking.release();
}

service::keynode *service::getPath(const char *id)
{
	assert(id != NULL && *id != 0);

	const char *np;
	char buf[65];
	char *ep;
	keynode *node = &root, *child;

	while(id && *id && node) {
		String::set(buf, sizeof(buf), id);
		ep = strchr(buf, '.');
		if(ep)
			*ep = 0;
		np = strchr(id, '.');
		if(np)
			id = ++np;
		else
			id = NULL;
		child = node->getChild(buf);
		if(!child) 
			child = addNode(node, buf, NULL);
		node = child;			
	}
	return node;
}

service::keynode *service::addNode(keynode *base, const char *id, const char *value)
{
	assert(base != NULL);
	assert(id != NULL && *id != 0);

	caddr_t mp;
	keynode *node;
	char *cp;

	mp = (caddr_t)memalloc::alloc(sizeof(keynode));
	cp = dup(id);
	node = new(mp) keynode(base, cp);
	if(value)
		node->setPointer(dup(value));
	else
		node->setPointer(NULL);
	return node;
}

const char *service::getValue(keynode *node, const char *id)
{
	assert(node != NULL);
	assert(id != NULL && *id != 0);

	node = node->getChild(id);
	if(!node)
		return NULL;

	return node->getPointer();
}

service::keynode *service::addNode(keynode *base, define *defs)
{
	assert(base != NULL);
	assert(defs != NULL);

	keynode *node = getNode(base, defs->key, defs->value);
	if(!node)
		node = addNode(base, defs->key, defs->value);

	for(;;) {
		++defs;
		if(!defs->key)
			return base;
		if(node->getChild(defs->key))
			continue;
		addNode(node, defs->key, defs->value);
	}
	return node;
}

service::keynode *service::getNode(keynode *base, const char *id, const char *attr, const char *value)
{
	assert(base != NULL);
	assert(id != NULL && *id != 0);
	assert(attr != NULL);
	assert(value != NULL);

	linked_pointer<keynode> node = base->getFirst();
	keynode *leaf;
	char *cp;

	while(node) {
		if(!strcmp(id, node->getId())) {
			leaf = node->getLeaf(attr);
			if(leaf) {
				cp = leaf->getPointer();
				if(cp && !stricmp(cp, value))
					return *node;
			}
		}
		node.next();
	}
	return NULL;
}

service::keynode *service::getNode(keynode *base, const char *id, const char *text)
{
	assert(base != NULL);
	assert(id != NULL && *id != 0);
	assert(text != NULL && *text != 0);

	linked_pointer<keynode> node = base->getFirst();
	char *cp;
	
	while(node) {
		if(!strcmp(id, node->getId())) {
			cp = node->getPointer();
			if(cp && !stricmp(cp, text))
				return *node;
		}
		node.next();
	}
	return NULL;
} 

void service::addAttributes(keynode *node, char *attr)
{
	assert(node != NULL);
	assert(attr != NULL);

	char *ep, *qt;
	char *id;
	int len;

	while(attr && *attr && *attr != '>') {
		while(isspace(*attr))
			++attr;

		if(!*attr || *attr == '>')
			return;		
	
		id = attr;
		while(*attr && *attr != '=' && *attr != '>')
			++attr;

		if(*attr != '=')
			return;

		*(attr++) = 0;
		id = String::trim(id, " \t\r\n");
		while(isspace(*attr))
			++attr;
	
		qt = attr;
		ep = strchr(++attr, *qt);
		if(!ep)
			return;

		*(ep++) = 0;
		len = strlen(attr);
		qt = (char *)memalloc::alloc(len + 1);
		xmldecode(qt, len + 1, attr);
		addNode(node, id, qt);
		attr = ep;
	}
}

bool service::load(FILE *fp, keynode *node)
{
	assert(fp != NULL);

	char *cp, *ep, *bp, *id;
	ssize_t len = 0;
	bool rtn = false;
	bool document = false, empty;
	keynode *top;

	if(!node) {
		node = &root;
		top = NULL;
	}
	else
		top = node->getParent();

	if(!fp)
		return false;

	buffer = "";

	while(node != top) {
		cp = buffer.c_mem() + buffer.len();
		if(buffer.len() < 1024 - 5) {
			len = fread(cp, 1, 1024 - buffer.len() - 1, fp);
		}
		else
			len = 0;

		if(len < 0)
			goto exit;

		cp[len] = 0;
		if(!buffer.chr('<'))
			goto exit;

		cp = buffer.c_mem();

		while(node != top && cp && *cp)
		{
			cp = String::trim(cp, " \t\r\n");

			if(cp && *cp && !node)
				goto exit;

			bp = strchr(cp, '<');
			if(bp == cp && String::equal(bp, "<!--", 4)) {
				ep = strstr(cp, "-->");
				if(ep) {
					cp = ep + 3;
					break;
				}
			}
			else
				ep = strchr(cp, '>');
			if(!ep && bp == cp)
				break;
			if(!bp ) {
				cp = cp + strlen(cp);
				break;
			}
			if(bp > cp) {
				if(node->getPointer() != NULL)
					goto exit;

				*bp = 0;
				cp = String::chop(cp, " \r\n\t");
				len = strlen(cp);
				ep = (char *)memalloc::alloc(len + 1);
				xmldecode(ep, len + 1, cp);
				node->setPointer(ep);
				*bp = '<';
				cp = bp;
				continue;
			}

			empty = false;	
			*ep = 0;
			if(*(ep - 1) == '/') {
				*(ep - 1) = 0;
				empty = true;
			}
			cp = ++ep;

			if(!strncmp(bp, "</", 2)) {
				if(strcmp(bp + 2, node->getId())) {
                                    process::errlog(ERRLOG, 
					    "No matching opening token found for: %s", node->getId());		
					goto exit;
                                }

				node = node->getParent();
				continue;
			}		

			++bp;

			// if comment/control field...
			if(!isalnum(*bp))
				continue;

			ep = bp;
			while(isalnum(*ep))
				++ep;

			id = NULL;
			if(isspace(*ep))
				id = ep;

			while(id && *id && isspace(*id))
				*(id++) = 0;

			if(!document) {
				if(strcmp(node->getId(), bp))
					goto exit;
				document = true;
				continue;
			}

			node = addNode(node, bp, NULL);
			if(id)
				addAttributes(node, id);
			if(empty)
				node = node->getParent();
		}
		buffer = cp;
	}
	if(node == top)
		rtn = true;
exit:
	fclose(fp);
	return rtn;
}

void service::startup(void)
{
	linked_pointer<callback> sp;

	memset(&peering, 0, sizeof(peering));

	process::errlog(NOTICE, "startup");

	cdr::start();

	for(unsigned int level = 0;level < (sizeof(callback::runlevels) / sizeof(LinkedObject *));++level) {
		sp = callback::runlevels[level];
		while(sp) {
			sp->start(cfg);
			sp.next();
		}
	}
}

void service::shutdown(void)
{
	linked_pointer<callback> sp;
	unsigned level = RUNLEVELS;

	while(level--) {
		sp = callback::runlevels[level];
		while(sp) {
			sp->stop(cfg);
			sp.next();
		}
	}

	cdr::stop();
}

void service::dump(FILE *fp, service::keynode *root, unsigned level)
{
	assert(fp != NULL);
	assert(root != NULL);

	unsigned offset;
	const char *id, *value;
	service::keynode *child;
	linked_pointer<service::keynode> node = root;
	while(node) {
		id = node->getId();
		value = node->getPointer();
		child = node->getFirst();
		offset = level;
		while(offset--)
			fputc(' ', fp);
		if(child && value && id)
			fprintf(fp, "%s(%s):\n", id, value);
		else if(child && id)
			fprintf(fp, "%s:\n", id);
		else if(value && id)
			fprintf(fp, "%s=%s\n", id, value);
		else if(id)
			fprintf(fp, "%s\n", id);
		if(child)
			dump(fp, child, level + 2);		
		node.next();
	}
}

void service::dump(FILE *fp)
{
	assert(fp != NULL);

	fprintf(fp, "Config ");
	dump(fp, &root, 0);
}

void service::history(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	keynode *env = getEnviron();

	if(!uid)
		uid = getValue(env, "USER");

	process::histlog(uid);
	release(env);
}

void service::dumpfile(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	linked_pointer<callback> cb;
	keynode *env = getEnviron();

	if(!uid)
		uid = getValue(env, "USER");

	FILE *fp = process::dumpfile(uid);

	release(env);

	if(!fp) {
		process::errlog(ERRLOG, "dump cannot access file");
		return;
	}

	process::errlog(DEBUG1, "dumping config");
	locking.access();
	if(cfg)
		cfg->service::dump(fp);
	locking.release();
	fclose(fp);
}

bool service::period(long slice)
{
	assert(slice > 0);

	time_t now, next;
	struct tm *dt;

	slice *= 60l;	// convert to minute intervals...
	time(&now);
	next = ((periodic / slice) + 1l) * slice;
	if(now < next)
		return false;

	next = (now / slice) * slice;

	FILE *fp = process::statfile();

	if(fp) {
		dt = localtime(&periodic);

		if(dt->tm_year < 1900)
			dt->tm_year += 1900;

		fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d %ld\n",
			dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
			dt->tm_hour, dt->tm_min, dt->tm_sec, next - periodic);
	}
	periodic = next;
	stats::period(fp);
	if(fp)
		fclose(fp);

	linked_pointer<modules::sipwitch> cb = service::getModules();
	while(is(cb)) {
		cb->period(slice);
		cb.next();
	}
	return true;
}

void service::snapshot(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	linked_pointer<callback> cb;
	unsigned rl = 0;
	keynode *env = getEnviron();

	if(!uid)
		uid = getValue(env, "USER");

	FILE *fp = process::snapshot(uid);
	release(env);

	if(!fp) {
		process::errlog(ERRLOG, "snapshot; cannot access file");
		return;
	}

	process::errlog(DEBUG1, "snapshot started");

	while(rl < RUNLEVELS) {
		cb = callback::runlevels[rl++];
		while(cb) {
			cb->snapshot(fp);
			cb.next();
		}
	}
	locking.access();
	if(cfg)
		cfg->dump(fp);
	locking.release();
	fclose(fp);
	process::errlog(DEBUG1, "snapshot completed");
}

void service::confirm(const char *user)
{
}

bool service::check(void)
{
	linked_pointer<callback> cb;
	unsigned rl = 0;
	bool rtn = true;

	while(rtn && rl < RUNLEVELS) {
		cb = callback::runlevels[rl++];
		while(rtn && is(cb)) {
			rtn = cb->check();
			cb.next();
		}
	}
	return rtn;
}

void service::commit(const char *user)
{
	service *orig;
	linked_pointer<callback> cb;
	unsigned rl = 0;

	while(rl < RUNLEVELS) {
		cb = callback::runlevels[rl++];
		while(is(cb)) {
			cb->reload(this);
			cb.next();
		}
	}

	confirm(user);

	locking.modify();
	orig = cfg;
	cfg = this;
	locking.commit();

	// let short-term volatile references settle before we delete it...
	if(orig) {
		Thread::sleep(1000);
		delete orig;
	}
}

FILE *service::open(const char *uid, const char *cfgfile)
{
	assert(cfgfile == NULL || *cfgfile != 0);
	assert(uid == NULL || *uid != 0);

	if(!cfgfile)
		cfgfile = getenv("CFG");

	if(cfgfile && *cfgfile) {
		process::errlog(DEBUG1, "loading config from %s", cfgfile);
		return fopen(cfgfile, "r");
	}

	return process::config(uid);
}

bool service::match(const char *digits, const char *match, bool partial)
{
	assert(digits != NULL);
	assert(match != NULL);

	unsigned len = strlen(match);
	unsigned dlen = 0;
	bool inc;
	const char *d = digits;
	char dbuf[32];

	if(*d == '+')
		++d;

	while(*d && dlen < sizeof(dbuf) - 1) {
		if(isdigit(*d) || *d == '*' || *d == '#') {
			dbuf[dlen++] = *(d++);
			continue;
		}

		if(*d == ' ' || *d == ',') {
			++d;
			continue;
		}

		if(*d == '!')
			break;

		if(!stricmp(digits, match))
			return true;

		return false;
	}

	if(*d && *d != '!')
		return false;

	digits = dbuf;
	dbuf[dlen] = 0;

	if(*match == '+') {
		++match;
		--len;
		if(dlen < len)
			return false;
		digits += (len - dlen);
	}

	while(*match && *digits) {
		inc = true;
		switch(*match) {
		case 'x':
		case 'X':
			if(!isdigit(*digits))
				return false;
			break;
		case 'N':
		case 'n':
			if(*digits < '2' || *digits > '9')
				return false;
			break;
		case 'O':
		case 'o':
			if(*digits && *digits != '1')
				inc = false;
			break;
		case 'Z':
		case 'z':
			if(*digits < '1' || *digits > '9')
				return false;
			break;
		case '?':
			if(!*digits)
				return false;
			break;
		default:
			if(*digits != *match)
				return false;
		}
		if(*digits && inc)
			++digits;
		++match;
	}
	if(*match && !*digits)
		return partial;

	if(*match && *digits)
		return false;

	return true;
}


