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

#include <config.h>
#include <gnutelephony/service.h>
#include <gnutelephony/process.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>

#define	RUNLEVELS	(sizeof(callback::runlevels) / sizeof(LinkedObject *))

using namespace UCOMMON_NAMESPACE;

LinkedObject *service::subscriber::list = NULL;
rwlock_t service::subscriber::locking;
LinkedObject *service::callback::runlevels[4] = {NULL, NULL, NULL, NULL};
unsigned service::callback::count = 0;
condlock_t service::locking;
service *service::cfg = NULL;

static char header[80] = "- welcome";
static SOCKET trap4 = -1;
static SOCKET trap6 = -1;
static time_t started = 0l;

static size_t xmldecode(char *out, size_t limit, const char *src)
{
	char *ret = out;

	assert(src != NULL && out != NULL && limit > 0);

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

service::pointer::pointer()
{
	node = NULL;
}

service::pointer::pointer(const char *id)
{
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

service::subscriber::subscriber(const char *name, const char *cmds) :
LinkedObject(&list)
{
	strcpy(path, name);
#ifdef	_MSWINDOWS_
	fd = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	fd = ::open(path, O_RDWR);
#endif
	if(!cmds)
		cmds = "";
	string::set(listen, sizeof(listen), cmds);
	write(header);
}

void service::subscriber::close(void)
{
#ifdef	_MSWINDOWS_
	if(fd != INVALID_HANDLE_VALUE)
		CloseFile(fd);
	fd = INVALID_HANDLE_VALUE;
#else
	if(fd > -1)
		::close(fd);
	fd = -1;
#endif
}

void service::subscriber::reopen(const char *cmds)
{
	close();
#ifdef	_MSWINDOWS_
	fd = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	fd = ::open(path, O_RDWR);
#endif
	write(header);

	if(!cmds)
		cmds = "";
	string::set(listen, sizeof(listen), cmds);
}

void service::subscriber::write(char *str)
{
	exclusive_access(mutex);

	size_t len = strlen(str);

	if(str[len - 1] != '\n')
		str[len++] = '\n';

#ifdef	_MSWINDOWS_
	DWORD result = 0;

	if(fd != INVALID_HANDLE_VALUE) {
		WriteFile(fd, str, (DWORD)len, &result, NULL);
		if(result < len) {
			CloseFile(fd);
			fd = INVALID_HANDLE_VALUE;
		}
	}
#else
	if(fd > -1) {
		while(::write(fd, str, len) < (int)len) {
			if(errno != EAGAIN) {
				::close(fd);
				fd = -1;
				break;
			}
			Thread::sleep(10);
		}
	}
#endif
}

service::callback::callback(unsigned rl, const char *name) :
OrderedObject()
{
	crit(rl < RUNLEVELS, "service runlevel invalid");
	LinkedObject::enlist(&runlevels[rl]);
	id = name;
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


bool service::callback::reload(service *keys)
{
	return true;
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

service::service(char *name, size_t s) :
mempager(s), root()
{
	keynode *env;
	
	static char *vars[] = {"HOME", "USER", "IDENT", "PATH", "LANG", "PWD", "TZ", "TMP", "SHELL", "CFG", NULL};
	char **varp = vars;
	const char *cp;

	root.setId(name);
	root.setPointer(NULL);
	snmpservers = NULL;
	community = "public";
	if(!started)
		time(&started);

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
	mempager::purge();
}

void service::setHeader(const char *h)
{
	string::set(header, sizeof(header) - 1, h);
}

long service::uptime(void)
{
	time_t now;
	time(&now);
	if(!started)
		return 0l;

	return now - started;
}

void service::snmptrap(unsigned id, const char *descr)
{
	static unsigned char header1_short[] = {
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xc7, 0x42,
		0x40, 0x04, 0xc0, 0xa8, 0x3b, 0xcd};

	static unsigned char header1_long[] = {
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xc7, 0x42,
		0x40, 0x04, 0xc0, 0xa8, 0x3b, 0xcd};

	static unsigned char header2[] = {
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04};

	if(!cfg)
		return;

	linked_pointer<snmpserver> servers = cfg->snmpservers;
	unsigned char buf[128];
	unsigned id1 = id, id2 = 0;
	unsigned len;
	long timestamp = uptime() * 100l;
	unsigned offset1 = 7 + strlen(cfg->community);
	unsigned offset2 = offset1 + sizeof(header1_long);
	unsigned lo1 = 1;
	unsigned lo2 = offset1 + 1;

	if(!servers)
		return;

	if(id1 > 6) {
		id2 = id1;
		id1 = 6;
	}

	buf[0] = 0x30;
	buf[2] = 0x02;
	buf[3] = 0x01;
	buf[4] = 0x00;
	buf[5] = 0x04;
	buf[6] = strlen(cfg->community);

	strcpy((char *)(buf + 7), cfg->community);
	buf[offset1] = 0xa4;

	if(descr)
	memcpy(buf + offset1 + 2, header1_long, sizeof(header1_long));
	else
	memcpy(buf + offset1 + 2, header1_short, sizeof(header1_short));

	buf[offset2] = 0x02;
	buf[offset2 + 1 ] = 0x01;
	buf[offset2 + 2] = id1;
	buf[offset2 + 3] = 0x02;
	buf[offset2 + 4] = 0x01;
	buf[offset2 + 5] = id2;

	buf[offset2 + 6] = 0x43;
	buf[offset2 + 7] = 0x04;
	buf[offset2 + 8] = timestamp / 0x1000000l;
	buf[offset2 + 9] = (timestamp / 0x10000l) & 0xff;
	buf[offset2 + 10] = (timestamp / 0x100l) & 0xff;
	buf[offset2 + 11] = timestamp & 0xff;
	buf[offset2 + 12] = 0x30;

	if(!descr) {
		buf[offset2 + 13] = 0x00;
		len = offset2 + 14;
		goto send;
	}

	buf[offset2 + 13] = strlen(descr) + 14;
	buf[offset2 + 14] = 0x30;
	buf[offset2 + 15] = strlen(descr) + 12;
	memcpy(buf + offset2 + 16, header2, sizeof(header2));
	offset2 += 16 + sizeof(header2);
	buf[offset2] = strlen(descr);
	strcpy((char *)(buf + offset2 + 1), descr);
	len = offset2 + 1 + strlen(descr);

send:
	buf[lo1] = len - 2;
	buf[lo2] = len - 15;

	while(servers) {
		int on = 1;
		socklen_t alen = Socket::getlen((struct sockaddr *)&servers->server);
		switch(servers->server.sa_family) {
#ifdef	AF_INET6
		case AF_INET6:
			if(trap6 == INVALID_SOCKET) {
				trap6 = socket(AF_INET6, SOCK_DGRAM, 0);
				setsockopt(trap6, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
			}
			sendto(trap6, buf, len, 0, (struct sockaddr *)&servers->server, alen);
			break;
#endif
		case AF_INET:
			if(trap4 == INVALID_SOCKET) {
				trap4 = socket(AF_INET, SOCK_DGRAM, 0);
				setsockopt(trap4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
			}
			sendto(trap4, buf, len, 0, (struct sockaddr *)&servers->server, alen);
			break;
		}
		servers.next();
	}
}

service::keynode *service::path(const char *id)
{
	if(!cfg)
		return NULL;

	return cfg->getPath(id);
}

service::keynode *service::list(const char *id)
{
	keynode *node;

	if(!cfg)
		return NULL;

	node = cfg->getPath(id);
	if(node)
		return node->getFirst();
	return NULL;
}


service::keynode *service::getProtected(const char *id)
{
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
	keynode *base = getPath(path);
	if(!base)
		return NULL;

	return base->getFirst();
}

void service::release(keynode *node)
{
	if(node)
		locking.release();
}

service::keynode *service::getPath(const char *id)
{
	const char *np;
	char buf[65];
	char *ep;
	keynode *node = &root, *child;

	while(id && *id && node) {
		string::set(buf, sizeof(buf), id);
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
	caddr_t mp;
	keynode *node;
	char *cp;

	mp = (caddr_t)mempager::alloc(sizeof(keynode));
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
	node = node->getChild(id);
	if(!node)
		return NULL;

	return node->getPointer();
}

service::keynode *service::addNode(keynode *base, define *defs)
{
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
	linked_pointer<keynode> node = base->getFirst();
	keynode *leaf;
	char *cp;

	while(node) {
		if(!strcmp(id, node->getId())) {
			leaf = node->getLeaf(attr);
			if(leaf) {
				cp = leaf->getData();
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
	linked_pointer<keynode> node = base->getFirst();
	char *cp;
	
	while(node) {
		if(!strcmp(id, node->getId())) {
			cp = node->getData();
			if(cp && !stricmp(cp, text))
				return *node;
		}
		node.next();
	}
	return NULL;
} 

void service::addAttributes(keynode *node, char *attr)
{
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
		id = string::trim(id, " \t\r\n");
		while(isspace(*attr))
			++attr;
	
		qt = attr;
		ep = strchr(++attr, *qt);
		if(!ep)
			return;

		*(ep++) = 0;
		len = strlen(attr);
		qt = (char *)mempager::alloc(len + 1);
		xmldecode(qt, len + 1, attr);
		addNode(node, id, qt);
		attr = ep;
	}
}

bool service::load(FILE *fp, keynode *node)
{
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
			cp = string::trim(cp, " \t\r\n");

			if(cp && *cp && !node)
				goto exit;

			bp = strchr(cp, '<');
			ep = strchr(cp, '>');
			if(!ep && bp == cp)
				break;
			if(!bp ) {
				cp = cp + strlen(cp);
				break;
			}
			if(bp > cp) {
				if(node->getData() != NULL)
					goto exit;

				*bp = 0;
				cp = string::chop(cp, " \r\n\t");
				len = strlen(cp);
				ep = (char *)mempager::alloc(len + 1);
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
				if(strcmp(bp + 2, node->getId()))
					goto exit;

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

void service::unsubscribe(const char *path)
{
	exclusive_access(subscriber::locking);
	linked_pointer<subscriber> sb;

	crit(cfg != NULL, "unsubscribe without config");

	sb = subscriber::list;
	while(sb) {
		if(!stricmp(sb->path, path))
			break;
		sb.next();
	}
	if(sb) 
		sb->close();
}

void service::publish(const char *path, const char *fmt, ...)
{
	linked_pointer<subscriber> sb;
	char buf[512];
	char cmdbuf[16];
	va_list args;
	int fd;
	unsigned len;
	const char *cp;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if(path) {
		cp = strrchr(path, '/');
		if(cp && !stricmp(cp, "/control"))
			goto control;
		len = strlen(buf);
		fd = ::open(path, O_WRONLY | O_NONBLOCK);
		if(fd > -1) {
			if(buf[len - 1] != '\n')
				buf[len++] = '\n';
			::write(fd, buf, len);
			::close(fd);
		}
		return;
	}

control:
	protected_access(subscriber::locking);

	cmdbuf[0] = 0;
	if(!path && (*fmt == '-' || *fmt == '-') && isspace(fmt[1])) {
		cp = fmt + 1;
		while(isspace(*cp))
			++cp;
		len = 0;
		while(len < sizeof(cmdbuf) - 1 && isalnum(*cp)) {
			cmdbuf[len++] = tolower(*cp);
			++cp;
		}
		cmdbuf[len] = 0;
	}

	sb = subscriber::list;
	while(sb) {
		if(path) {
			if(stricmp(sb->path, path))
				sb->write(buf);
		}
		else if(!cmdbuf[0] || string::ifind(sb->listen, cmdbuf, " ,;: \t\n"))
			sb->write(buf);
		sb.next();
	}
}

void service::subscribe(const char *path, const char *listen)
{
	exclusive_access(subscriber::locking);
	linked_pointer<subscriber> sb;
	caddr_t mp;

	crit(cfg != NULL, "subscribe without subscribe");

	if(!listen || !stricmp(listen, "*") || !stricmp(listen, "all"))
		listen = "";

	sb = subscriber::list;
	while(sb) {
		if(!stricmp(sb->path, path))
			break;
		sb.next();
	}
	if(sb) {
		sb->reopen(listen);
		return;
	}
	mp = (caddr_t)cfg->alloc(sizeof(subscriber) + strlen(path));
	new(mp) subscriber(path, listen);
}

void service::startup(bool restartable)
{
	linked_pointer<callback> sp;

	if(restartable)
		process::restart();

	process::errlog(NOTICE, "startup");

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

	process::release();
	publish(NULL, "- shutdown");

	while(level--) {
		sp = callback::runlevels[level];
		while(sp) {
			sp->stop(cfg);
			sp.next();
		}
	}
}

void service::dump(FILE *fp, service::keynode *root, unsigned level)
{
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
	fprintf(fp, "Config ");
	dump(fp, &root, 0);
}

void service::dumpfile(const char *id, const char *uid)
{
	FILE *fp;
	char buf[256];
	linked_pointer<callback> cb;
	keynode *env = getEnviron();

	if(!id)
		id = getValue(env, "IDENT");

	if(!uid)
		uid = getValue(env, "USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/dumpfile", id);
	fp = fopen(buf, "w");
	if(!fp) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/dumpfile", id, uid);
		fp = fopen(buf, "w");
	}

	release(env);

	if(!fp) {
		process::errlog(ERROR, "dump cannot access file");
		return;
	}

	process::errlog(DEBUG1, "dumping config");
	locking.access();
	if(cfg)
		cfg->service::dump(fp);
	locking.release();
	fclose(fp);
}

void service::snapshot(const char *id, const char *uid)
{
	FILE *fp;
	char buf[256];
	linked_pointer<callback> cb;
	unsigned rl = 0;
	keynode *env = getEnviron();

	if(!id)
		id = getValue(env, "IDENT");

	if(!uid)
		uid = getValue(env, "USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/snapshot", id);
	fp = fopen(buf, "w");
	if(!fp) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/snapshot", id, uid);
		fp = fopen(buf, "w");
	}

	release(env);

	if(!fp) {
		process::errlog(ERROR, "snapshot; cannot access file");
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

bool service::confirm(const char *user)
{
	return true;
}

service::callback *service::getComponent(const char *id)
{
	linked_pointer<callback> cb;
	unsigned rl = 0;

	while(rl < RUNLEVELS) {
		cb = callback::runlevels[rl++];
		while(cb) {
			if(cb->isActive() && cb->id && !stricmp(cb->id, id))
				return *cb;
			cb.next();
		}
	}
	return NULL;
}

bool service::check(void)
{
	linked_pointer<callback> cb;
	unsigned rl = 0;
	bool rtn = true;

	while(rtn && rl < RUNLEVELS) {
		cb = callback::runlevels[rl++];
		while(rtn && cb) {
			rtn = cb->check();
			cb.next();
		}
	}
	return rtn;
}

bool service::commit(const char *user)
{
	linked_pointer<callback> cb;
	unsigned rl = 0;
	bool rtn = true;

	while(rtn && rl < RUNLEVELS) {
		cb = callback::runlevels[rl++];
		while(rtn && cb) {
			rtn = cb->reload(this);
			cb.next();
		}
	}

	if(!rtn || !confirm(user))
		return false;

	locking.modify();
	cfg = this;
	locking.commit();
	return true;
}

FILE *service::open(const char *id, const char *uid, const char *cfgfile)
{
	char buf[128];
	struct stat ino;
	FILE *fp;

	if(!cfgfile)
		cfgfile = getenv("CFG");

	if(cfgfile && *cfgfile) {
		process::errlog(DEBUG1, "loading config from %s", cfgfile);
		return fopen(cfgfile, "r");
	}

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", id);
	if(uid && !stat(buf, &ino) && S_ISDIR(ino.st_mode)) {
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/config.xml", id);
		fp = fopen(buf, "r");
		if(fp) {
			process::errlog(DEBUG1, "loading config from %s", buf);
			return fp;
		}
	}

	if(uid)
		snprintf(buf, sizeof(buf), DEFAULT_CFGPATH "/%s.xml", id);
	else
		snprintf(buf, sizeof(buf), "%s/.gnutelephony/%s.xml", getenv("HOME"), id); 
	process::errlog(DEBUG1, "loading config from %s", buf);
	return fopen(buf, "r");
}

bool service::match(const char *digits, const char *match, bool partial)
{
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


