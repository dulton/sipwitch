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
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#define	RUNLEVELS	(sizeof(callback::runlevels) / sizeof(LinkedObject *))

using namespace UCOMMON_NAMESPACE;

LinkedObject *service::subscriber::list = NULL;
rwlock_t service::subscriber::locking;
LinkedObject *service::callback::runlevels[4] = {NULL, NULL, NULL, NULL};
unsigned service::callback::count = 0;
condlock_t service::locking;
service *service::cfg = NULL;
service::errlevel_t service::verbose = FAILURE;

#ifndef	_MSWINDOWS_

#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <limits.h>

#ifndef	OPEN_MAX
#define	OPEN_MAX 20
#endif

#ifdef  SIGTSTP
#include <sys/file.h>
#include <sys/ioctl.h>
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) ((unsigned)(status) >> 8)
#endif

#ifndef	_PATH_TTY
#define	_PATH_TTY	"/dev/tty"
#endif

static FILE *fifo = NULL;

static void detach(void)
{
	const char *dev = "/dev/null";
	pid_t pid;
	int fd;

	close(0);
	close(1);
	close(2);
#ifdef	SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif

#ifdef	SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif

#ifdef	SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
	pid = fork();
	if(pid > 0)
		exit(0);
	crit(pid == 0);

#if defined(SIGTSTP) && defined(TIOCNOTTY)
	crit(setpgid(0, getpid()) == 0);
	if((fd = open(_PATH_TTY, O_RDWR)) >= 0) {
		ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#else

#ifdef HAVE_SETPGRP
	crit(setpgrp() == 0);
#else
	crit(setpgid(0, getpid()) == 0);
#endif
	signal(SIGHUP, SIG_IGN);
	pid = fork();
	if(pid > 0)
		exit(0);
	crit(pid == 0);
#endif
	if(dev && *dev) {
		fd = open(dev, O_RDWR);
		if(fd > 0)
			dup2(fd, 0);
		if(fd != 1)
			dup2(fd, 1);
		if(fd != 2)
			dup2(fd, 2);
		if(fd > 2)
			close(fd);
	}
}

static void scheduler(int priority)
{
#if _POSIX_PRIORITY_SCHEDULING > 0
	int policy = SCHED_OTHER;

	if(priority > 0)
		policy = SCHED_RR;

	struct sched_param sparam;
    int min = sched_get_priority_min(policy);
    int max = sched_get_priority_max(policy);
	int pri = (int)priority;

	if(min == max)
		pri = min;
	else 
		pri += min;
	if(pri > max)
		pri = max;

	setpriority(PRIO_PROCESS, 0, -priority);
	memset(&sparam, 0, sizeof(sparam));
	sparam.sched_priority = pri;
	sched_setscheduler(0, policy, &sparam);	
#else
	nice(-priority);
#endif
}

static struct passwd *getuserenv(const char *id, const char *uid, const char *cfgfile)
{
	struct passwd *pwd;
	struct group *grp;
	char buf[128];
	struct stat ino;
	
	if(!cfgfile || !*cfgfile) 
		setenv("CFG", "", 1);
	else if(*cfgfile == '/')
		setenv("CFG", cfgfile, 1);
	else {			
		getcwd(buf, sizeof(buf));
		string::add(buf, sizeof(buf), "/");
		string::add(buf, sizeof(buf), cfgfile);
		setenv("CFG", buf, 1);
	}

	if(uid) {
		umask(007);
		pwd = getpwnam(uid);
		if(pwd)
			setgid(pwd->pw_gid);
		else {
			pwd = getpwuid(getuid());
			grp = getgrnam(uid);
			if(grp)
				setgid(grp->gr_gid);
		}
	}
	else {
		umask(077);
		pwd = getpwuid(getuid());
	}

	if(!pwd) {
		fprintf(stderr, "*** %s: unkown user identity; exiting\n", id);
		exit(-1);
	}

	if(uid) {
		mkdir(pwd->pw_dir, 0770);
		setenv("PWD", pwd->pw_dir, 1);
		if(!chdir(pwd->pw_dir)) {
			snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/lib/%s", id);
			mkdir(buf, 0770);
			chdir(buf);
			setenv("PWD", buf, 1);
		}
	}
	else {
		snprintf(buf, sizeof(buf), "%s/.%s", pwd->pw_dir, id);
		mkdir(buf, 0700);
		chdir(buf);
		setenv("PWD", buf, 1);
	} 

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", id);
	mkdir(buf, 0775);
	if(stat(buf, &ino) || !S_ISDIR(ino.st_mode)) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s", id, pwd->pw_name);
		mkdir(buf, 0770);
	}

	snprintf(buf, sizeof(buf), "%d", pwd->pw_uid);
	setenv("IDENT", id, 1);
	setenv("UID", buf, 1);
	setenv("USER", pwd->pw_name, 1);
	setenv("HOME", pwd->pw_dir, 1);
	return pwd;
}

static bool control(const char *id, const char *uid, const char *fmt, va_list args)
{
	char buf[512];
	int fd, len;
	bool rtn = true;

	if(!uid)
		uid = getenv("USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/control", id);
	fd = open(buf, O_WRONLY | O_NONBLOCK);
	if(fd < 0) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/control", id, uid);
		fd = open(buf, O_WRONLY | O_NONBLOCK);
	}
	if(fd < 0)
		return false;

	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	len = strlen(buf);
	if(buf[len - 1] != '\n')
		buf[len++] = '\n';
	if(write(fd, buf, len) < len)
		rtn = false;
	close(fd);
	return rtn;
}

static size_t ctrlfile(const char *id, const char *uid)
{
	char buf[65];
	struct stat ino;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", id);
	if(!stat(buf, &ino) && S_ISDIR(ino.st_mode)) 
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/control", id);
	else
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/control", id, uid);

	remove(buf);
	if(mkfifo(buf, 0660))
		return 0;

	fifo = fopen(buf, "r+");
	if(fifo) 
		return 512;
	else
		return 0;
}

static pid_t pidfile(const char *id, const char *uid)
{
	struct stat ino;
	time_t now;
	char buf[128];
	fd_t fd;
	pid_t pid;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", id);
	if(!stat(buf, &ino) && S_ISDIR(ino.st_mode)) 
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/pidfile", id);
	else
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/pidfile", id, uid);

	fd = open(buf, O_RDONLY);
	if(fd < 0 && errno == EPERM)
		return 1;

	if(fd < 0)
		return 0;

	if(read(fd, buf, 16) < 1) {
		goto bydate;
	}
	buf[16] = 0;
	pid = atoi(buf);
	if(pid == 1)
		goto bydate;

	close(fd);
	if(kill(pid, 0) && errno == ESRCH)
		return 0;

	return pid;

bydate:
	time(&now);
	fstat(fd, &ino);
	close(fd);
	if(ino.st_mtime + 30 < now)
		return 0;
	return 1;
}

static pid_t pidfile(const char *id, const char *uid, pid_t pid)
{
	char buf[128];
	pid_t opid;
	struct stat ino;
	fd_t fd;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", id);
	if(!stat(buf, &ino) && S_ISDIR(ino.st_mode))
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/pidfile", id);
	else
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/pidfile", id, uid);

retry:
	fd = open(buf, O_CREAT|O_WRONLY|O_TRUNC|O_EXCL, 0755);
	if(fd < 0) {
		opid = pidfile(id, uid);
		if(!opid || opid == 1 && pid > 1) {
			remove(buf);
			goto retry;
		}
		return opid;
	}

	if(pid > 1) {
		snprintf(buf, sizeof(buf), "%d\n", pid);
		write(fd, buf, strlen(buf));
	}
	close(fd);
	return 0;
}

#endif

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

service::subscriber::subscriber(const char *name) :
LinkedObject(&list)
{
	strcpy(path, name);
#ifdef	_MSWINDOWS_
	fd = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	fd = ::open(path, O_RDWR);
#endif
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

void service::subscriber::reopen(void)
{
	close();
#ifdef	_MSWINDOWS_
	fd = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
	fd = ::open(path, O_RDWR);
#endif
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
	crit(rl < RUNLEVELS);
	LinkedObject::enlist(&runlevels[rl]);
	id = name;
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
	root.setId(name);
	root.setPointer(NULL);
}

service::~service()
{
	mempager::purge();
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
	return node;
}

const char *service::getValue(keynode *node, const char *id, keynode *alt)
{
	node = node->getChild(id);
	if(!node && alt)
		node = alt->getChild(id);

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

	crit(cfg != NULL);

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
	va_list args;
	int fd;
	unsigned len;
	char *cp;

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

	sb = subscriber::list;
	while(sb) {
		if(!path || !stricmp(sb->path, path))
			sb->write(buf);
		sb.next();
	}
}

void service::subscribe(const char *path)
{
	exclusive_access(subscriber::locking);
	linked_pointer<subscriber> sb;
	caddr_t mp;

	crit(cfg != NULL);

	sb = subscriber::list;
	while(sb) {
		if(!stricmp(sb->path, path))
			break;
		sb.next();
	}
	if(sb) {
		sb->reopen();
		return;
	}
	mp = (caddr_t)cfg->alloc(sizeof(subscriber) + strlen(path));
	new(mp) subscriber(path);
}

void service::startup(bool restartable)
{
	linked_pointer<callback> sp;

#ifndef _MSWINDOWS_
	pid_t pid;
	int status;

restart:
	pid = 0;
	if(restartable) {
		pid = fork();
	}
	if(pid > 0) {
		waitpid(pid, &status, 0);
		if(WIFSIGNALED(status))
			status = WTERMSIG(status);
		else
			status = WIFEXITED(status);
		switch(status) {
		case SIGPWR:
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
		case 0:
			exit(status);
		default:
			goto restart;
		}
	}
	
#endif

	errlog(NOTICE, "startup");

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

	errlog(NOTICE, "shutdown");

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

	if(!uid)
		uid = getenv("USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/dumpfile", id);
	fp = fopen(buf, "w");
	if(!fp) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/dumpfile", id, uid);
		fp = fopen(buf, "w");
	}

	if(!fp) {
		errlog(ERROR, "dump cannot access file");
		return;
	}

	errlog(DEBUG, "dumping config");
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

	if(!uid)
		uid = getenv("USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/snapshot", id);
	fp = fopen(buf, "w");
	if(!fp) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/snapshot", id, uid);
		fp = fopen(buf, "w");
	}

	if(!fp) {
		errlog(ERROR, "snapshot; cannot access file");
		return;
	}

	errlog(DEBUG, "snapshot started");

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
	errlog(DEBUG, "snapshot completed");
}

bool service::confirm(void)
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
			if(cb->id && !stricmp(cb->id, id))
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

bool service::commit(void)
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

	if(!rtn || !confirm())
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
		errlog(DEBUG, "loading config from %s", cfgfile);
		return fopen(cfgfile, "r");
	}

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", id);
	if(uid && !stat(buf, &ino) && S_ISDIR(ino.st_mode)) {
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/config.xml", id);
		fp = fopen(buf, "r");
		if(fp) {
			errlog(DEBUG, "loading config from %s", buf);
			return fp;
		}
	}

	if(uid)
		snprintf(buf, sizeof(buf), DEFAULT_CFGPATH "/%s.xml", id);
	else
		snprintf(buf, sizeof(buf), "%s/.%s/config.xml", getenv("HOME"), id); 
	errlog(DEBUG, "loading config from %s", buf);
	return fopen(buf, "r");
}

#ifndef	_MSWINDOWS_

static const char *replytarget = NULL;

void service::errlog(errlevel_t loglevel, const char *fmt, ...)
{
	char buf[256];
	int level = LOG_ERR;
	va_list args;
	
	va_start(args, fmt);

	switch(loglevel)
	{
	case DEBUG1:
	case DEBUG2:
	case DEBUG3:
		if((getppid() > 1) && (loglevel <= verbose)) {
			fprintf(stderr, "%s: ", getenv("IDENT"));
			vfprintf(stderr, fmt, args);
			if(fmt[strlen(fmt) - 1] != '\n') 
				fputc('\n', stderr);
			fflush(stderr);
		}
		va_end(args);
		return;
	case INFO:
		level = LOG_INFO;
		break;
	case NOTIFY:
		level = LOG_NOTICE;
		break;
	case WARN:
		level = LOG_WARNING;
		break;
	case ERROR:
		level = LOG_ERR;
		break;
	case FAILURE:
		level = LOG_CRIT;
		break;
	}

	if(loglevel <= verbose) {
		if(getppid() > 1) {
			fprintf(stderr, "%s: ", getenv("IDENT"));
			vfprintf(stderr, fmt, args);
			if(fmt[strlen(fmt) - 1] != '\n') 
				fputc('\n', stderr);
			fflush(stderr);
		}

		vsnprintf(buf, sizeof(buf), fmt, args);
		publish(NULL, "- log %d %s", loglevel, buf); 
		::vsyslog(level, fmt, args);
	}
	
	va_end(args);

	if(level == LOG_CRIT)
		abort();
}

bool service::control(const char *id, const char *uid, const char *fmt, ...)
{
	bool rtn;
	va_list args;

	va_start(args, fmt);
	rtn = ::control(id, uid, fmt, args);
	va_end(args);
	return rtn;
}

char *service::receive(void)
{
	static char buf[512];
	char *cp;

	if(!fifo)
		return NULL;

	reply(NULL);

retry:
	fgets(buf, sizeof(buf), fifo);
	cp = string::strip(buf, " \t\r\n");
	if(*cp == '/') {
		if(strstr(cp, ".."))
			goto retry;

		if(strncmp(cp, "/tmp/.reply.", 12))
			goto retry; 
	}

	if(*cp == '/' || isdigit(*cp)) {
		replytarget = cp;
		while(*cp && !isspace(*cp))
			++cp;
		*(cp++) = 0;
		while(isspace(*cp))
			++cp;
	}	
	return cp;
}

void service::reply(const char *msg)
{
	pid_t pid;
	char *sid;

	if(msg)
		errlog(ERROR, "control failed; %s", msg);

	if(!replytarget)
		return;
	
	if(isdigit(*replytarget)) {
		pid = atoi(replytarget);
		if(msg)
			kill(pid, SIGUSR2);
		else
			kill(pid, SIGUSR1);
	}
	else {
		sid = strchr(replytarget, ';');
		if(sid)
			*(sid++) = 0;
		if(msg)
			publish(replytarget, "%s msg %s", sid, msg);
		else
			publish(replytarget, "%s ok", sid);
	}
	replytarget = NULL;
}

void service::util(const char *id)
{
	signal(SIGPIPE, SIG_IGN);
	setenv("IDENT", id, 1);
	openlog(id, 0, LOG_USER);
}

void service::foreground(const char *id, const char *uid, const char *cfgpath, unsigned priority, size_t ps)
{
	struct passwd *pwd = getuserenv(id, uid, cfgpath);
	pid_t pid;

	if(0 != (pid = pidfile(id, pwd->pw_name, getpid()))) {
		fprintf(stderr, "*** %s: already running; pid=%d\n", id, pid);
		exit(-1);
	}

	if(!ctrlfile(id, pwd->pw_name)) {
		fprintf(stderr, "*** %s: no control file; exiting\n", id);
		exit(-1);
	}

	signal(SIGPIPE, SIG_IGN);
	scheduler(priority);
	setuid(pwd->pw_uid);
	endpwent();
	endgrent();
	openlog(id, 0, LOG_USER);
}

void service::background(const char *id, const char *uid, const char *cfgpath, unsigned priority, size_t ps)
{
	struct passwd *pwd = getuserenv(id, uid, cfgpath);
	pid_t pid;

	if(!ctrlfile(id, pwd->pw_name)) {
		fprintf(stderr, "*** %s: no control file; exiting\n", id);
		exit(-1);
	}

	signal(SIGPIPE, SIG_IGN);
	scheduler(priority);
	endpwent();
	endgrent();

	if(getppid() > 1) {
		if(getppid() > 1 && 0 != (pid = pidfile(id, pwd->pw_name, 1))) {
			fprintf(stderr, "*** %s: already running; pid=%d\n", id, pid);
			exit(-1);
		}
		detach();
	}

	openlog(id, LOG_CONS, LOG_DAEMON);

	if(0 != pidfile(id, pwd->pw_name, getpid())) {
		syslog(LOG_CRIT, "already running; exiting");
		exit(-1);
	}

	setuid(pwd->pw_uid);
}

#endif
