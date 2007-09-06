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
#include <gnutelephony/process.h>
#include <gnutelephony/service.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

using namespace UCOMMON_NAMESPACE;

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

static char fifopath[128] = "";

static size_t ctrlfile(const char *id, const char *uid)
{
	struct stat ino;

	snprintf(fifopath, sizeof(fifopath), DEFAULT_VARPATH "/run/%s", id);
	if(!stat(fifopath, &ino) && S_ISDIR(ino.st_mode)) 
		snprintf(fifopath, sizeof(fifopath), DEFAULT_VARPATH "/run/%s/control", id);
	else
		snprintf(fifopath, sizeof(fifopath), "/tmp/%s-%s/control", id, uid);

	remove(fifopath);
	if(mkfifo(fifopath, 0660)) {
		fifopath[0] = 0;
		return 0;
	}

	fifo = fopen(fifopath, "r+");
	if(fifo) 
		return 512;
	fifopath[0] = 0;
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

static const char *replytarget = NULL;

errlevel_t process::verbose = FAILURE;

void process::errlog(errlevel_t loglevel, const char *fmt, ...)
{
	char buf[256];
	int level = LOG_ERR;
	va_list args;	

	va_start(args, fmt);

	assert(fmt != NULL);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	switch(loglevel)
	{
	case DEBUG1:
	case DEBUG2:
	case DEBUG3:
		if((getppid() > 1) && (loglevel <= verbose)) {
			fprintf(stderr, "%s: %s", getenv("IDENT"), buf);
			if(fmt[strlen(fmt) - 1] != '\n') 
				fputc('\n', stderr);
			fflush(stderr);
		}
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
	default:
		level = LOG_ERR;
	}

	if(loglevel <= verbose) {
		if(getppid() > 1) {
			fprintf(stderr, "%s: %s", getenv("IDENT"), buf);
			if(fmt[strlen(fmt) - 1] != '\n') 
				fputc('\n', stderr);
			fflush(stderr);
		}

		service::snmptrap(loglevel + 10, buf);
		service::publish(NULL, "- log %d %s", loglevel, buf); 
		::syslog(level, "%s", buf);
	}
	
	if(level == LOG_CRIT)
		abort();
}

void process::release(void)
{
	errlog(INFO, "shutdown");
	if(fifopath[0]) {
		::remove(fifopath);
		fifopath[0] = 0;
	}
}

void process::restart(void)
{
	pid_t pid;
	int status;

restart:
	pid = fork();
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
}

bool process::control(const char *id, const char *uid, const char *fmt, ...)
{
	char buf[512];
	int fd, len;
	bool rtn = true;
	va_list args;
	service::keynode *env = service::getEnviron();

	va_start(args, fmt);
	if(!id)
		id = service::getValue(env, "IDENT");

	if(!uid)
		uid = service::getValue(env, "USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/control", id);
	fd = ::open(buf, O_WRONLY | O_NONBLOCK);
	if(fd < 0) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/control", id, uid);
		fd = ::open(buf, O_WRONLY | O_NONBLOCK);
	}
	service::release(env);
	if(fd < 0)
		return false;

	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);
	len = strlen(buf);
	if(buf[len - 1] != '\n')
		buf[len++] = '\n';
	if(::write(fd, buf, len) < len)
		rtn = false;
	::close(fd);
	return rtn;
}

char *process::receive(void)
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

void process::reply(const char *msg)
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
			service::publish(replytarget, "%s msg %s", sid, msg);
		else
			service::publish(replytarget, "%s ok", sid);
	}
	replytarget = NULL;
}

void process::util(const char *id)
{
	signal(SIGPIPE, SIG_IGN);
	setenv("IDENT", id, 1);
	openlog(id, 0, LOG_USER);
}

void process::foreground(const char *id, const char *uid, const char *cfgpath, unsigned priority, size_t ps)
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

void process::background(const char *id, const char *uid, const char *cfgpath, unsigned priority, size_t ps)
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
