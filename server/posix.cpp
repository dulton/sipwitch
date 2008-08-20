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

#ifndef	_MSWINDOWS_

#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <errno.h>

#ifdef  SIGTSTP
#include <sys/file.h>
#include <sys/ioctl.h>
#endif

#ifndef OPEN_MAX
#define OPEN_MAX 20
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) ((unsigned)(status) >> 8)
#endif

#ifndef _PATH_TTY
#define _PATH_TTY   "/dev/tty"
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

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
	crit(pid == 0, "detach without process");

#if defined(SIGTSTP) && defined(TIOCNOTTY)
	crit(setpgid(0, getpid()) == 0, "detach without process group");
	if((fd = open(_PATH_TTY, O_RDWR)) >= 0) {
		ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#else

#ifdef HAVE_SETPGRP
	crit(setpgrp() == 0, "detach without process group");
#else
	crit(setpgid(0, getpid()) == 0, "detach without process group");
#endif
	signal(SIGHUP, SIG_IGN);
	pid = fork();
	if(pid > 0)
		exit(0);
	crit(pid == 0, "detach without process");
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

static void restart(void)
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
#ifdef	SIGPWR
		case SIGPWR:
#endif
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

static pid_t pidfile(const char *uid)
{
	assert(uid != NULL && *uid != 0);

	struct stat ino;
	time_t now;
	char buf[128];
	fd_t fd;
	pid_t pid;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch");
	if(!stat(buf, &ino) && S_ISDIR(ino.st_mode) && !access(buf, W_OK))
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch/pidfile");
	else 
		snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s/pidfile", uid);

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

static pid_t pidfile(const char *uid, pid_t pid)
{
	assert(uid != NULL && *uid != 0);

	char buf[128];
	pid_t opid;
	struct stat ino;
	fd_t fd;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch");
	if(!stat(buf, &ino) && S_ISDIR(ino.st_mode) && !access(buf, W_OK))
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch/pidfile");
	else 
		snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s/pidfile", uid);

retry:
	fd = open(buf, O_CREAT|O_WRONLY|O_TRUNC|O_EXCL, 0755);
	if(fd < 0) {
		opid = pidfile(uid);
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

static struct passwd *getuserenv(const char *uid, const char *cfgfile)
{
	assert(uid == NULL || *uid != 0);

	struct passwd *pwd;
	struct group *grp;
	char buf[128];
	struct stat ino;
	const char *cp;
	
	if(!cfgfile || !*cfgfile) 
		setenv("CFG", "", 1);
	else if(*cfgfile == '/')
		setenv("CFG", cfgfile, 1);
	else {			
		fsys::getPrefix(buf, sizeof(buf));
		String::add(buf, sizeof(buf), "/");
		String::add(buf, sizeof(buf), cfgfile);
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
		fprintf(stderr, "*** sipw: unkown user identity; exiting\n");
		exit(-1);
	}

	if(uid) {
		fsys::createDir(pwd->pw_dir, 0770);
		setenv("PWD", pwd->pw_dir, 1);
		if(!fsys::changeDir(pwd->pw_dir)) {
			snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/lib/sipwitch");
			fsys::createDir(buf, 0770);
			fsys::changeDir(buf);
			setenv("PWD", buf, 1);
		}
	}
	else {
		snprintf(buf, sizeof(buf), "%s/.sipwitch", pwd->pw_dir);
		fsys::createDir(buf, 0700);
		fsys::changeDir(buf);
		setenv("PWD", buf, 1);
	} 

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch");
	fsys::createDir(buf, 0775);
	if(stat(buf, &ino) || !S_ISDIR(ino.st_mode)) {
		snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s", pwd->pw_name);
		fsys::createDir(buf, 0770);
	}

	snprintf(buf, sizeof(buf), "%d", pwd->pw_uid);
	setenv("IDENT", "sipwitch", 1);
	setenv("UID", buf, 1);
	setenv("USER", pwd->pw_name, 1);
	setenv("HOME", pwd->pw_dir, 1);
	cp = getenv("SHELL");
	if(!cp)
		setenv("SHELL", "/bin/sh", 1);
	return pwd;
}

static void foreground(const char *uid, const char *cfgpath, unsigned priority)
{
	assert(uid == NULL || *uid != 0);

	struct passwd *pwd = getuserenv(uid, cfgpath);
	pid_t pid;

	if(0 != (pid = pidfile(pwd->pw_name, getpid()))) {
		fprintf(stderr, "*** sipw: already running; pid=%d\n", pid);
		exit(-1);
	}

	if(!process::attach(pwd->pw_name)) {
		fprintf(stderr, "*** sipw: no control file; exiting\n");
		exit(-1);
	}

	signal(SIGPIPE, SIG_IGN);
	scheduler(priority);
	setuid(pwd->pw_uid);
	endpwent();
	endgrent();
	openlog("sipw", 0, LOG_USER);
}

static void background(const char *uid, const char *cfgpath, unsigned priority)
{
	assert(uid == NULL || *uid != 0);

	struct passwd *pwd = getuserenv(uid, cfgpath);
	pid_t pid;

	if(!process::attach(pwd->pw_name)) {
		fprintf(stderr, "*** sipw: no control file; exiting\n");
		exit(-1);
	}

	signal(SIGPIPE, SIG_IGN);
	scheduler(priority);
	endpwent();
	endgrent();

	if(getppid() > 1) {
		if(getppid() > 1 && 0 != (pid = pidfile(pwd->pw_name, 1))) {
			fprintf(stderr, "*** sipw: already running; pid=%d\n", pid);
			exit(-1);
		}
		detach();
	}

	openlog("sipw", LOG_CONS, LOG_DAEMON);

	if(0 != pidfile(pwd->pw_name, getpid())) {
		syslog(LOG_CRIT, "already running; exiting");
		exit(-1);
	}

	setuid(pwd->pw_uid);
}

#if defined(HAVE_SETRLIMIT) && defined(DEBUG)
#include <sys/time.h>
#include <sys/resource.h>

static void corefiles(void)
{
	struct rlimit core;

	assert(getrlimit(RLIMIT_CORE, &core) == 0);
#ifdef	MAX_CORE_SOFT
	core.rlim_cur = MAX_CORE_SOFT;
#else
	core.rlim_cur = RLIM_INFINITY;
#endif
#ifdef	MAX_CORE_HARD
	core.rlim_max = MAX_CORE_HARD;
#else
	core.rlim_max = RLIM_INFINITY;
#endif
	assert(setrlimit(RLIMIT_CORE, &core) == 0);
}
#else
static void corefiles(void)
{
}
#endif

static class __LOCAL SignalThread : public JoinableThread
{
private:
	bool shutdown;
	bool started;

public:
	sigset_t sigs;

	SignalThread();
	~SignalThread();

	void run(void);
	void cancel(void);
} sigthread;

SignalThread::SignalThread() :
JoinableThread()
{
	shutdown = started = false;
}

SignalThread::~SignalThread()
{
	if(!shutdown)
		cancel();
}

void SignalThread::cancel()
{
	if(started) {
		shutdown = true;
#ifdef	__FreeBSD__
		raise(SIGINT);
#endif
		pthread_kill(tid, SIGALRM);
		join();
	}
}

void SignalThread::run(void)
{
	const char *uid = getenv("USER");
	int signo;
	unsigned period = 900;

	started = true;
	process::errlog(DEBUG1, "starting signals");

	for(;;) {
		alarm(period);
#ifdef	HAVE_SIGWAIT2
		sigwait(&sigs, &signo);
#else
		signo = sigwait(&sigs);
#endif
		alarm(0);
		if(shutdown)
			join();
		process::errlog(DEBUG1, "received signal %d", signo);
		switch(signo) {
		case SIGALRM:
			process::errlog(INFO, "system housekeeping");
			registry::cleanup(period);
			break;
		case SIGINT:
		case SIGTERM:
			process::control(uid, "down");
			break;
		case SIGUSR1:
			process::control(uid, "snapshot");
			break;
		case SIGHUP:
			process::control(uid, "reload");
			break;
		}
	}
}

#ifdef USES_COMMANDS
static void command(const char *uid, const char *cmd, unsigned timeout)
{
	assert(uid == NULL || *uid != 0);
	assert(cmd != NULL && *cmd != 0);
	assert(timeout > 0);

	sigset_t sigs;
	int signo;

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);

	server::utils(uid);

	if(!process::control(uid, "%d %s", getpid(), cmd)) {
		fprintf(stderr, "*** sipw: %s; server not responding\n", cmd);
		exit(2);
	}

	alarm(timeout);
#ifdef	HAVE_SIGWAIT2
	sigwait(&sigs, &signo);
#else
	signo = sigwait(&sigs);
#endif
	if(signo == SIGUSR1)
		exit(0);
	if(signo == SIGALRM) {
		fprintf(stderr, "*** sipw: %s; server timed out\n", cmd);
		exit(1);
	}
	fprintf(stderr, "*** sipw: %s; request failed\n", cmd);
	exit(3);
}
#endif

extern "C" int main(int argc, char **argv)
{
	static const char *user = NULL;
	static char *plugins = NULL;
	static char *cfgfile = NULL;
	static bool daemon = false;
	static bool warned = false;
	static unsigned verbose = 0;
	static unsigned priority = 0;
	static unsigned concurrency = 0;
	static int exit_code = 0;
	static bool restartable = false;
	static bool dumping = false;

	const char *userid;
	const char *secret;
	const char *text;
	char *cp;
	char *args[65];
	char tbuf[512];
	const char *argv0 = argv[0];

	corefiles();

#ifdef	USES_COMMANDS
	if(argv[1] && (!strcmp(argv[1], "-gdb") || !strcmp(argv[1], "--gdb"))) {
		argc = 0;
		args[argc++] = (char *)"gdb";
		args[argc++] = (char *)"--args";
		args[argc++] = (char *)argv0;
		argv += 2;
		while(*argv && argc < 63)
			args[argc++] = *(argv++);
		args[argc++] = NULL;
		execvp("gdb", args);
		exit(-1);
	}
	
	if(argv[1] && (!strcmp(argv[1], "-memcheck") || !strcmp(argv[1], "--memcheck"))) {
		argc = 0;
		args[argc++] = (char *)"valgrind";
		args[argc++] = (char *)"--tool=memcheck";
		args[argc++] = (char *)argv0;
		argv += 2;
		while(*argv && argc < 63)
			args[argc++] = *(argv++);
		args[argc++] = NULL;
		execvp("valgrind", args);
		exit(-1);
	}	
	
	if(argv[1] && (!strcmp(argv[1], "-memleak") || !strcmp(argv[1], "--memleak"))) {
		argc = 0;
		args[argc++] = (char *)"valgrind";
		args[argc++] = (char *)"--tool=memcheck";
		args[argc++] = (char *)"--leak-check=yes";
		args[argc++] = (char *)"--show-reachable=yes";
		args[argc++] = (char *)argv0;
		argv += 2;
		while(*argv && argc < 63)
			args[argc++] = *(argv++);
		args[argc++] = NULL;
		execvp("valgrind", args);
		exit(-1);
	}
	
#endif

	// for deaemon env usually loaded from /etc/defaults or /etc/sysconfig

	cp = getenv("CONCURRENCY");
	if(cp)
		concurrency = atoi(cp);

	cp = getenv("PRIORITY");
	if(cp)
		priority = atoi(cp);

	cp = getenv("VERBOSE");
	if(cp) {
		warned = true;
		verbose = atoi(cp);
	}

	cp = getenv("CFGFILE");
	if(cp)
		cfgfile = strdup(cp);

	cp = getenv("PLUGINS");
	if(cp)
		plugins = strdup(cp);
	else
		plugins = (char *)"none";

	if(!getuid())
		daemon = true;

	while(NULL != *(++argv)) {
		if(!strncmp(*argv, "--", 2))
			++*argv;

		if(!strcmp(*argv, "-f") || !stricmp(*argv, "-foreground")) {
			daemon = false;
			continue;
		}

		if(!strcmp(*argv, "-r") || !stricmp(*argv, "-restartable")) {
			restartable = true;
			daemon = true;
			continue;
		}

		if(!strcmp(*argv, "-t") || !stricmp(*argv, "-trace")) {
			dumping = true;
			continue;
		}

		if(!strcmp(*argv, "-d") || !stricmp(*argv, "-background")) {
			daemon = true;
			continue;
		}

		if(!strcmp(*argv, "-p")) {
			priority = 1;
			continue;
		}

		if(!strnicmp(*argv, "-priority=", 10)) {
			priority = atoi(*argv + 10);
			continue;
		} 

		if(!stricmp(*argv, "-concurrency")) {
			cp = *(++argv);
			if(!cp) {
				fprintf(stderr, "*** sipw: concurrency option missing\n");
				exit(-1);
			}
			concurrency = atoi(cp);
			continue;
		}

		if(!strnicmp(*argv, "-concurrency=", 13)) {
			concurrency = atoi(*argv + 13);
			continue;
		} 

		if(!stricmp(*argv, "-l") || !stricmp(*argv, "-plugins")) {
			plugins = *(++argv);
			if(!plugins) {
				fprintf(stderr, "*** sipw: plugins option missing\n");
				exit(-1);
			}
			continue;
		}

		if(!strnicmp(*argv, "-plugins=", 9)) {
			plugins = *argv + 9;
			continue;
		} 

		if(!stricmp(*argv, "-c") || !stricmp(*argv, "-config")) {
			cfgfile = *(++argv);
			if(!cfgfile) {
				fprintf(stderr, "*** sipw: cfgfile option missing\n");
				exit(-1);
			}
			continue;
		}

		if(!strnicmp(*argv, "-config=", 8)) {
			cfgfile = *argv + 8;
			continue;
		} 

		if(!stricmp(*argv, "-version")) 
			server::version();

		if(!strcmp(*argv, "-u") || !stricmp(*argv, "-user")) {
			user = *(++argv);
			if(!user) {
				fprintf(stderr, "*** sipw: user option missing\n");
				exit(-1);
			}
			continue;
		}

		if(!strnicmp(*argv, "-user=", 6)) {
			user = *argv + 6;
			continue;
		} 

		if(!stricmp(*argv, "-help") || !stricmp(*argv, "-?")) 
			server::usage();

		if(!strnicmp(*argv, "-x", 2)) {
			if(*argv + 2)
				cp = *argv + 2;
			else
				cp = *(++argv);
			if(!cp) {
				fprintf(stderr, "*** sipw: debug level missing\n");
				exit(-1);
			}
			verbose = atoi(cp) + INFO;
			continue;
		}

		cp = *argv;
		while(**argv == '-' && *(++cp)) {
			switch(*cp) {
			case 'v':
				warned = true;
				if(!verbose)
					verbose = INFO;
				else
					++verbose;
				break;
			case 'r':
				daemon = true;
				restartable = true;
				break;
			case 'f':
				daemon = false;
				break;
			case 'd':
				daemon = true;
				break;
			case 'p':
				priority = 1;
				break;
			default:
				fprintf(stderr, "*** sipw: -%c: unknown option\n", *cp);
				exit(-1);
			}	
		}
		if(!*cp)
			continue;

#ifdef	USES_COMMANDS
		signal(SIGPIPE, SIG_IGN);
		setenv("IDENT", "sipwitch", 1);
		openlog("sipw", 0, LOG_USER);

		if(!stricmp(*argv, "stop") || !stricmp(*argv, "reload") || !stricmp(*argv, "abort") || !stricmp(*argv, "restart")) {
			server::utils(user);
			if(!process::control(user, *argv)) {
				fprintf(stderr, "*** sipw: %s; server not responding\n", *argv);
				exit(2);
			}
			exit(0);
		}

		if(!stricmp(*argv, "check")) {
			server::utils(user);
			if(!process::control(user, *argv)) {
				fprintf(stderr, "*** sipw: %s; server cannot be checked\n", *argv);
				exit(2);
			}
			exit(0);
		}

		if(!stricmp(*argv, "message")) {
			userid = *(++argv);
			text = *(++argv);

			if(!userid || !text) {
				fprintf(stderr, "*** sipw: use message userid \"text\"\n");
				exit(-1);
			}
			snprintf(tbuf, sizeof(tbuf), "message %s {%s}", userid, text);
			command(user, tbuf, 30);
		}

		if(!stricmp(*argv, "digest")) {
			userid = *(++argv);
			secret = *(++argv);
			string_t digest;		
	
			if(!userid || !secret) {
				fprintf(stderr, "*** sipw: use digest userid secret\n");
				exit(-1);
			}

			server::utils(user);
			printf("<!-- provision template example for realm %s -->\n", registry::getRealm());
			printf("<provision>\n");
			printf("  <user><id>%s</id>\n", userid);
			digest = (string_t)userid + ":" + (string_t)getenv("REALM") + ":" + (string_t)secret;
			if(!stricmp(getenv("DIGEST"), "sha1"))
				digest::sha1(digest);
			else if(!stricmp(getenv("DIGEST"), "rmd160"))
				digest::rmd160(digest);
			else
				digest::md5(digest);
			if(digest[0])
				printf("    <digest>%s</digest>\n", *digest);
			printf("  </user>\n");
			printf("</provision>\n");
			exit(0);
		}

		if(!stricmp(*argv, "registry")) 
			server::regdump();

		if(!stricmp(*argv, "address")) {
			if(!argv[1]) {
				fprintf(stderr, "*** sipw: address: missing\n");
				exit(-1);
			}
			if(argv[2]) {
				fprintf(stderr, "*** sip: address: only one address\n");
				exit(-1);
			}
			command(user, *argv, 30);
		}


		if(!stricmp(*argv, "state")) {
			if(!argv[1]) {
				fprintf(stderr, "*** sipw: state: selection missing\n");
				exit(-1);
			}
			if(argv[2]) {
				fprintf(stderr, "*** sip: state: only one selection\n");
				exit(-1);
			}
			command(user, *argv, 30);
		}

		if(!stricmp(*argv, "activate")) {
			if(!argv[1]) {
				fprintf(stderr, "*** sipw: activate: userid [address] missing\n");
				exit(-1);
			}
			if(argv[2] && argv[3]) {
				fprintf(stderr, "*** sipw: activate: only one address\n");
				exit(-1);
			}
			command(user, *argv, 30);
		}

		if(!stricmp(*argv, "release")) {
			if(!argv[1]) {
				fprintf(stderr, "*** sipw: release: userid missing\n");
				exit(-1);
			}
			if(argv[2]) {
				fprintf(stderr, "*** sipw: release: only one userid\n");
				exit(-1);
			}
			command(user, *argv, 30);
		}

		if(!stricmp(*argv, "dump") || !stricmp(*argv, "snapshot"))
			command(user, *argv, 30);
#endif

		fprintf(stderr, "*** sipw: %s: unknown option\n", *argv);
		exit(-1);
	}

	sigemptyset(&sigthread.sigs);
	sigaddset(&sigthread.sigs, SIGALRM);
	sigaddset(&sigthread.sigs, SIGHUP);
	sigaddset(&sigthread.sigs, SIGINT);
	sigaddset(&sigthread.sigs, SIGTERM);
	sigaddset(&sigthread.sigs, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &sigthread.sigs, NULL);

	signal(SIGPIPE, SIG_IGN);

	if(!warned && !verbose)
		verbose = 2;
	process::setVerbose((errlevel_t)(verbose));

	if(!user && getuid() == 0)
		user = "telephony";

#ifdef	SCHED_RR
	if(priority)
		Thread::policy(SCHED_RR);
#endif

	if(plugins)
		server::plugins(argv0, plugins);

	if(daemon)
		background(user, cfgfile, priority);
	else
		foreground(user, cfgfile, priority);

	server::reload(user);

	if(restartable) 
		restart();

	server::startup();

	if(dumping)
		stack::enableDumping();

	if(concurrency)
		Thread::concurrency(concurrency);

	sigthread.background();
	server::run(user);

	sigthread.cancel();
	service::shutdown();
	process::release();
	return exit_code;
}

END_NAMESPACE

#endif
