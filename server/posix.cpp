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

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) ((unsigned)(status) >> 8)
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

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

	config::utils(uid);

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
	static char *user = NULL;
	static char *cfgfile = NULL;
	static bool daemon = false;
	static bool warned = false;
	static unsigned verbose = 0;
	static unsigned priority = 0;
	static unsigned concurrency = 0;
	static int exit_code = 0;
	static bool restartable = false;

	char *cp, *tokens;
	char *args[65];

	corefiles();

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
			config::utils(user);
			if(!process::control(user, *argv)) {
				fprintf(stderr, "*** sipw: %s; server not responding\n", *argv);
				exit(2);
			}
			exit(0);
		}

		if(!stricmp(*argv, "check")) {
			config::utils(user);
			if(!process::control(user, *argv)) {
				fprintf(stderr, "*** sipw: %s; server cannot be checked\n", *argv);
				exit(2);
			}
			exit(0);
		}

		if(!stricmp(*argv, "digest")) {
			const char *userid = *(++argv);
			const char *secret = *(++argv);
			string_t digest;		
	
			if(!userid || !secret) {
				fprintf(stderr, "*** sipw: use digest userid secret\n");
				exit(-1);
			}

			config::utils(user);
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

	if(daemon)
		process::background(user, cfgfile, priority);
	else
		process::foreground(user, cfgfile, priority);

	config::reload(user);

	if(restartable) 
		restart();

	config::startup();

	if(concurrency)
		Thread::concurrency(concurrency);

	sigthread.background();
	server::run(user);

	sigthread.cancel();
	service::shutdown();
	process::release();
	exit(exit_code);
}

END_NAMESPACE

#endif
