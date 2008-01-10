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
#include <signal.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

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

#ifdef	USES_SIGNALS
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
} sigthread;

SignalThread::SignalThread() :
JoinableThread()
{
	shutdown = started = false;
}

SignalThread::~SignalThread()
{
	if(started) {
		shutdown = true;
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

#endif

#ifdef	USES_COMMANDS
static void paddress(struct sockaddr_internet *a1, struct sockaddr_internet *a2)
{
	char sep = '\n';
	char buf[64];
	unsigned len;
	unsigned p1 = 0, p2 = 0;

	if(!a1)
		return;

	Socket::getaddress((struct sockaddr *)a1, buf, sizeof(buf));
	len = strlen(buf);
	switch(a1->sa_family) {
	case AF_INET:
		p1 = (unsigned)ntohs(a1->ipv4.sin_port);
		break;
#ifdef	AF_INET6
	case AF_INET6:
		p1 = (unsigned)ntohs(a1->ipv6.sin6_port);
		break;
#endif
	}

	if(a2) {
		switch(a2->sa_family) {
		case AF_INET:
			p2 = (unsigned)ntohs(a2->ipv4.sin_port);
			break;
#ifdef	AF_INET6
		case AF_INET6:
			p2 = (unsigned)ntohs(a2->ipv6.sin6_port);
			break;
#endif
		}
	}

	if(a2 && p2)
		sep = ',';

	if(p1)
		printf("%s:%u%c", buf, p1, sep);
	else
		printf("none%c", sep);

	if(!a2 || !p2)
		return;

	Socket::getaddress((struct sockaddr *)a2, buf, sizeof(buf));
	printf("%s:%u\n", buf, p2);
}

static void regdump(void)
{
	mapped_view<MappedRegistry> reg("sipwitch.regmap");
	unsigned count = reg.getCount();
	unsigned found = 0, index = 0;
	volatile const MappedRegistry *member;
	MappedRegistry buffer;
	time_t now;
	char ext[8], exp[8], use[8];
	const char *type;

	if(!count) {
		process::errlog(FAILURE, "cannot access mapped registry");
		exit(-1);
	}

	time(&now);
	while(index < count) {
		member = reg(index++);
		do {	
			memcpy(&buffer, (const void *)member, sizeof(buffer));
		} while(memcmp(&buffer, (const void *)member, sizeof(buffer)));
		if(buffer.type == MappedRegistry::EXPIRED)
			continue;
		else if(buffer.type == MappedRegistry::TEMPORARY && !buffer.inuse)
			continue;
		if(!found++)
			printf("%7s %-30s type %-30s  use expires address\n", "ext", "user", "profile");
		ext[0] = 0;
		if(buffer.ext)
			snprintf(ext, sizeof(ext), "%7d", buffer.ext); 
		exp[0] = '-';
		exp[1] = 0;
		snprintf(use, sizeof(use), "%u", buffer.inuse);
		if(buffer.expires && buffer.type != MappedRegistry::TEMPORARY)
			snprintf(exp, sizeof(exp), "%ld", buffer.expires - now);
		switch(buffer.type) {
		case MappedRegistry::REJECT:
			type = "rej";
			break;
		case MappedRegistry::REFER:
			type = "ref";
			break;
		case MappedRegistry::GATEWAY:
			type = "gw";
			break;
		case MappedRegistry::SERVICE:
			type = "peer";
			break;
		case MappedRegistry::TEMPORARY:
			type = "temp";
			break;
		default:
			type = "user";
		};
		printf("%7s %-30s %-4s %-30s %4s %7s ", ext, buffer.userid, type, buffer.profile.id, use, exp);
		paddress(&buffer.contact, NULL);
		fflush(stdout);
	}

	printf("found %d entries active of %d\n", found, count);  
	exit(0);
}

static void command(const char *uid, const char *cmd, unsigned timeout)
{
#ifdef	USES_SIGNALS
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
#endif
	exit(3);
}
#endif

static bool activate(int argc, char **args)
{
	registry::mapped *reg;
	bool rtn = true;

	Socket::address *addr;
	if(argc < 2 || argc > 3)
		return false;
	if(argc == 3)
		addr = stack::getAddress(args[2]);
	else
		addr = config::getContact(args[1]);
	if(!addr)
		return false;
	if(NULL == (reg = registry::create(args[1]))) {
		delete addr;
		return false;
	}
	if(!reg->setTargets(addr))
		rtn = false;
	registry::release(reg);
	delete addr;
	return rtn;
}

static mempager mempool(PAGING_SIZE);

unsigned allocate(void)
{
	return mempool.getPages();
}

caddr_t allocate(size_t size, LinkedObject **list, volatile unsigned *count)
{
	caddr_t mp;
	if(list && *list) {
		mp = (caddr_t)*list;
		*list = (*list)->getNext();
	}
	else {
		if(count)
			++(*count);
		mp = (caddr_t)mempool.alloc(size);
	}
	memset(mp, 0, size);
	return mp;
}

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

#ifndef	_MSWINDOWS_
	if(!getuid())
		daemon = true;
#endif

	while(NULL != *(++argv)) {
		if(!strncmp(*argv, "--", 2))
			++*argv;

		if(!strcmp(*argv, "-f") || !stricmp(*argv, "-foreground")) {
			daemon = false;
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

		if(!stricmp(*argv, "-version")) {
			printf("SIP Witch " VERSION "\n"
				"Copyright (C) 2007 David Sugar, Tycho Softworks\n"
				"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
				"This is free software: you are free to change and redistribute it.\n"
				"There is NO WARRANTY, to the extent permitted by law.\n");
			exit(0);
		}

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

		if(!stricmp(*argv, "-help") || !stricmp(*argv, "-?")) {
#ifdef	USES_COMMANDS
			printf("Usage: sipw [options] [command...]\n"
#else
			printf("Usage: sipw [options\n"
#endif
				"Options:\n"
				"  --help                Display this information\n"
				"  -foreground           Run server in foreground\n"
				"  -background           Run server as daemon\n"
                "  -config=<cfgfile>     Use cfgfile in place of default one\n"
				"  -user=<userid>        Change to effective user from root\n" 
				"  -concurrency=<level>  Increase thread concurrency\n"
				"  -priority=<level>     Increase process priority\n"
				"  -v[vv], -x<n>         Select verbosity or debug level\n"
#ifdef	USES_COMMANDS
				"Commands:\n"
				"  stop                  Stop running server\n"
				"  reload                Reload config file\n"
				"  restart               Restart server\n"
				"  check                 Test for thread deadlocks\n"
				"  snapshot              Create snapshot file\n"
                "  dump                  Dump in-memory config tables\n"
                "  digest <user> <pass>  Compute digest based on server realm\n"
                "  registry              List registrations from shared memory\n"
                "  activate <user>       Activate static user registration\n"
                "  release <user>        Release registered user\n"
#endif
			);
			exit(0);
		}

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
		process::util();

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
			regdump();

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

#ifdef USES_SIGNALS
	sigemptyset(&sigthread.sigs);
	sigaddset(&sigthread.sigs, SIGALRM);
	sigaddset(&sigthread.sigs, SIGHUP);
	sigaddset(&sigthread.sigs, SIGINT);
	sigaddset(&sigthread.sigs, SIGTERM);
	sigaddset(&sigthread.sigs, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &sigthread.sigs, NULL);
#endif

#ifndef	_MSWINDOWS_
	signal(SIGPIPE, SIG_IGN);
#endif

	if(!warned && !verbose)
		verbose = 2;
	process::setVerbose((errlevel_t)(verbose));

#ifdef	_MSWINDOWS_
	if(!user)
		user = "telephony";
#else
	if(!user && getuid() == 0)
		user = "telephony";
#endif

	if(daemon)
		process::background(user, cfgfile, priority);
	else
		process::foreground(user, cfgfile, priority);

	config::reload(user);
	config::startup();

#ifdef	USES_SIGNALS
	sigthread.background();
#endif

	if(concurrency)
		Thread::concurrency(concurrency);

	while(NULL != (cp = process::receive())) {
        if(!stricmp(cp, "reload")) {
            config::reload(user);
            continue;
        }

		if(!stricmp(cp, "check")) {
			if(!config::check())
				process::reply("check failed");
			continue;
		}

        if(!stricmp(cp, "stop") || !stricmp(cp, "down") || !strcmp(cp, "exit"))
            break;

		if(!stricmp(cp, "restart")) {
			exit_code = SIGABRT;
			break;
		}

		if(!stricmp(cp, "snapshot")) {
			service::snapshot(user);
			continue;
		}

		if(!stricmp(cp, "dump")) {
			service::dumpfile(user);
			continue;
		}

		if(!stricmp(cp, "abort")) {
			abort();
			continue;
		}

		argc = 0;
		tokens = NULL;
		while(argc < 64 && NULL != (cp = const_cast<char *>(string::token(cp, &tokens, " \t")))) {
			args[argc++] = cp;
		}
		args[argc] = NULL;
		if(argc < 1)
			continue;

		if(!stricmp(args[0], "verbose")) {
			if(argc > 2) {
invalid:
				process::reply("invalid argument");
				continue;
			}
			process::setVerbose(errlevel_t(atoi(args[1])));
			continue;
		}

#ifdef	SCHED_RR
		Thread::policy(SCHED_RR);
#endif

		if(!stricmp(args[0], "concurrency")) {
			if(argc != 2)
				goto invalid;
			Thread::concurrency(atoi(args[1]));
			continue;
		}

		if(!stricmp(args[0], "subscribe")) {
			if(argc < 2 || argc > 3)
				goto invalid;
			service::subscribe(args[1], args[2]);
			continue;
		}

		if(!stricmp(args[0], "unsubscribe")) {
			if(argc != 2)
				goto invalid;
			service::unsubscribe(args[1]);
			continue;
		}

		if(!stricmp(args[0], "activate")) {
			if(!activate(argc, args))
				process::reply("cannot activate");
			continue;
		}

		if(!stricmp(args[0], "release")) {
			if(argc != 2)
				goto invalid;
			if(!registry::remove(args[1]))
				process::reply("cannot release");
			continue;
		}

		process::reply("unknown command");
	}
	service::shutdown();
	exit(exit_code);
}

END_NAMESPACE
