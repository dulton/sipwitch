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

static mempager mempool(PAGING_SIZE);
static bool running = true;

#ifdef	USES_COMMANDS
static void paddress(struct sockaddr_internet *a1, struct sockaddr_internet *a2)
{
	assert(a1 != NULL);

	char sep = '\n';
	char buf[64];
	unsigned len;
	unsigned p1 = 0, p2 = 0;

	if(!a1)
		return;

	Socket::getaddress((struct sockaddr *)a1, buf, sizeof(buf));
	len = strlen(buf);
	switch(a1->address.sa_family) {
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
		switch(a2->address.sa_family) {
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
#endif

static bool activate(int argc, char **args)
{
	assert(args != NULL);

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
	if(!reg->setTargets(*addr))
		rtn = false;
	registry::detach(reg);
	delete addr;
	return rtn;
}

unsigned server::allocate(void)
{
	return mempool.getPages();
}

caddr_t server::allocate(size_t size, LinkedObject **list, volatile unsigned *count)
{
	assert(size > 0);
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

#ifdef	_MSWINDOWS_
#define	DLL_SUFFIX	".dll"
#define	LIB_PREFIX	"_libs"
#else
#define	LIB_PREFIX	".libs"
#define	DLL_SUFFIX	".so"
#endif

void server::plugins(const char *argv0, const char *list)
{
	char buffer[256];
	char path[256];
	char *tp = NULL;
	char *ep;
	const char *cp;
	fsys	module;

	if(!list || !*list)
		return;

	string::set(buffer, sizeof(buffer), list);
	while(NULL != (cp = string::token(buffer, &tp, ", ;:\r\n"))) {
		string::set(path, sizeof(path), argv0);
		ep = strstr(path, LIB_PREFIX + 1);
		if(ep) {
			ep[strlen(LIB_PREFIX)] = 0;
			string::add(path, sizeof(path), cp);
			string::add(path, sizeof(path), DLL_SUFFIX);
			if(fsys::isfile(path)) {
				process::errlog(INFO, "loading %s" DLL_SUFFIX " locally", cp);
				goto loader;
			}
		}
		snprintf(path, sizeof(path), DEFAULT_LIBPATH "/sipwitch/%s" DLL_SUFFIX, cp);
		process::errlog(INFO, "loading %s", path);
loader:
		if(fsys::load(path)) 
			process::errlog(ERRLOG, "failed loading %s", path);
	}
}

void server::regdump(void)
{
#ifdef	USES_COMMANDS
	mapped_view<MappedRegistry> reg("sipwitch.regmap");
	unsigned count = reg.getCount();
	unsigned found = 0, index = 0;
	volatile const MappedRegistry *member;
	MappedRegistry buffer;
	time_t now;
	char ext[8], exp[8], use[8];
	const char *type;

	if(!count) {
		fprintf(stderr, "*** sipw: cannot access mapped registry\n");
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

#endif
}

void server::stop(void)
{
	running = false;
}

void server::run(const char *user)
{
	int argc;
	char *argv[65];
	char *cp, *tokens;
	static int exit_code = 0;
	time_t now;
	struct tm *dt, hold;

	time(&now);
	dt = localtime_r(&now, &hold);
	if(dt->tm_year < 1900)
		dt->tm_year += 1900;

	process::printlog("server startup %04d-%02d-%02d %02d:%02d:%02d\n",
		dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
		dt->tm_hour, dt->tm_min, dt->tm_sec);

	while(running && NULL != (cp = process::receive())) {
		debug(9, "received request %s\n", cp);

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
		while(argc < 64 && NULL != (cp = const_cast<char *>(String::token(cp, &tokens, " \t", "{}")))) {
			printf("TOKEN %s\n", cp);
			argv[argc++] = cp;
		}
		argv[argc] = NULL;
		if(argc < 1)
			continue;

		if(!stricmp(argv[0], "verbose")) {
			if(argc > 2) {
invalid:
				process::reply("invalid argument");
				continue;
			}
			process::setVerbose(errlevel_t(atoi(argv[1])));
			continue;
		}

		if(!stricmp(argv[0], "concurrency")) {
			if(argc != 2)
				goto invalid;
			Thread::concurrency(atoi(argv[1]));
			continue;
		}

		if(!stricmp(argv[0], "message")) {
			if(argc != 3)
				goto invalid;
			messages::system(argv[1], argv[2]);
			continue;
		}

		if(!stricmp(argv[0], "subscribe")) {
			if(argc < 2 || argc > 3)
				goto invalid;
			service::subscribe(argv[1], argv[2]);
			continue;
		}

		if(!stricmp(argv[0], "unsubscribe")) {
			if(argc != 2)
				goto invalid;
			service::unsubscribe(argv[1]);
			continue;
		}

		if(!stricmp(argv[0], "activate")) {
			if(!activate(argc, argv))
				process::reply("cannot activate");
			continue;
		}

		if(!stricmp(argv[0], "release")) {
			if(argc != 2)
				goto invalid;
			if(!registry::remove(argv[1]))
				process::reply("cannot release");
			continue;
		}

		process::reply("unknown command");
	}
	time(&now);
	dt = localtime_r(&now, &hold);
	if(dt->tm_year < 1900)
		dt->tm_year += 1900;

	process::printlog("server shutdown %04d-%02d-%02d %02d:%02d:%02d\n",
		dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
		dt->tm_hour, dt->tm_min, dt->tm_sec);
}

void server::version(void)
{
	printf("SIP Witch " VERSION "\n"
        "Copyright (C) 2007-2008 David Sugar, Tycho Softworks\n"
		"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
		"This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n");
    exit(0);
}

void server::usage(void)
{
#if !defined(_MSWINDOWS_) && defined(USES_COMMANDS)
	printf("Usage: sipw [debug] [options] [command...]\n"
#elif defined(USES_COMMANDS)
	printf("Usage: sipw [options] [command...]\n"
#else
	printf("Usage: sipw [options]\n"
#endif
		"Options:\n"
		"  --help                Display this information\n"
		"  -foreground           Run server in foreground\n"
		"  -background           Run server as daemon\n"
#ifdef	_MSWINDOWS_
#else
		"  -restartable			 Run server as restartable daemon\n"
#endif
		"  -trace                Trace/dump sip messages\n"
		"  -config=<cfgfile>     Use cfgfile in place of default one\n"
#ifndef	_MSWINDOWS
		"  -plugins=<list>       List of plugins to load\n"
#endif
		"  -user=<userid>        Change to effective user from root\n" 
#ifndef	_MSWINDOWS_
		"  -concurrency=<level>  Increase thread concurrency\n"
#endif
		"  -priority=<level>     Increase process priority\n"
		"  -v[vv], -x<n>         Select verbosity or debug level\n"
#if defined(USES_COMMANDS) || defined(_MSWINDOWS_)
		"Commands:\n"
		"  stop                  Stop running server\n"
		"  reload                Reload config file\n"
#ifdef	_MSWINDOWS_
		"  register              Register as service deamon\n"
		"  release               Release service deamon registeration\n"
#endif
#endif
#ifdef	USES_COMMANDS
		"  restart               Restart server\n"
		"  check                 Test for thread deadlocks\n"
		"  snapshot              Create snapshot file\n"
		"  dump                  Dump in-memory config tables\n"
		"  message <user> <text> Send instant message to user agent\n"
		"  digest <user> <pass>  Compute digest based on server realm\n"
		"  registry              List registrations from shared memory\n"
		"  activate <user>       Activate static user registration\n"
		"  release <user>        Release registered user\n"
#endif
#if defined(USES_COMMANDS) && !defined(_MSWINDOWS_)
		"Debug Option:\n"
		"  -gdb                  Run server from gdb\n"
		"  -memcheck             Check for memory leaks with valgrind\n"
		"  -memleak              Find where leaks are with valgrind\n"
#endif
	);
	exit(0);
}

END_NAMESPACE
