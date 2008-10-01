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

server::server(const char *id) :
service(id, PAGING_SIZE)
{
	assert(id != NULL && *id != 0);

	definitions = NULL;
	images = NULL;
}

server::~server()
{
	linked_pointer<server::image> ip = images;

	if(definitions)
		definitions->release();

	while(is(ip)) {
		if(ip->image)
			ip->image->release();
		ip.next();
	}
}

bool server::confirm(const char *user)
{
	assert(user == NULL || *user != 0);

	return true;
}

void server::utils(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	process::util("sipapps");
	FILE *fp = service::open(uid);
	const char *key = NULL, *value;
	linked_pointer<keynode> sp;

	cfg = new server("sipapps");
	
	crit(cfg != NULL, "util has no config");

	if(fp)
		if(!cfg->load(fp)) {
			process::errlog(ERRLOG, "invalid config");
			delete cfg;
			return;
		}
}

bool server::check(void)
{
	process::errlog(INFO, "checking config...");
	locking.modify();
	locking.commit();
	process::errlog(INFO, "checking components...");
	if(service::check()) {
		process::errlog(INFO, "checking complete");
		return true;
	}
	process::errlog(WARN, "checking failed");
	return false;
}

void server::dump(FILE *fp)
{
	assert(fp != NULL);
	assert(cfg != NULL);

	fprintf(fp, "Server:\n");
	fprintf(fp, "  allocated pages: %d\n", server::allocate());
	fprintf(fp, "  configure pages: %d\n", cfg->getPages());
	fprintf(fp, "  memory paging:   %d\n", PAGING_SIZE);
	keynode *reg = getPath("sip");
	if(reg && reg->getFirst()) {
		fprintf(fp, "  sip stack keys:\n");
		service::dump(fp, reg->getFirst(), 4);
	}
}
		
void server::reload(const char *uid)
{
	assert(uid == NULL || *uid != 0);

	char buf[256];

	server *cfgp = new server("sipapps");

	static server *reclaim = NULL;
	
	crit(cfgp != NULL, "reload without config");

	FILE *fp = service::open(uid);
	if(fp)
		if(!cfgp->load(fp)) {
			process::errlog(ERRLOG, "invalid config");
			delete cfgp;
			return;
		}

	if(!cfgp->commit(uid)) {
		process::errlog(ERRLOG, "config rejected");
		if(reclaim) {
			locking.modify();
			delete reclaim;
			locking.commit();
		}
		reclaim = cfgp;
	}
	if(!cfg) {
		process::errlog(FAILURE, "no configuration");
		exit(2);
	}
	if(reclaim) {
		delete reclaim;
		reclaim = NULL;
	}
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
	fsys	dir;
	unsigned el;

	if(!list || !*list || !stricmp(list, "none"))
		return;

	if(!stricmp(list, "auto")) {
		String::set(path, sizeof(path), argv0);
		ep = strstr(path, LIB_PREFIX + 1);
		if(ep)
			ep[strlen(LIB_PREFIX)] = 0;
		else 
			String::set(path, sizeof(path), DEFAULT_LIBPATH "/sipapps");
		el = strlen(path);
		fsys::open(dir, path, fsys::ACCESS_DIRECTORY);
		while(is(dir) && fsys::read(dir, buffer, sizeof(buffer)) > 0) {
			ep = strrchr(buffer, '.');
			if(!ep || stricmp(ep, DLL_SUFFIX))
				continue;
			snprintf(path + el, sizeof(path) - el, "/%s", buffer);
			process::errlog(INFO, "loading %s", buffer);
			if(fsys::load(path)) 
				process::errlog(ERRLOG, "failed loading %s", path);
		}
		fsys::close(dir);
	}
	else {
		String::set(buffer, sizeof(buffer), list);
		while(NULL != (cp = String::token(buffer, &tp, ", ;:\r\n"))) {
			String::set(path, sizeof(path), argv0);
			ep = strstr(path, LIB_PREFIX + 1);
			if(ep) {
				ep[strlen(LIB_PREFIX)] = 0;
				String::add(path, sizeof(path), cp);
				String::add(path, sizeof(path), DLL_SUFFIX);
				if(fsys::isfile(path)) {
					process::errlog(INFO, "loading %s" DLL_SUFFIX " locally", cp);
					goto loader;
				}
			}
			snprintf(path, sizeof(path), DEFAULT_LIBPATH "/sipapps/%s" DLL_SUFFIX, cp);
			process::errlog(INFO, "loading %s", path);
loader:
			if(fsys::load(path)) 
				process::errlog(ERRLOG, "failed loading %s", path);
		}
	}
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
	FILE *fp;

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
            reload(user);
            continue;
        }

		if(!stricmp(cp, "check")) {
			if(!check())
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
		while(argc < 64 && NULL != (cp = const_cast<char *>(String::token(cp, &tokens, " \t", "{}")))) 
			argv[argc++] = cp;
	
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
	printf("SIP Apps " VERSION "\n"
        "Copyright (C) 2007-2008 David Sugar, Tycho Softworks\n"
		"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
		"This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n");
    exit(0);
}

void server::usage(void)
{
#if !defined(_MSWINDOWS_) && defined(USES_COMMANDS)
	printf("Usage: sipapps [debug] [options] [command...]\n"
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

void server::release(image *img)
{
	if(img)
		locking.release();
}

void server::release(script *scr)
{
	if(scr)
		scr->release();
}

script *server::getScript(const char *id)
{
	server::image *img = getImages();
	linked_pointer<server::image> ip = img;
	script *scr;
	
	while(is(ip)) {
		if(String::equal(ip->id, id)) {
			scr = ip->image;
			if(scr)
				scr->retain();
			release(img);
			return scr;
		}
		ip.next();
	}
	release(img);
	return NULL;
}

server::image *server::getImages(void)
{
	image *img = NULL;
	server *cfgp;

	locking.access();
	cfgp = static_cast<server*>(cfg);
	if(cfgp)
		img = cfgp->images;
	if(!img)
		locking.release();
	return img;
}
	
END_NAMESPACE
