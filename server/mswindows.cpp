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

#ifdef	_MSWINDOWS_
#include <signal.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

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

		fprintf(stderr, "*** sipw: %s: unknown option\n", *argv);
		exit(-1);
	}

	if(!warned && !verbose)
		verbose = 2;
	process::setVerbose((errlevel_t)(verbose));

	if(!user)
		user = "telephony";

	if(daemon)
		process::background(user, cfgfile, priority);
	else
		process::foreground(user, cfgfile, priority);

	config::reload(user);

	config::startup();

	if(concurrency)
		Thread::concurrency(concurrency);

	server::run(user);
	service::shutdown();
	process::release();
	exit(exit_code);
}
END_NAMESPACE

#endif
