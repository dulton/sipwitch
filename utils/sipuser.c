// Copyright (C) 2008 David Sugar, Tycho Softworks.
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

#define	CUTIL_ONLY
#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <eXosip2/eXosip.h>

static int port = 0;
static int family = AF_INET;
static int protocol = IPPROTO_UDP;
static const char *server = NULL;
static const char *forwarded = NULL;
static const char *proxy = NULL;
static const char *binding = NULL;
static unsigned timeout = 1000;
static int tls = 0;

int main(int argc, char **argv)
{
	int error = 2;
	eXosip_event_t *sevent;
	const char *cp, *user;

	cp = getenv("SIP_PROXY");
	if(cp)
		proxy = cp;

	cp = getenv("SIP_SERVER");
	if(cp)
		server = cp;

	
	while(NULL != *(++argv)) {
		if(!strncmp(*argv, "--", 2))
			++*argv;

		if(!strcmp(*argv, "-t") || !strcmp(*argv, "-timeout")) {
			if(NULL == *(++argv)) {
				fprintf(stderr, "*** sipuser: timeout option missing timeout\n");
				exit(3);
			}
			timeout = atoi(*argv) * 1000;
			if(!timeout) {
				fprintf(stderr, "*** sipuser: timeout option invalid\n");
				exit(3);
			}
			continue;
		}

		if(!strncmp(*argv, "-timeout=", 9)) {
			timeout = atoi(*argv + 9) * 1000;
			if(!timeout) {
				fprintf(stderr, "*** sipuser: timeout option invalid\n");
				exit(3);
			}
			continue;
		}

		if(!strcmp(*argv, "-p") || !strcmp(*argv, "-port")) {
			if(NULL == *(++argv)) {
				fprintf(stderr, "*** sipuser: port option missing port\n");
				exit(3);
			}
			port = atoi(*argv);
			if(!port) {
				fprintf(stderr, "*** sipuser: port option invalid number\n");
				exit(3);
			}
			continue;
		}

		if(!strncmp(*argv, "-port=", 6)) {
			port = atoi(*argv + 6);
			 if(!port) {
				fprintf(stderr, "*** sipuser: port option invalid number\n");
				exit(3);
			}
			continue;
		}

		if(!strcmp(*argv, "-proxy")) {
			proxy = *(++argv);
			if(!proxy) {
				fprintf(stderr, "*** sipuser: proxy option missing proxy\n");
				exit(3);
			}
			continue;
		}

		if(!strncmp(*argv, "-proxy=", 7)) {
			proxy = *argv + 7;
			continue;
		}

		if(!strcmp(*argv, "-server")) {
			server = *(++argv);
			if(!server) {
				fprintf(stderr, "*** sipuser: server option missing proxy\n");
				exit(3);
			}
			continue;
		}

		if(!strncmp(*argv, "-server=", 8)) {
			server = *argv + 8;
			continue;
		}

		if(!strcmp(*argv, "-forward")) {
			forwarded = *(++argv);
			if(!forwarded) {
				fprintf(stderr, "*** sipuser: forwarding option missing interface\n");
				exit(3);
			}
			continue;
		}

		if(!strncmp(*argv, "-forward=", 9)) {
			forwarded = *argv + 8;
			continue;
		}

		if(!strcmp(*argv, "-?") || !strcmp(*argv, "-h") || !strcmp(*argv, "-help")) {
			fprintf(stderr, "usage: sipuser [options] userid...\n"
				"[options]\n"
				"  -proxy    sip:proxyhost[:port]\n"
				"  -server   sip:server[:port]\n"
				"  -forward  ip-address\n"
				"  -port     port-numer\n"
				"  -timeout  seconds\n");
			exit(3);
		}

		if(*argv == '-') {
			fprintf(stderr, "*** sipuser: %s: unknown option\n", *argv);
			exit(3);
		}

		break;
	}

	if(!*argv) {
		fprintf(stderr, "use: sipuser [options] userid...\n");
		exit(3);
	}
		 
	if(!port)
		port = 5060 + getuid();

	if(eXosip_init()) {
		fprintf(stderr, "*** sipuser: failed exosip init\n");
		exit(3);
	}

#ifdef	AF_INET6
	if(family == AF_INET6) {
		eXosip_enable_ipv6(1); 
		if(server == NULL)
			server = "::1";
		if(binding == NULL)
			binding = "::0";
	}
#endif
	if(server == NULL)
		server = "127.0.0.1";

	if(eXosip_listen_addr(protocol, binding, port, family, tls)) {
#ifdef  AF_INET6
        if(!binding && family == AF_INET6)
            binding = "::0";
#endif
        if(!binding)
            binding = "*";
		fprintf(stderr, "*** sipuser: failed to listen %s:%d\n", binding, port);
		exit(3);
	}

	if(forwarded)
		eXosip_masquerade_contact(forwarded, port);
	
	eXosip_set_user_agent("SIPW/sipuser");

	while(*argv) {
		user = *(argv++);
		printf("USER %s\n", user);
	}

	for(;;) {
		sevent = eXosip_event_wait(0, timeout);
		if(!sevent) {
			fprintf(stderr, "*** sipuser: timed out\n");
			break;
		}
		printf("sip: event %d; cid=%d, did=%d\n",
			sevent->type, sevent->cid, sevent->did);

		eXosip_event_free(sevent);
	}
	eXosip_quit();
	return error;
}

