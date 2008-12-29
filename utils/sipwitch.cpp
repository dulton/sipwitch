// Copyright (C) 2008-2009 David Sugar, Tycho Softworks.
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

#include "sipwitch/sipwitch.h"
#include <signal.h>
#include <pwd.h>
#include <fcntl.h>
#include <config.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

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

static void registry(char **argv)
{
	mapped_view<MappedRegistry> reg("sipwitch.regmap");
	unsigned count = reg.getCount();
	unsigned found = 0, index = 0;
	volatile const MappedRegistry *member;
	MappedRegistry buffer;
	time_t now;
	char ext[8], exp[8], use[8];
	const char *type;

	if(argv[1]) {
		fprintf(stderr, "*** sipwitch: registry: too many arguments\n");
		exit(-1);
	}

	if(!count) {
		fprintf(stderr, "*** sipwitch: offline\n");
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


static void command(char **argv, unsigned timeout)
{
	char buffer[512];
	size_t len;
	sigset_t sigs;
	int signo;
	struct passwd *pwd = getpwuid(getuid());
	fd_t fd;

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sigs, NULL);

	fd = ::open(DEFAULT_VARPATH "/run/sipwitch/control", O_WRONLY | O_NONBLOCK);
	if(fd < 0) {
		snprintf(buffer, sizeof(buffer), "/tmp/sipwitch-%s/control", pwd->pw_name);
		fd = ::open(buffer, O_WRONLY | O_NONBLOCK);
	}
	if(fd < 0) {
		fprintf(stderr, "*** sipwitch: offline\n");
		exit(2);
	}

	if(timeout)
		snprintf(buffer, sizeof(buffer), "%d", getpid());
	else
		buffer[0] = 0;

	while(*argv) {
		len = strlen(buffer);
		snprintf(buffer + len, sizeof(buffer) - len - 1, " %s", *(argv++));
	}

	len = strlen(buffer);
	buffer[len++] = '\n';
	buffer[len] = 0;

	if(::write(fd, buffer, len) < (int)len) {
		fprintf(stderr, "*** sipwitch: control failed\n");
		exit(4);
	}
	
	if(!timeout)
		exit(0);

	alarm(timeout);
#ifdef	HAVE_SIGWAIT2
	sigwait(&sigs, &signo);
#else
	signo = sigwait(&sigs);
#endif
	if(signo == SIGUSR1)
		exit(0);
	if(signo == SIGALRM) {
		fprintf(stderr, "*** sipwitch: timed out\n");
		exit(1);
	}
	fprintf(stderr, "*** sipwitch: request failed\n");
	exit(3); 
}

static void usage(void)
{
	printf("usage: sipwitch command\n"
		"Commands:\n"
        "  abort                   Force daemon abort\n"
	    "  activate <ext> <ipaddr> Assign registration\n"
        "  address <ipaddr>        Set public ip address\n"
		"  check                   Server deadlock check\n"
        "  concurrency <level>     Server concurrency level\n"
		"  down                    Shut down server\n"
		"  message <ext> <text>    Send text message to extension\n"
        "  registry                Dump registry\n"
        "  release <ext>           Release registration\n"
		"  reload                  Reload configuration\n"
        "  restart                 Server restart\n"
        "  snapshot                Server snapshot\n"
        "  state <selection>       Change server state\n"
        "  verbose <level>         Server verbose logging level\n"
	);		
	exit(0);
}

static void single(char **argv, int timeout)
{
	if(argv[1]) {
		fprintf(stderr, "*** sipwitch: %s: too many arguments\n", *argv);
		exit(-1);
	}
	command(argv, timeout);
}

static void level(char **argv, int timeout)
{
	if(!argv[1]) {
		fprintf(stderr, "*** sipwitch: %s: level missing\n", *argv);
		exit(-1);
	}
	if(argv[2]) {
		fprintf(stderr, "*** sipwitch: %s: too many arguments\n", *argv);
		exit(-1);
	}
	command(argv, timeout);
}

static void address(char **argv)
{
	if(!argv[1]) {
		fprintf(stderr, "*** sipwitch: address: ipaddr missing\n");
		exit(-1);
	}
	if(argv[2]) {
		fprintf(stderr, "*** sipwitch: address: too many arguments\n");
		exit(-1);
	}
	command(argv, 10);
}

static void state(char **argv)
{
	if(!argv[1]) {
		fprintf(stderr, "*** sipwitch: state: value missing\n");
		exit(-1);
	}
	if(argv[2]) {
		fprintf(stderr, "*** sipwitch: state: too many arguments\n");
		exit(-1);
	}
	command(argv, 10);
}

static void release(char **argv)
{
	if(!argv[1]) {
		fprintf(stderr, "*** sipwitch: release: extension missing\n");
		exit(-1);
	}
	if(argv[2]) {
		fprintf(stderr, "*** sipwitch: release: too many arguments\n");
		exit(-1);
	}
	command(argv, 10);
}

static void activate(char **argv)
{
	if(!argv[1]) {
		fprintf(stderr, "*** sipwitch: activate: extension missing\n");
		exit(-1);
	}

	if(!argv[2]) {
		fprintf(stderr, "*** sipwitch: activate: ipaddr missing\n");
		exit(-1);
	}

	if(argv[3]) {
		fprintf(stderr, "*** sipwitch: activate: too many arguments\n");
		exit(-1);
	}
	command(argv, 10);
}


static void message(char **argv)
{
	char buffer[500];

	if(!argv[1]) {
		fprintf(stderr, "*** sipwitch: message: extension missing\n");
		exit(-1);
	}

	if(!argv[2]) {
		fprintf(stderr, "*** sipwitch: message: \"text\" missing\n");
		exit(-1);
	}

	if(argv[3]) {
		fprintf(stderr, "*** sipwitch: message: too many arguments\n");
		exit(-1);
	}

	if(argv[2][0] != '{') {
		snprintf(buffer, sizeof(buffer), "{%s}", argv[2]);
		argv[2] = buffer;
	}
	command(argv, 10);
}

extern "C" int main(int argc, char **argv)
{
	if(argc < 2)
		usage();

	++argv;
	if(String::equal(*argv, "help"))
		usage();
	else if(String::equal(*argv, "reload") || String::equal(*argv, "check") || String::equal(*argv, "snapshot"))
		single(argv, 30);
	else if(String::equal(*argv, "down") || String::equal(*argv, "restart") || String::equal(*argv, "abort"))
		single(argv, 0);
	else if(String::equal(*argv, "verbose") || String::equal(*argv, "concurrency"))
		level(argv, 10);
	else if(String::equal(*argv, "message"))
		message(argv);
	else if(String::equal(*argv, "registry"))
		registry(argv);
	else if(String::equal(*argv, "address"))
		address(argv);
	else if(String::equal(*argv, "activate"))
		activate(argv);
	else if(String::equal(*argv, "release"))
		release(argv);
	else if(String::equal(*argv, "state"))
		state(argv);

	if(!argv[1])
		fprintf(stderr, "use: sipwitch command [arguments...]\n");
	else
		fprintf(stderr, "*** sipwitch: %s: unknown command or option\n", argv[1]);
	exit(1);
}

