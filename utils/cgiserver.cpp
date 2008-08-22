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

#include <sipwitch/sipwitch.h>
#include <config.h>

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

static char *cgi_version = NULL;
static char *cgi_remuser = NULL;
static char *cgi_method = NULL;
static char *cgi_query = NULL;
static char *cgi_content = NULL;
static unsigned cgi_length = 0;
static const char *save_file;
static const char *temp_file;
static const char *control_file;
static const char *snapshot_file;
static const char *dump_file;

static void error(unsigned err, const char *text)
{
	printf(
		"Status: %d %s\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"\r\n", err, text);
	exit(0);
}

#ifdef	_MSWINDOWS_

static void cgilock(void)
{
}

static void cgiunlock(void)
{
}

#else

#include <fcntl.h>

static pid_t pidfile(void)
{
	struct stat ino;
	time_t now;
	fd_t fd;
	pid_t pid;
	char buf[65];

	fd = open(DEFAULT_VARPATH "/run/sipwitch/cgilock", O_RDONLY);
	if(fd < 0 && errno == EPERM)
		error(403, "Lock access forbidden");

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

static void cgiunlock(void)
{
	remove(DEFAULT_VARPATH "/run/sipwitch/cgilock");
}

static void cgilock(void)
{
	unsigned count = 90;
	pid_t opid;
	fd_t fd;
	char buf[65];

retry:
	fd = open(DEFAULT_VARPATH "/run/sipwitch/cgilock", O_CREAT|O_WRONLY|O_TRUNC|O_EXCL, 0755);
	if(fd < 0) {
		opid = pidfile();
		if(!opid || opid == 1) {
			remove(buf);
			goto retry;
		}
		if(count) {
			--count;
			::sleep(1);
		}
		else
			error(408, "Lock timed out");
	}

	snprintf(buf, sizeof(buf), "%d\n", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
}

#endif

static void request(const char *fmt, ...)
{
	char buf[512];
	unsigned len = 0;
	va_list args;
	FILE *fp;

#ifndef	_MSWINDOWS_
	int signo;
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigs, NULL);
	snprintf(buf, sizeof(buf), "%d ", getpid());
	len = strlen(buf);
#endif

	va_start(args, fmt);
	vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
	va_end(args);
	if(!strchr(buf, '\n'))
		String::add(buf, sizeof(buf), "\n");

	fp = fopen(control_file, "w");
	if(!fp)
		error(405, "Server unavailable");

	fputs(buf, fp);
	fclose(fp);
#ifndef	_MSWINDOWS_
	alarm(60);
#ifdef	HAVE_SIGWAIT2
	sigwait(&sigs, &signo);
#else
	signo = sigwait(&sigs);
#endif
	if(signo == SIGUSR2)
		error(405, "Request failed");
	if(signo == SIGALRM)
		error(408, "Request timed out");
#endif
}

static void dump(void)
{
	char buf[512];

	cgilock();
	request("dump");
	FILE *fp = fopen(dump_file, "r");
	cgiunlock();
	if(!fp)
		error(403, "Dump unavailable");

	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n");

	while(!feof(fp)) {
		fgets(buf, sizeof(buf) - 1, fp);
		fputs(buf, stdout);
	}
	fflush(stdout);
	exit(0);
}

static void snapshot(void)
{
	char buf[512];

	cgilock();
	request("snapshot");
	FILE *fp = fopen(snapshot_file, "r");
	cgiunlock();
	if(!fp)
		error(403, "Snapshot unavailable");

	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n");

	while(!feof(fp)) {
		fgets(buf, sizeof(buf) - 1, fp);
		fputs(buf, stdout);
	}
	fflush(stdout);
	exit(0);
}

static void config(void)
{
	char buf[512];
	FILE *fp = fopen(save_file, "r");
	if(!fp)
		error(403, "Config unavailable");

	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"\r\n");

	while(!feof(fp)) {
		fgets(buf, sizeof(buf) - 1, fp);
		fputs(buf, stdout);
	}
	fflush(stdout);
	exit(0);
}

static void post(void)
{
	FILE *fp;
	char buf[257];
	long len;

	if(!cgi_length)
		error(411, "Length required");
	if(!cgi_content || stricmp(cgi_content, "text/xml"))
		error(415, "Unsupported media type");

	cgilock();
	remove(temp_file);
	fp = fopen(temp_file, "w");
	if(!fp)
		error(403, "Access forbidden");

	while(cgi_length > 0) {
		if(cgi_length > sizeof(buf) - 1)
			len = sizeof(buf) - 1;
		else
			len = cgi_length;

		if(fread(buf, len, 1, stdin) < 1)
			error(500, "Invalid read of config");
		if(fwrite(buf, len, 1, fp) < 1)
			error(500, "Invalid write of config");
		cgi_length -= len;
	}
	fclose(fp);
	rename(temp_file, save_file);
	cgiunlock();
	request("reload");
	error(200, "ok");
}

static void callfile(FILE *fp, const char *id)
{
#ifdef	_MSWINDOWS_
	struct _stat ino;
#else
	struct stat ino;
#endif
	char buf[256];
	char *cp = NULL;
	unsigned long date, line = 0;
	unsigned long last_date = 0, last_line = 0;
	struct tm *dt;

	if(!fp)
		return;

#ifdef	_MSWINDOWS_
	_fstat(_fileno(fp), &ino);
#else
	fstat(fileno(fp), &ino);
#endif

	dt = localtime(&ino.st_ctime);

	if(dt->tm_year >= 2000)
		dt->tm_year -= 2000;

	date = dt->tm_hour + (32l * dt->tm_mday) + (1024l * dt->tm_mon) + (16384l * dt->tm_year);  

	if(id) {
		last_date = atol(id);
		cp = strchr(id, '/');
	}
	if(cp)
		last_line = atol(++cp);

	if(date < last_date) {
		fclose(fp);
		return;
	}

	while(!feof(fp)) {
		buf[0] = 0;
		fgets(buf, sizeof(buf), fp);
		if(strnicmp(buf, "call ", 5))
			continue;
		cp = buf + 5;
		while(*cp == ' ')
			++cp;
		++line;
		if(date == last_date && line <= last_line)
			continue;
		if(id && *id && strnicmp(id, cp, strlen(id) > 0))
			continue;
		printf("%07ld/%07ld %s", date, line, cp);
	}
	if(fp)
		fclose(fp);
}

static void calls(const char *id)
{
	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n");
	callfile(fopen(DEFAULT_VARPATH "/log/sipwitch.log.0", "r"), id);
	callfile(fopen(DEFAULT_VARPATH "/log/sipwitch.log", "r"), id);
	exit(0);
}

static void info(void)
{
	char buf[256];
	char *cp;
	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"\r\n");

	printf("<?xml version=\"1.0\"?>\n");
	printf("<serviceInfo>\n");
	printf(" <version>" VERSION "</version>\n");
	FILE *fp = fopen(DEFAULT_VARPATH "/run/sipwitch/state.def", "r");
	String::set(buf, sizeof(buf), "up");
	if(fp) {
		fgets(buf, sizeof(buf), fp);
		fclose(fp);
	}
	cp = strchr(buf, '\r');
	if(!cp)
		cp = strchr(buf, '\n');
	if(cp)
		*cp = 0;
	if(!stricmp(buf, "none") || !buf[0])
		String::set(buf, sizeof(buf), "up"); 
#ifndef	_MSWINDOWS_
	pid_t pid = 0;
	fp = fopen(DEFAULT_VARPATH "/run/sipwitch/pidfile", "r");
	if(fp) {
		fgets(buf, sizeof(buf), fp);
		fclose(fp);
		pid = atol(buf);
		if(pid) {
			if(kill(pid, 0) && errno == ESRCH)
				pid = 0;
		}
	}
	if(!pid)
		String::set(buf, sizeof(buf), "down");
#endif		
	printf(" <state>%s</state>\n", buf);
	printf("</serviceInfo>\n");
	error(200, "ok");
}

static void registry(const char *id)
{
	mapped_view<MappedRegistry> reg("sipwitch.regmap");
	unsigned count = reg.getCount();
	unsigned index = 0;
	volatile const MappedRegistry *member;
	MappedRegistry buffer;
	time_t now;
	struct tm *dt;
	char buf[64];
	const char *type;
	unsigned port;

	if(!count) 
		error(405, "Server unavailable");

	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"\r\n");

	printf("<?xml version=\"1.0\"?>\n");
	printf("<mappedRegistry>\n");
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
		time(&now);
		if(buffer.expires && buffer.expires < now)
			continue;
		if(id && buffer.ext && (unsigned)atoi(id) == buffer.ext)
			goto use;
		if(id && stricmp(id, buffer.userid))
			continue;
use:
		printf(" <entry id=\"%s\">\n", buffer.userid);
		if(buffer.ext)
			printf("  <extension>%d</extension>\n", buffer.ext);
		printf("  <used>%u</used>\n", buffer.inuse);
		if(buffer.expires && buffer.type != MappedRegistry::TEMPORARY)
			printf("  <expires>%ld</expires>\n", buffer.expires - now);
		switch(buffer.type) {
		case MappedRegistry::REJECT:
			type = "reject";
			break;
		case MappedRegistry::REFER:
			type = "refer";
			break;
		case MappedRegistry::GATEWAY:
			type = "gateway";
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
		printf("  <type>%s</type>\n", type);
		printf("  <class>%s</class>\n", buffer.profile.id);

		dt = localtime(&buffer.created);
		if(dt->tm_year < 1000)
			dt->tm_year += 1900;

		printf("  <created>%04d%02d%02dT%02d%02d%02d</created>\n",
			dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
			dt->tm_hour, dt->tm_min, dt->tm_sec);

		Socket::getaddress((struct sockaddr *)&buffer.contact, buf, sizeof(buf));
		port = Socket::getservice((struct sockaddr *)&buffer.contact);
		printf("  <address>%s</address>\n", buf);
		printf("  <service>%u</service>\n", port);
		printf(" </entry>\n");
		fflush(stdout);
	}
	printf("</mappedRegistry>\n");
	fflush(stdout);
	exit(0);
}

extern "C" int main(int argc, char **argv)
{
#ifdef _MSWINDOWS_
	char buf[256];
	GetEnvironmentVariable("APPDATA", buf, 192);
	unsigned len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\sipwitch\\config.xml");
	save_file = strdup(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\sipwitch\\config.tmp");
	temp_file = strdup(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\sipwitch\\snapshot.log");
	snapshot_file = strdup(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\sipwitch\\dumpfile.log");
	dump_file = strdup(buf);
	if(GetEnvironmentVariable("GATEWAY_INTERFACE", buf, sizeof(buf)) > 0)
		cgi_version = strdup(buf);
	if(GetEnvironmentVariable("REMOTE_USER", buf, sizeof(buf)) > 0)
		cgi_remuser = strdup(buf);
	if(GetEnvironmentVariable("REQUEST_METHOD", buf, sizeof(buf)) > 0)
		cgi_method = strdup(buf);
	if(GetEnvironmentVariable("QUERY_STRING", buf, sizeof(buf)) > 0)
		cgi_query = strdup(buf);
	if(GetEnvironmentVariable("CONTENT_TYPE", buf, sizeof(buf)) > 0)
		cgi_content = strdup(buf);
	if(GetEnvironmentVariable("CONTENT_LENGTH", buf, sizeof(buf)) > 0)
		cgi_length = atol(buf);
	control_file = "\\\\.\\mailslot\\sipwitch_ctrl";
#else
	save_file = DEFAULT_VARPATH "/run/sipwitch/config.xml";
	temp_file = DEFAULT_VARPATH "/run/sipwitch/config.tmp";
	control_file = DEFAULT_VARPATH "/run/sipwitch/control";
	dump_file = DEFAULT_VARPATH "/run/sipwitch/dumpfile";
	snapshot_file = DEFAULT_VARPATH "/run/sipwitch/snapshot";
	cgi_version = getenv("GATEWAY_INTERFACE");
	cgi_remuser = getenv("REMOTE_USER");
	cgi_method = getenv("REQUEST_METHOD");
	cgi_query = getenv("QUERY_STRING");
	cgi_content = getenv("CONTENT_LENGTH");
	if(cgi_content)
		cgi_length = atol(cgi_content);
	cgi_content = getenv("CONTENT_TYPE");
#endif

	if(!cgi_version) {
		fprintf(stderr, "*** sipwitch.cgi must execute from http server on password protected resource\n");
		exit(-1);
	}

	if(!cgi_remuser || !*cgi_remuser) 
		error(403, "Unauthorized to access sipwitch interface");

	if(cgi_method && !stricmp(cgi_method, "post"))
		post();

	if(cgi_query) {
		if(!strnicmp(cgi_query, "state-", 6) || !strnicmp(cgi_query, "state=", 6) || !strnicmp(cgi_query, "state_", 6)) {
			request("state %s", cgi_query + 6);
			error(200, "ok");
		}
 
		if(!stricmp(cgi_query, "reload")) {
			request("reload");
			error(200, "ok");
		}

		if(!stricmp(cgi_query, "restart")) {
			request("restart");
			error(200, "ok");
		}

		if(!stricmp(cgi_query, "check")) {
			request("check");
			error(200, "ok");
		}

		if(!stricmp(cgi_query, "snapshot"))
			snapshot();

		if(!stricmp(cgi_query, "dump"))
			dump();

		if(!stricmp(cgi_query, "info"))
			info();

		if(!stricmp(cgi_query, "registry"))
			registry(NULL);

		if(!stricmp(cgi_query, "calls"))
			calls(NULL);
		
		if(!strnicmp(cgi_query, "registry=", 9))
			registry(cgi_query + 9); 

		if(!strnicmp(cgi_query, "calls=", 6))
			calls(cgi_query + 6); 
	}

	config();
}


