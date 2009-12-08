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
#include <ctype.h>
#include <config.h>
#include <sys/stat.h>

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

#define	RPC_MAX_PARAMS 96

#ifdef	_MSWINDOWS_
typedef	DWORD	rpcint_t;
#else
typedef	int32_t	rpcint_t;
#endif
typedef	rpcint_t rpcbool_t;

typedef struct {
	const char *method;
	void (*exec)(void);
	const char *help;
	const char *signature;
}	node_t;

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

static void system_identity(void);
static void system_methods(void);
static void system_help(void);
static void system_signature(void);
static void system_status(void);
static void server_realm(void);
static void server_status(void);
static void server_control(void);
static void call_range(void);
static void call_instance(void);
static void stat_range(void);
static void stat_instance(void);
static void stat_periodic(void);
static void user_range(void);
static void user_instance(void);

static node_t nodes[] = {
	{"system.identity", &system_identity, "Identify server type and version", "string"},
	{"system.listMethods", &system_methods, "List server methods", "array"},
	{"system.methodHelp", &system_help, "Get help text for method", "string, string"},
	{"system.methodSignature", &system_signature, "Get parameter signature for specified method", "array, string"},
	{"system.status", &system_status, "Return server status information", "struct"},
	{"server.status", &server_status, "Return server status string", "string"}, 
	{"server.control", &server_control, "Return control request", "boolean, string"},
	{"server.realm", &server_realm, "Return server realm", "string"},
	{"call.range", &call_range, "Return list of active calls", "array"},
	{"call.instance", &call_instance, "Return specific call instance", "struct, string"},
	{"stat.range", &stat_range, "Return list of call stat nodes", "array"},
	{"stat.instance", &stat_instance, "return specific statistic node", "struct, string"},
	{"stat.periodic", &stat_periodic, "return periodic statistics of node", "struct, string"},
	{"user.range", &user_range, "Return list of user registrations", "array"},
	{"user.instance", &user_instance, "Return specific user registration", "struct, string"},
	{NULL, NULL, NULL, NULL}
};

static struct {
	char *name[RPC_MAX_PARAMS];
	char *map[RPC_MAX_PARAMS];
	char *value[RPC_MAX_PARAMS];
	unsigned short param[RPC_MAX_PARAMS];
	unsigned count;
	short argc;
} params;

static size_t xmlformat(char *dp, size_t max, const char *fmt, ...)
{
	va_list args;

	if(max < 0)
		return 0;

	va_start(args, fmt);
	vsnprintf(dp, max, fmt, args);
	va_end(args);
	return strlen(dp);
}

static const char *getIndexed(unsigned short param, unsigned short offset = 0)
{
	unsigned count = 0;
	unsigned member = 1;

	if(!offset)
		offset = 1;

	while(count < params.count) {
		if(params.param[count] > param)
			break;

		if(params.param[count] == param)
			if(member++ == offset)
				return (const char *)params.value[count];

		++count;
	}
	return NULL;
}

/*
static const char *getNamed(unsigned short param, const char *member)
{
	unsigned count = 0;

	while(count < params.count) {
		if(params.param[count] > param)
			break;

		if(params.param[count] == param)
			if(!strcmp(params.name[count], member))
				return (const char *)params.value[count];

		++count;
	}
	return NULL;
}

static const char *getMapped(const char *map, const char *member)
{
	unsigned count = 0;

	while(count < params.count) {
		if(!strcmp(params.map[count], map))
			if(!strcmp(params.name[count], member))
				return (const char *)params.value[count];
		++count;
	}
	return NULL;
}

static const char *getParamId(unsigned short param, unsigned short offset)
{
	unsigned count = 0;
	unsigned member = 1;

	if(!offset)
	offset = 1;

	while(count < params.count) {
		if(params.param[count] > param)
			break;

		if(params.param[count] == param)
			if(member++ == offset)
				return (const char *)params.name[count];

		++count;
	}
	return NULL;
}

*/

static size_t xmltext(char *dp, size_t max, const char *src)
{
	unsigned count = 0;
	while(*src && count < max) {
		switch(*src) {
		case '&':
			snprintf(dp + count, max - count, "&amp;");
			count += strlen(dp + count);
			++src;
			break;
		case '<':
			snprintf(dp + count, max - count, "&lt;");
			count += strlen(dp + count);
			++src;
			break;
		case '>':
			snprintf(dp + count, max - count, "&gt;");
			count += strlen(dp + count);
			++src;
			break;
		case '\"':
			snprintf(dp + count, max - count, "&quot;");
			count += strlen(dp + count);
			++src;
			break;
		 case '\'':
			snprintf(dp + count, max - count, "&apos;");
			count = strlen(dp + count);
			++src;
			break;
		default:
			dp[count++] = *(src++);
		}
	}
	return count;
}

static size_t b64encode(char *dest, const unsigned char *src, size_t size, size_t max)
{
	static const unsigned char alphabet[65] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	size_t count = 0;
	unsigned bits;

	while(size >= 3 && max > 4) {
		bits = (((unsigned)src[0])<<16) |
			(((unsigned)src[1])<<8) | ((unsigned)src[2]);

		src += 3;
		size -= 3;

			*(dest++) = alphabet[bits >> 18];
			*(dest++) = alphabet[(bits >> 12) & 0x3f];
			*(dest++) = alphabet[(bits >> 6) & 0x3f];
			*(dest++) = alphabet[bits & 0x3f];
		max -= 4;
		count += 4;
	}
	*dest = 0;
	if(!size || max < 5)
		return count;

	bits = ((unsigned)src[0])<<16;
	*(dest++) = alphabet[bits >> 18];
	++count;
	if (size == 1) {
	   		*(dest++) = alphabet[(bits >> 12) & 0x3f];
			*(dest++) = '=';
		count += 2;
	}
	else {
			bits |= ((unsigned)src[1])<<8;
			*(dest++) = alphabet[(bits >> 12) & 0x3f];
			*(dest++) = alphabet[(bits >> 6) & 0x3f];
		count += 2;
	}
	*(dest++) = '=';
	++count;
	*(dest++) = 0;
	return count;
}

static char *parseText(char *cp)
{
	char *dp = cp;
	char *rp = cp;

	if(!cp)
		return NULL;

	while(*cp) {
		if(*cp != '&') {
			*(dp++) = *(cp++);
			continue;
			}
		if(!strncmp(cp, "&amp;", 5)) {
					*(dp++) = '&';
			cp += 5;
			continue;
		}
 		else if(!strncmp(cp, "&gt;", 4))
		{
			*(dp++) = '>';
			cp += 4;
			continue;
		}
		else if(!strncmp(cp, "&lt;", 4))
		{
			*(dp++) = '<';
			*cp += 4;
			continue;
		}
		else if(!strncmp(cp, "&quot;", 6))
		{
			*(dp++) = '\"';
			*cp += 6;
			continue;
		}
		else if(!strncmp(cp, "&apos;", 6))
		{
			*(dp++) = '\'';
			*cp += 6;
			continue;
		}
		*(dp++) = *(cp++);
	}
	*dp = 0;
	return rp;
}

static char *parseValue(char *cp, char **value, char **map)
{
	*value = NULL;
	bool base64 = false;

	if(map)
		*map = NULL;

	while(*cp) {
		while(isspace(*cp))
			++cp;

		if(!strncmp(cp, "<base64>", 8)) {
			base64 = true;
			cp += 8;
			continue;
		}

		if(!strncmp(cp, "<struct>", 8))
			return cp + 8;
		else if(!strncmp(cp, "<array>", 7))
			return cp + 7;

		if(*cp == '<' && cp[1] != '/') {
			if(map)
				*map = ++cp;
			while(*cp && *cp != '>')
				++cp;
			if(*cp == '>')
				*(cp++) = 0;
			continue;
		}

		*value = cp;
		while(*cp && *cp != '<')
			++cp;

		if(*cp)
			*(cp++) = 0;

		while(*cp && *cp != '>')
			++cp;
		if(!*cp)
			return cp;
		++cp;
		parseText(*value);
		return cp;
	}
	return cp;
}

static char *parseName(char *cp, char **value)
{
	char *t = NULL;

	while(isspace(*cp))
		++cp;

	if(isalnum(*cp))
		t = cp;
	while(*cp && !isspace(*cp) && *cp != '<')
		++cp;
	while(isspace(*cp))
		*(cp++) = 0;
	if(*cp != '<')
		t = NULL;
	*(cp++) = 0;
	*value = parseText(t);
	return cp;
}

static void version(void)
{
	printf("sipwitch cgi 0.1.0\n"
        "Copyright (C) 2008 David Sugar, Tycho Softworks\n"
		"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
		"This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n");
    exit(0);
}

static void error(unsigned err, const char *text)
{
	printf(
		"Status: %d %s\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n"
		"%s\r\n", err, text, text);
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
	if(write(fd, buf, strlen(buf)) < (ssize_t)strlen(buf))
		error(500, "Failed Lock");
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
		if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
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
		if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
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
		if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
			fputs(buf, stdout);
	}
	fflush(stdout);
	exit(0);
}

static void response(char *buffer, unsigned max, const char *fmt, ...)
{
	rpcint_t iv;
	time_t tv;
	struct tm *dt, dbuf;
	double dv;
	const unsigned char *xp;
	size_t xsize;
	const char *sv;
	const char *valtype = "string";
	const char *name;
	bool end_flag = false;	// end of param...
	bool map_flag = false;
	bool struct_flag = false;
	bool array_flag = false;
	size_t count = strlen(buffer);
	va_list args;
	va_start(args, fmt);

	if(*fmt == '^') {
		count = 0;
		++fmt;
	}

	switch(*fmt) {
	case '(':
	case '[':
	case '<':
	case '{':
	case 's':
	case 'i':
	case 'd':
	case 't':
	case 'b':
	case 'x':
		count += xmlformat(buffer + count, max - count,
			"<?xml version=\"1.0\"?>\r\n"
			"<methodResponse>\r\n"
			" <params><param>\r\n");
		break;
	case '!':
		array_flag = true;
		break;
	case '+':
		map_flag = true;
	case '.':
		struct_flag = true;
	}

	if(!*fmt)
		end_flag = true;

	while(*fmt && *fmt != '$' && count < max - 1 && !end_flag) {
		switch(*fmt) {
		case '[':
			count += xmlformat(buffer + count, max - count,
				" <value><array><data>\r\n");
		case ',':
			array_flag = true;
			break;
		case ']':
			array_flag = false;
			count += xmlformat(buffer + count, max - count,
				" </data></array></value>\r\n");
			end_flag = true;
			break;
		case '}':
		case '>':
			map_flag = struct_flag = false;
			count += xmlformat(buffer + count, max - count,
				" </struct></value></member>\r\n"
				" </struct></value>\r\n");
			end_flag = true;
			break;
		case ';':
		case ':':
			name = va_arg(args, const char *);
			count += xmlformat(buffer + count, max - count,
				" </struct></value></member>\r\n"
				" <member><name>%s<value><struct>\r\n", name);
			break;
		case '{':
		case '<':
			name = va_arg(args, const char *);
			count += xmlformat(buffer + count, max - count,
				" <value><struct>\r\n"
				" <member><name>%s</name><value><struct>\r\n", name);
			struct_flag = map_flag = true;
			break;
		case '(':
			struct_flag = true;
			count += xmlformat(buffer + count, max - count, " <value><struct>\r\n");
			break;
		case ')':
			struct_flag = false;
			if(!map_flag && !array_flag)
				end_flag = true;
			count += xmlformat(buffer + count, max - count,
				" </struct></value>\r\n");
			break;
		case 's':
		case 'i':
		case 'b':
		case 'd':
		case 't':
		case 'x':
		case 'm':
			switch(*fmt) {
			case 'm':
				valtype = "string";
				break;
			case 'd':
				valtype = "double";
				break;
			case 'b':
				valtype = "boolean";
				break;
			case 'i':
				valtype = "i4";
				break;
			case 's':
				valtype = "string";
				break;
			case 't':
				valtype = "dateTime.iso8601";
				break;
			case 'x':
				valtype = "base64";
			}
			if(struct_flag && *fmt == 'm') {
				if(count > max - 60)
					goto skip;
				sv = va_arg(args, const char *);
				while(sv && *sv) {
					count += xmlformat(buffer + count, max - count,
						"  <member><name>");
					while(*sv && *sv != ':' && *sv != '=' && count < max - 35) {
						buffer[count++] = tolower(*sv);
						++sv;
					}
					buffer[count] = 0;
					count += xmlformat(buffer + count, max - count,
						"</name>\r\n"
						"   <value><%s>", valtype);
					if(*sv == ':' || *sv == '=')
						++sv;
					else
						sv="";
					while(*sv && *sv != ';' && count < max - 20) {
						switch(*sv) {
						case '<':
							count += xmlformat(buffer + count, max - count, "&lt;");
							break;
						case '>':
							count += xmlformat(buffer + count, max - count, "&gt;");
							break;
						case '&':
							count += xmlformat(buffer + count, max - count, "&amp;");
							break;
						case '\"':
							count += xmlformat(buffer + count, max - count, "&quot;");
							break;
						case '\'':
							count += xmlformat(buffer + count, max - count, "&apos;");
							break;
						default:
							buffer[count++] = *sv;
						}
						++sv;
					}
					count += xmlformat(buffer + count, max - count,
						"</%s></value></member>\r\n", valtype);
				}
				goto skip;
			}
			if(struct_flag) {
				name = va_arg(args, const char *);
				count += xmlformat(buffer + count, max - count,
					"  <member><name>%s</name>\r\n"
					"   <value><%s>", name, valtype);
			}
			else
				count += xmlformat(buffer + count, max - count,
					"  <value><%s>", valtype);

			switch(*fmt) {
			case 'x':
				xp = va_arg(args, const unsigned char *);
				xsize = va_arg(args, size_t);
				count += b64encode(buffer + count, xp, xsize, max - count);
				break;
			case 's':
				sv = va_arg(args, const char *);
				if(!sv)
					sv = "";
				count += xmltext(buffer + count, max - count, sv);
				break;
			case 'd':
				dv = va_arg(args, double);
				count += xmlformat(buffer + count, max - count, "%f", dv);
				break;
			case 'i':
			case 'b':
				iv = va_arg(args, rpcint_t);
				if(*fmt == 'b' && iv)
					iv = 1;
				count += xmlformat(buffer + count, max - count, "%ld", (long)iv);
				break;
			case 't':
				tv = va_arg(args, time_t);
				dt = localtime_r(&tv, &dbuf);
				if(dt->tm_year < 1800)
					dt->tm_year += 1900;
				count += xmlformat(buffer + count, max - count,
					"%04d%02d%02dT%02d:%02d:%02d",
					dt->tm_year, dt->tm_mon + 1, dt->tm_mday,
					dt->tm_hour, dt->tm_min, dt->tm_sec);
				break;
			}
			if(struct_flag)
				count += xmlformat(buffer + count, max - count,
					"</%s></value></member>\r\n", valtype);
			else
				count += xmlformat(buffer + count, max - count,
					"</%s></value>\r\n", valtype);
skip:
			if(!struct_flag && !array_flag)
				end_flag = true;
		}
		++fmt;
	}

	if(*fmt == '$' || end_flag)
		count += xmlformat(buffer + count, max - count,
			" </param></params>\r\n"
			"</methodResponse>\r\n");

	va_end(args);
}

static void reply(const char *buffer)
{
	printf(
		"Status: 200 OK\r\n"
		"Content-Length: %ld\r\n"
		"Content-Type: text/xml\r\n"
		"\r\n%s", (long)strlen(buffer), buffer);
	exit(0);
}

/*
static void success(void)
{
	char buffer[1024];

	xmlformat(buffer, sizeof(buffer),
		"<?xml version=\"1.0\"?>\r\n"
		"<methodResponse><params></params></methodResponse>\r\n");

	reply(buffer);
}
*/

static void fault(int code, const char *string)
{
	char buffer[4096];

	size_t count = xmlformat(buffer, sizeof(buffer),
		"<?xml version=\"1.0\"?>\r\n"
		"<methodResponse>\r\n"
		" <fault><value><struct>\r\n"
		"  <member><name>faultCode</name>\r\n"
		"   <value><int>%d</int></value></member>\r\n"
		"  <member><name>faultString</name>\r\n"
		"   <value><string>", code);
	count += xmltext(buffer + count, sizeof(buffer) - count, string);
	count += xmlformat(buffer + count, sizeof(buffer) - count,
		"</string></value></member>\r\n"
		" </struct></value></fault>\r\n"
		"</methodResponse>\r\n");

	reply(buffer);
}

static void system_methods(void)
{
	char buffer[2048];
	unsigned index = 0;

	if(params.argc)
		fault(3, "Invalid Parameters");

	response(buffer, sizeof(buffer), "^[");

	while(nodes[index].method) {
		response(buffer, sizeof(buffer), "!s", nodes[index].method);
		++index;
	}

	response(buffer, sizeof(buffer), "]");
	reply(buffer);
}

static void system_help(void)
{
	char buffer[1024];
	unsigned index = 0;

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *method = getIndexed(1);
	if(!method || !*method)
		fault(4, "Invalid Method Argument");

	while(nodes[index].method && !String::equal(nodes[index].method, method))
		++index;

	if(!nodes[index].help)
		fault(4, "Unknown Method");

	response(buffer, sizeof(buffer), "^s", nodes[index].help);
	reply(buffer);
}

static void system_signature(void)
{
	char buffer[1024];
	unsigned index = 0;

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *method = getIndexed(1);
	if(!method || !*method)
		fault(4, "Invalid Method Argument");

	while(nodes[index].method && !String::equal(nodes[index].method, method))
		++index;

	if(!nodes[index].signature)
		fault(4, "Unknown Method");

	response(buffer, sizeof(buffer), "^[!s]", nodes[index].signature);
	reply(buffer);
}

static void system_identity(void)
{
	char buffer[512];

	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	response(buffer, sizeof(buffer), "^s", "sipwitch/" VERSION);
	reply(buffer);
}

static bool iocontrol(const char *cmd)
{
	char buffer[512];
	FILE *fp;
#ifdef	_MSWINDOWS_
	snprintf(buffer, sizeof(buffer), "%s\n", cmd);
#else
	snprintf(buffer, sizeof(buffer), "%d %s\n", getpid(), cmd);
#endif
	char *ep = strchr(buffer, '\n');
	if(ep)
		*(++ep) = 0;

#ifndef	_MSWINDOWS_
	int signo;
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigs, NULL);
#endif	

	fp = fopen(control_file, "w");
	if(!fp)
		fault(2, "Server Offline");

	fputs(buffer, fp);
	fclose(fp);
#ifndef	_MSWINDOWS_
	alarm(60);
#ifdef	HAVE_SIGWAIT2
	sigwait(&sigs, &signo);
#else
	signo = sigwait(&sigs);
#endif
	if(signo == SIGUSR2)
		return false;
	if(signo == SIGALRM)
		fault(6, "Request Timed Out");
#endif
	return true;
}

static void server_control(void)
{
	char buffer[512];

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *command = getIndexed(1);
	if(!command || !*command)
		fault(5, "Invalid Command Argument");	

	response(buffer, sizeof(buffer), "^(b)", iocontrol(command));
	reply(buffer);
}

static void call_instance(void)
{
	mapped_view<MappedCall> cr(REGISTRY_MAP);
	unsigned index = 0;
	char id[32];
	MappedCall copy;
	char buffer[1024];
	rpcint_t diff = 0;
	time_t now;

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *cid = getIndexed(1);
	if(!cid || !*cid)
		fault(5, "Invalid Command Argument");	


	unsigned count = cr.getCount();
	if(!count)
		fault(2, "Server Offline");

	time(&now);
	while(index < count) {
		const MappedCall *map = const_cast<const MappedCall *>(cr(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(!map->created)
			continue;

		snprintf(id, sizeof(id), "%08x:%d", map->sequence, map->cid);
		if(!String::equal(id, cid))
			continue;
	
		if(map->active) {
			time(&now);
			diff = (rpcint_t)(now - map->active);
		}

		response(buffer, sizeof(buffer), "^(tsssssi)",
			map->created, map->state + 1, map->authorized,
			map->source, map->target, map->display, diff);
		reply(buffer);
	}
	fault(6, "Unknown Call");
}

static void call_range(void)
{
	mapped_view<MappedCall> cr(REGISTRY_MAP);
	unsigned size;
	unsigned index = 0;
	char id[32];
	MappedCall copy;

	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	unsigned count = cr.getCount();
	if(!count)
		fault(2, "Server Offline");

	size = count * 64 + 128;
	char *buffer = (char *)malloc(size);
	response(buffer, size, "^[");

	while(index < count) {
		const MappedCall *map = const_cast<const MappedCall *>(cr(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(!map->created)
			continue;
	
		snprintf(id, sizeof(id), "%08x:%d", map->sequence, map->cid);
		response(buffer, size, "!s", buffer);
	}
	response(buffer, size, "]");
	reply(buffer);
}

static void stat_periodic(void)
{
	mapped_view<stats> sta(STAT_MAP);
	unsigned index = 0;
	stats copy;
	char buffer[1024];

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *cid = getIndexed(1);
	if(!cid || !*cid)
		fault(5, "Invalid Command Argument");	

	unsigned count = sta.getCount();
	if(!count)
		fault(2, "Server Offline");

	while(index < count) {
		const stats *map = const_cast<const stats *>(sta(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(!String::equal(map->id, cid))
			continue;
	
		response(buffer, sizeof(buffer), "^(itiiiiii)",
			(rpcint_t)map->limit, map->lastcall,
			(rpcint_t)map->data[0].pperiod, (rpcint_t)map->data[0].pmin, (rpcint_t)map->data[0].pmax,
			(rpcint_t)map->data[1].pperiod, (rpcint_t)map->data[1].pmin, (rpcint_t)map->data[1].pmax);
		reply(buffer);
	}
	fault(7, "Unknown Stat");
}

static void stat_instance(void)
{
	mapped_view<stats> sta(STAT_MAP);
	unsigned index = 0;
	stats copy;
	char buffer[1024];

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *cid = getIndexed(1);
	if(!cid || !*cid)
		fault(5, "Invalid Command Argument");	

	unsigned count = sta.getCount();
	if(!count)
		fault(2, "Server Offline");

	while(index < count) {
		const stats *map = const_cast<const stats *>(sta(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(!String::equal(map->id, cid))
			continue;
	
		response(buffer, sizeof(buffer), "^(itiiiiii)",
			(rpcint_t)map->limit, map->lastcall,
			(rpcint_t)map->data[0].total, (rpcint_t)map->data[0].current, (rpcint_t)map->data[0].peak,
			(rpcint_t)map->data[1].total, (rpcint_t)map->data[1].current, (rpcint_t)map->data[1].peak);
		reply(buffer);
	}
	fault(7, "Unknown Stat");
}

static void stat_range(void)
{
	mapped_view<stats> sta(STAT_MAP);
	unsigned size;
	unsigned index = 0;
	stats copy;

	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	unsigned count = sta.getCount();
	if(!count)
		fault(2, "Server Offline");

	size = count * 48 + 128;
	char *buffer = (char *)malloc(size);
	response(buffer, size, "^[");

	while(index < count) {
		const stats *map = const_cast<const stats *>(sta(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(!map->id[0])
			continue;

		response(buffer, size, "!s", map->id);
	}
	response(buffer, size, "]");
	reply(buffer);
}

static void user_instance(void)
{
	mapped_view<MappedRegistry> reg(REGISTRY_MAP);
	unsigned index = 0;
	char ext[48];
	MappedRegistry copy;
	char buffer[2048];
	time_t now;
	const char *status = "idle";

	if(params.argc != 1)
		fault(3, "Invalid Parameters");

	const char *id = getIndexed(1);
	if(!id || !*id)
		fault(5, "Invalid Command Argument");	

	unsigned count = reg.getCount();
	if(!count)
		fault(2, "Server Offline");

	time(&now);
	while(index < count) {
		const MappedRegistry *map = const_cast<const MappedRegistry *>(reg(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(map->type != MappedRegistry::USER && map->type != MappedRegistry::SERVICE) 
			continue;

		if(map->expires < now)
			continue;

		if(!String::equal(map->userid, id))
			continue;
	
		if(map->ext)
			snprintf(ext, sizeof(ext), "%u", map->ext);
		else
			String::set(ext, sizeof(ext), map->userid);

		if(map->inuse)
			status = "busy";
		else
			switch(map->status) {
			case MappedRegistry::AWAY:
				status = "away";
				break;
			case MappedRegistry::DND:
				status = "dnd";
				break;
			case MappedRegistry::BUSY:
				status = "busy";
				break;
			default:
				break;
			}

		response(buffer, sizeof(buffer), "^(ssssii)",
			ext, map->display, map->profile.id, status,
			(rpcint_t)map->inuse, (rpcint_t)map->profile.level);
		reply(buffer);
	}
	fault(8, "Unknown User");
}

static void user_range(void)
{
	mapped_view<MappedRegistry> reg(REGISTRY_MAP);
	unsigned size;
	unsigned index = 0;
	MappedRegistry copy;

	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	unsigned count = reg.getCount();
	if(!count)
		fault(2, "Server Offline");

	size = count * 48 + 128;
	char *buffer = (char *)malloc(size);
	response(buffer, size, "^[");
	time_t now;
	time(&now);

	while(index < count) {
		const MappedRegistry *map = const_cast<const MappedRegistry *>(reg(index++));
	
		do {
			memcpy(&copy, map, sizeof(copy));
		} while(memcmp(&copy, map, sizeof(copy)));
		map = &copy;

		if(map->type != MappedRegistry::USER && map->type != MappedRegistry::SERVICE) 
			continue;

		if(map->expires < now)
			continue;

		response(buffer, size, "!s", map->userid);
	}
	response(buffer, size, "]");
	reply(buffer);
}

static void server_realm(void)
{
	fsys fd;
	char realm[128];
	char buffer[256];

	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	fsys::open(fd, "/tmp/siprealm", fsys::ACCESS_RDONLY);
	if(is(fd)) {
		memset(realm, 0, sizeof(realm));
		fsys::read(fd, realm, sizeof(realm) - 1);
		fsys::close(fd);
	}
	else
		fault(2, "Server Offline");

	response(buffer, sizeof(buffer), "^s", realm);
	reply(buffer);
}

static void server_status(void)
{
	mapped_view<MappedCall> cr(REGISTRY_MAP);
	char *cp;
	unsigned index = 0;
	volatile const MappedCall *map;

	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	unsigned count = cr.getCount();
	if(!count)
		fault(2, "Server Offline");

	cp = (char *)malloc(count + 1);
	cp[count] = 0;
	memset(cp, ' ', count);
	while(index < count) {
		map = (const volatile MappedCall*)(cr(index++));
		if(map->state[0])
			cp[index - 1] = map->state[0];
	}
	char *buffer = (char *)malloc(count + 512);
	response(buffer, count + 512, "^s", cp);
	reply(buffer);
}
	
static void system_status(void)
{
	time_t now;
	struct stat ino;
	char buffer[512];
	unsigned count = 0;


	if(params.argc != 0)
		fault(3, "Invalid Parameters");

	if(stat(control_file, &ino))
		fault(2, "Server Offline");

	while(nodes[count].method)
		++count;

	time(&now);
	response(buffer, sizeof(buffer), "^(titissi)", 
		"date", now,
		"date_int", (rpcint_t)now,
		"started", ino.st_ctime,
		"started_int", ino.st_ctime,
		"name", "sipwitch",
		"version", VERSION,
		"methods_known", (rpcint_t)count);

	reply(buffer);
}		
	
static void dispatch(const char *method)
{
	unsigned index = 0;
	while(nodes[index].method && !String::equal(method, nodes[index].method))
		++index;
	if(!nodes[index].method)
		fault(1, "Unknown Method");
	(*nodes[index].exec)();
}

static void post(FILE *inp = stdin)
{
	FILE *fp;
	char *buf;
	char *cp;
	char *value;
	char *map = NULL;
	char *method;
	bool name_flag = false;

	params.argc = 0;
	params.count = 0;

	if(!cgi_length)
		error(411, "Length required");
	if(!cgi_content || stricmp(cgi_content, "text/xml"))
		error(415, "Unsupported media type");

	buf = new char[cgi_length + 1];
	if(fread(buf, cgi_length, 1, inp) < 1)
		error(400, "Invalid read of input");
 
	buf[cgi_length] = 0;

	cp = buf;
	while(*cp) {
		while(isspace(*cp))
			++cp;

		if(!strncmp(cp, "<sipwitch>", 10)) {
			cgilock();
			remove(temp_file);
			fp = fopen(temp_file, "w");
			if(!fp) {
				cgiunlock();
				error(403, "Access forbidden");
			}
	
			if(fwrite(buf, cgi_length, 1, fp) < 1) {
				cgiunlock();
				error(500, "Invalid write of config");
			}

			fclose(fp);
			rename(temp_file, save_file);
			cgiunlock();
			request("reload");
			error(200, "ok");
		}

		if(!strncmp(cp, "<methodName>", 12)) {
			cp = parseName(cp + 12, &method);
			if(strncmp(cp, "/methodName>", 12) || !method) 
				error(400, "Malformed request");

			cp += 12;
			break;

		}

		if(!strncmp(cp, "<methodCall>", 12)) {
			cp += 12;
			continue;
		}

		if(!strncmp(cp, "<?", 2) || !strncmp(cp, "<!", 2)) {
			while(*cp && *cp != '>')
				++cp;
			if(*cp)
				++cp;
			continue;
		}

		error(400, "Malformed request");
	}

	if(!method || !*cp)
		error(400, "Malformed request");

	while(*cp && params.count < RPC_MAX_PARAMS) {
		while(isspace(*cp))
			++cp;

		if(!*cp)
			break;

		if(!strncmp(cp, "<name>", 6)) {
			name_flag = true;
			cp = parseName(cp + 6, &params.name[params.count]);
			params.map[params.count] = map;
			if(strncmp(cp, "/name>", 6))
				error(400, "Malformed request");

			cp += 6;
			continue;
		}
		if(!strncmp(cp, "</struct>", 9) && map && !name_flag) {
			map = NULL;
			cp += 9;
			continue;
		}
		if(!strncmp(cp, "<param>", 7)) {
			params.name[params.count] = params.value[params.count] = params.map[params.count] = NULL;
			++params.argc;
			cp += 7;
			continue;
		}
		if(!strncmp(cp, "<value>", 7)) {
			params.param[params.count] = params.argc;
			cp = parseValue(cp, &value, NULL);
			if(value)
				params.value[params.count++] = value;
			else if(name_flag)
				map = params.name[params.count];
			name_flag = false;
			params.name[params.count] = params.map[params.count] = params.value[params.count] = NULL;
			continue;
		}
		if(!strncmp(cp, "</params>", 9))
			dispatch(method);

		if(*cp == '<') {
			while(*cp && *cp != '>')
				++cp;
			if(*cp)
				++cp;
			else
				error(400, "Malformed request");
			continue;
		}
		error(400, "Malformed request");
	}
	error(400, "Malformed request");
}

static void callfile(FILE *fp, const char *id)
{
#ifdef	_MSWINDOWS_
	struct _stat ino;
#else
	struct stat ino;
#endif
	char buf[256];
	const char *cp = NULL;
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
		if(fgets(buf, sizeof(buf), fp) == NULL)
			buf[0] = 0;
		if(!buf[0])
			continue;
		cp = buf;
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
	callfile(fopen(DEFAULT_VARPATH "/log/sipwitch.calls.0", "r"), id);
	callfile(fopen(DEFAULT_VARPATH "/log/sipwitch.calls", "r"), id);
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
		if(fgets(buf, sizeof(buf), fp) == NULL)
			buf[0] = 0;
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
		if(fgets(buf, sizeof(buf), fp) == NULL)
			buf[0] = 0;
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
	exit(0);
}

static void dumpcalls(const char *id)
{
	mapped_view<MappedCall> calls(CALL_MAP);
	unsigned count = calls.getCount();
	unsigned index = 0;
	volatile const MappedCall *member;
	MappedCall buffer;
	char idbuf[32];
	time_t now;

	if(!count) 
		error(405, "Server unavailable");

	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"\r\n");

	printf("<?xml version=\"1.0\"?>\n");
	printf("<mappedCalls>\n");
	time(&now);

	while(index < count) {
		member = (const volatile MappedCall *)(calls(index++));
		do {	
			memcpy(&buffer, (const void *)member, sizeof(buffer));
		} while(memcmp(&buffer, (const void *)member, sizeof(buffer)));
		if(!member->created)
			continue;

		snprintf(idbuf, sizeof(idbuf), "%08x:%u", buffer.sequence, buffer.cid);
		if(id && !String::equal(id, idbuf))
			continue;
		printf(" <call id=\"%s\">\n", idbuf);
		printf("  <source>%s</source>\n", buffer.source);
		printf("  <started>%ld</started>\n", now - buffer.created);
		if(buffer.target[0]) {
			printf("  <active>%ld</active>\n", now - buffer.active);
			printf("  <target>%s</target>\n", buffer.target);
		}
		printf(" </call>\n");
	}
	printf("</mappedCalls>\n");
	fflush(stdout);
	exit(0);
}

static void dumpstats(const char *id)
{
	mapped_view<stats> sta(STAT_MAP);
	unsigned count = sta.getCount();
	unsigned index = 0;
	volatile const stats *member;
	stats buffer;
	time_t now;

	if(!count) 
		error(405, "Server unavailable");

	printf(
		"Status: 200 OK\r\n"
		"Content-Type: text/xml\r\n"
		"\r\n");

	printf("<?xml version=\"1.0\"?>\n");
	printf("<mappedStats>\n");
	time(&now);

	while(index < count) {
		member = (const volatile stats *)(sta(index++));
		do {	
			memcpy(&buffer, (const void *)member, sizeof(buffer));
		} while(memcmp(&buffer, (const void *)member, sizeof(buffer)));
		if(!member->id[0])
			continue;
		if(id && !String::equal(id, buffer.id))
			continue;
		printf(" <stat id=\"%s\">\n", buffer.id);
		printf("  <incoming>\n");
		printf("   <total>%lu</total>\n", buffer.data[0].total);
		printf("   <period>%lu</period>\n", buffer.data[0].period);
		printf("   <current>%hu</current>\n", buffer.data[0].current);
		printf("   <peak>%hu</peak>\n", buffer.data[0].peak);
		printf("  </incoming>\n");
		printf("  <outgoing>\n");
		printf("   <total>%lu</total>\n", buffer.data[1].total);
		printf("   <period>%lu</period>\n", buffer.data[1].period);
		printf("   <current>%hu</current>\n", buffer.data[1].current);
		printf("   <peak>%hu</peak>\n", buffer.data[1].peak);
		printf("  </outgoing>\n");
		printf(" </stat>\n");
	}
	printf("</mappedStats>\n");
	fflush(stdout);
	exit(0);
}

static void registry(const char *id)
{
	mapped_view<MappedRegistry> reg(REGISTRY_MAP);
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
		member = (const volatile MappedRegistry *)(reg(index++));
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
		printf(" <registry id=\"%s\">\n", buffer.userid);
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
		printf(" </registry>\n");
		fflush(stdout);
	}
	printf("</mappedRegistry>\n");
	fflush(stdout);
	exit(0);
}

extern "C" int main(int argc, char **argv)
{
	if(argc > 1) {
		if(String::equal(argv[1], "-version") || String::equal(argv[1], "--version")) 
			version();
	}

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

		if(!stricmp(cgi_query, "stats"))
			dumpstats(NULL);

		if(!stricmp(cgi_query, "sessions"))
			dumpcalls(NULL);

		if(!stricmp(cgi_query, "calls"))
			calls(NULL);
		
		if(!strnicmp(cgi_query, "registry=", 9))
			registry(cgi_query + 9); 

		if(!strnicmp(cgi_query, "stats=", 6))
			dumpstats(cgi_query + 6); 

		if(!strnicmp(cgi_query, "calls=", 6))
			calls(cgi_query + 6); 

		if(!strnicmp(cgi_query, "sessions=", 9))
			dumpcalls(cgi_query + 9); 
	}

	config();
}


