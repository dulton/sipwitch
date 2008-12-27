// Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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

#include <config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/process.h>
#include <sipwitch/service.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

static const char *replytarget = NULL;
static const char *ident = "sipwitch";

#ifndef	_MSWINDOWS_

#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <limits.h>
#include <pwd.h>

static FILE *fifo = NULL;
static char fifopath[128] = "";

typedef	unsigned long long uuid_time_t;

static void get_system_time(uuid_time_t *uuid_time)
{
    struct timeval tp;

    gettimeofday(&tp, (struct timezone *)0);

    /* Offset between UUID formatted times and Unix formatted times.
       UUID UTC base time is October 15, 1582.
       Unix base time is January 1, 1970.*/
    *uuid_time = ((unsigned long long)tp.tv_sec * 10000000)
        + ((unsigned long long)tp.tv_usec * 10)
        + 0x01B21DD213814000ll;
}

size_t process::attach(const char *id, const char *uid)
{
	assert(id != NULL && *id != 0);
	assert(uid != NULL && *uid != 0);

	struct stat ino;

	if(!uid)
		uid = process::identity();
	ident = id;
	snprintf(fifopath, sizeof(fifopath), DEFAULT_VARPATH "/run/%s", ident);
	if(!stat(fifopath, &ino) && S_ISDIR(ino.st_mode) && !access(fifopath, W_OK)) 
		snprintf(fifopath, sizeof(fifopath), DEFAULT_VARPATH "/run/%s/control", ident);
	else
		snprintf(fifopath, sizeof(fifopath), "/tmp/%s-%s/control", ident, uid);

	remove(fifopath);
	if(mkfifo(fifopath, 0660)) {
		fifopath[0] = 0;
		return 0;
	}

	fifo = fopen(fifopath, "r+");
	if(fifo) 
		return 512;
	fifopath[0] = 0;
	return 0;
}

static void logfile(fsys_t &fs)
{
	char buf[128];

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/log/%s.log", ident);
	fsys::create(fs, buf, fsys::ACCESS_APPEND, 0660);
	if(is(fs))
		return;

	snprintf(buf, sizeof(buf), "/tmp/%s-%s/logfile", ident, process::identity());
	fsys::create(fs, buf, fsys::ACCESS_APPEND, 0660); 
}

void process::release(void)
{
	errlog(INFO, "shutdown");
	if(fifopath[0]) {
		::remove(fifopath);
		char *cp = strrchr(fifopath, '/');
		String::set(cp, 10, "/pidfile");
		::remove(fifopath);
		fifopath[0] = 0;
	}
}

char *process::receive(void)
{
	static char buf[512];
	char *cp;

	if(!fifo)
		return NULL;

	reply(NULL);

retry:
	buf[0] = 0;
	if(fgets(buf, sizeof(buf), fifo) == NULL)
		buf[0] = 0;
	cp = String::strip(buf, " \t\r\n");
	if(*cp == '/') {
		if(strstr(cp, ".."))
			goto retry;

		if(strncmp(cp, "/tmp/.reply.", 12))
			goto retry; 
	}

	if(*cp == '/' || isdigit(*cp)) {
		replytarget = cp;
		while(*cp && !isspace(*cp))
			++cp;
		*(cp++) = 0;
		while(isspace(*cp))
			++cp;
	}	
	return cp;
}

void process::errlog(errlevel_t loglevel, const char *fmt, ...)
{
	assert(fmt != NULL && *fmt != 0);

	char buf[256];
	int level = LOG_ERR;
	va_list args;	

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	switch(loglevel)
	{
	case DEBUG1:
	case DEBUG2:
	case DEBUG3:
		if((getppid() > 1) && (loglevel <= verbose)) {
			if(fmt[strlen(fmt) - 1] == '\n') 
				fprintf(stderr, "sipw: %s", buf);
			else
				fprintf(stderr, "sipw: %s\n", buf);
		}
		return;
	case INFO:
		level = LOG_INFO;
		break;
	case NOTIFY:
		level = LOG_NOTICE;
		break;
	case WARN:
		level = LOG_WARNING;
		break;
	case ERRLOG:
		level = LOG_ERR;
		break;
	case FAILURE:
		level = LOG_CRIT;
		break;
	default:
		level = LOG_ERR;
	}

	if(loglevel <= verbose) {
		if(getppid() > 1) {
			if(fmt[strlen(fmt) - 1] == '\n') 
				fprintf(stderr, "sipw: %s", buf);
			else
				fprintf(stderr, "sipw: %s\n", buf);
		}
		service::snmptrap(loglevel + 10, buf);
		::syslog(level, "%s", buf);
	}
	
	if(level == LOG_CRIT)
		cpr_runtime_error(buf);
}


#else

static HANDLE hFifo = INVALID_HANDLE_VALUE;
static HANDLE hLoopback = INVALID_HANDLE_VALUE;
static HANDLE hEvent = INVALID_HANDLE_VALUE;
static OVERLAPPED ovFifo;

typedef	__int64 uuid_time_t;

static void get_system_time(uuid_time_t *uuid_time)
{
    ULARGE_INTEGER time;

    /* NT keeps time in FILETIME format which is 100ns ticks since
       Jan 1, 1601. UUIDs use time in 100ns ticks since Oct 15, 1582.
       The difference is 17 Days in Oct + 30 (Nov) + 31 (Dec)
       + 18 years and 5 leap days. */
    GetSystemTimeAsFileTime((FILETIME *)&time);
    time.QuadPart +=

          (unsigned __int64) (1000*1000*10)       // seconds
        * (unsigned __int64) (60 * 60 * 24)       // days
        * (unsigned __int64) (17+30+31+365*18+5); // # of days
    *uuid_time = time.QuadPart;
}

static void logfile(fsys_t& fd)
{
	char buf[256];
	unsigned len;

	GetEnvironmentVariable("APPDATA", buf, 192);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\%s\\service.log", ident);
	
	fsys::create(fd, buf, fsys::ACCESS_APPEND, 0660);
}

size_t process::attach(const char *id, const char *uid)
{
	char buf[64];

	ident = id;
	snprintf(buf, sizeof(buf), "\\\\.\\mailslot\\%s_ctrl", ident);
	hFifo = CreateMailslot(buf, 0, MAILSLOT_WAIT_FOREVER, NULL);
	if(hFifo == INVALID_HANDLE_VALUE)
		return 0;

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	hLoopback = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	ovFifo.Offset = 0;
	ovFifo.OffsetHigh = 0;
	ovFifo.hEvent = hEvent;
	return 464;
}
	
char *process::receive(void)
{
	static char buf[464];
	BOOL result;
	DWORD msgresult;
	const char *lp;
	char *cp;

	if(hFifo == INVALID_HANDLE_VALUE)
		return NULL;

	reply(NULL);
	
retry:
	result = ReadFile(hFifo, buf, sizeof(buf) - 1, &msgresult, &ovFifo);
	if(!result && GetLastError() == ERROR_IO_PENDING) {
		int ret = WaitForSingleObject(ovFifo.hEvent, INFINITE);
		if(ret != WAIT_OBJECT_0)
			return NULL;
		result = GetOverlappedResult(hFifo, &ovFifo, &msgresult, TRUE);
	}
	
	if(!result || msgresult < 1)
		return NULL;
	
	buf[msgresult] = 0;
	cp = String::strip(buf, " \t\r\n");
	
	if(*cp == '\\') {
		if(strstr(cp, ".."))
			goto retry;

		if(strncmp(cp, "\\\\.\\mailslot\\", 14))
			goto retry; 
	}

	if(*cp == '\\' || isdigit(*cp)) {
		replytarget = cp;
		while(*cp && !isspace(*cp))
			++cp;
		*(cp++) = 0;
		while(isspace(*cp))
			++cp;
		lp = replytarget + strlen(replytarget) - 6;
		if(stricmp(lp, "_temp")) 
			goto retry;
	}	
	return cp;
} 

void process::errlog(errlevel_t loglevel, const char *fmt, ...)
{
	assert(fmt != NULL && *fmt != 0);

	char buf[256];
	va_list args;	

	va_start(args, fmt);

	assert(fmt != NULL);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if(loglevel <= verbose) {
		if(fmt[strlen(fmt) - 1] == '\n') 
			fprintf(stderr, "%s: %s", getenv("IDENT"), buf);
		else
			fprintf(stderr, "%s: %s\n", getenv("IDENT"), buf);
		service::snmptrap(loglevel + 10, buf);
	}
	
	if(loglevel == FAILURE)
		cpr_runtime_error(buf);
}

void process::release(void)
{
	errlog(INFO, "shutdown");

	if(hFifo != INVALID_HANDLE_VALUE) {
		CloseHandle(hFifo);
		CloseHandle(hLoopback);
		CloseHandle(hEvent);
		hFifo = hLoopback = hEvent = INVALID_HANDLE_VALUE;
	}
}

#endif

errlevel_t process::verbose = FAILURE;

void process::printlog(const char *fmt, ...)
{
	assert(fmt != NULL && *fmt != 0);

	fsys_t log;
	va_list args;
	char buf[1024];
	int len;
	char *cp;

	va_start(args, fmt);

	logfile(log);

	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	len = strlen(buf);
	if(buf[len - 1] != '\n')
		buf[len++] = '\n';

	if(is(log)) {		
		fsys::write(log, buf, strlen(buf));
		fsys::close(log);
	}
	cp = strchr(buf, '\n');
	if(cp)
		*cp = 0;

	debug(2, "logfile: %s", buf);
	va_end(args);
}

void process::reply(const char *msg)
{
	assert(msg == NULL || *msg != 0);

	pid_t pid;
	char *sid;
	fsys fd;
	char buffer[256];

	if(msg)
		errlog(ERRLOG, "control failed; %s", msg);

	if(!replytarget)
		return;
	
	if(isdigit(*replytarget)) {
#ifndef	_MSWINDOWS_
		pid = atoi(replytarget);
		if(msg)
			kill(pid, SIGUSR2);
		else
			kill(pid, SIGUSR1);
#endif
	}
	else {
		sid = (char *)strchr(replytarget, ';');
		if(sid)
			*(sid++) = 0;

		else
			sid = (char *)"-";
		if(msg)
			snprintf(buffer, sizeof(buffer), "%s msg %s\n", sid, msg);
		else
			snprintf(buffer, sizeof(buffer), "%s ok\n", sid);
		fd.open(replytarget, fsys::ACCESS_WRONLY);
		if(is(fd)) {
			fd.write(buffer, strlen(buffer));
			fd.close();
		}
	}
	replytarget = NULL;
}

bool process::system(const char *fmt, ...)
{
	assert(fmt != NULL);

	va_list args;
	char buf[256];

	va_start(args, fmt);
	if(fmt)
		vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	debug(5, "executing %s", buf);

#ifdef	_MSWINDOWS_
#else
	int max = sizeof(fd_set) * 8;
	pid_t pid = fork();
#ifdef  RLIMIT_NOFILE
	struct rlimit rlim;

	if(!getrlimit(RLIMIT_NOFILE, &rlim))
		max = rlim.rlim_max;
#endif
	if(pid) {
		waitpid(pid, NULL, 0); 
		return true;
	}
	::signal(SIGQUIT, SIG_DFL);
	::signal(SIGINT, SIG_DFL);
	::signal(SIGCHLD, SIG_DFL);
	::signal(SIGPIPE, SIG_DFL);
	int fd = ::open("/dev/null", O_RDWR);
	dup2(fd, 0);
	dup2(fd, 2);
	dup2(fileno(fifo), 1);
	for(fd = 3; fd < max; ++fd)
		::close(fd);
	pid = fork();
	if(pid > 0)
		::exit(0);
	::execlp("/bin/sh", "sh", "-c", buf, NULL);
	::exit(127); 
#endif
	return true;
}

const char *process::identity(void)
{
	static const char *userid = NULL;

#ifdef	_MSWINDOWS_
	return "telephony";
#else
	if(!userid)
		userid = getenv("USER");
	if(userid)
		return userid;

	struct passwd *pwd = getpwuid(getuid());
	if(pwd)
		userid = strdup(pwd->pw_name);
	else 
		userid = "nobody";
	endpwent();
	return userid;
#endif
}

bool process::control(const char *uid, const char *fmt, ...)
{
	assert(uid == NULL || *uid != 0);
	assert(fmt != NULL && *fmt != 0);

	char buf[512];
	fd_t fd;
	int len;
	bool rtn = true;
	va_list args;

	va_start(args, fmt);
#ifdef	_MSWINDOWS_
	snprintf(buf, sizeof(buf), "\\\\.\\mailslot\\%s_ctrl", ident);
	fd = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(fd == INVALID_HANDLE_VALUE)
		return false;

#else
	if(!uid)
		uid = identity();

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/control", ident);
	fd = ::open(buf, O_WRONLY | O_NONBLOCK);
	if(fd < 0) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/control", ident, uid);
		fd = ::open(buf, O_WRONLY | O_NONBLOCK);
	}
	if(fd < 0)
		return false;
#endif

	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);
	len = strlen(buf);
	if(buf[len - 1] != '\n')
		buf[len++] = '\n';
#ifdef	_MSWINDOWS_
	if(!WriteFile(fd, buf, (DWORD)strlen(buf) + 1, NULL, NULL))
		rtn = false; 
	if(fd != hLoopback)
		CloseHandle(fd);
#else
	buf[len] = 0;
	if(::write(fd, buf, len) < len)
		rtn = false;
	::close(fd);
#endif
	return rtn;
}

bool process::state(const char *state)
{
	char buf[256], buf1[256];

#ifdef	_MSWINDOWS_
	return false;
#else
	snprintf(buf, sizeof(buf), DEFAULT_CFGPATH "/%s/%s.xml", ident, state);
	if(!fsys::isfile(buf))
		return false;
	snprintf(buf1, sizeof(buf1), DEFAULT_VARPATH "/run/%s/state.xml", ident);
	remove(buf1);
	if(!stricmp(state, "up") || !stricmp(state, "none"))
		return true;
#ifdef	HAVE_SYMLINK
	snprintf(buf1, sizeof(buf1), DEFAULT_VARPATH "/run/%s/state.xml", ident);
	if(symlink(buf, buf1))
		return false;
#else
	snprintf(buf1, sizeof(buf1), DEFAULT_VARPATH "/run/%s/state.xml", ident);
	if(link(buf, buf1))
		return false;
#endif
	return true;
#endif
}

FILE *process::dumpfile(const char *uid)
{
	FILE *fp;
	char buf[256];

#ifdef	_MSWINDOWS_
	GetEnvironmentVariable("APPDATA", buf, 192);
	unsigned len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\%s\\dumpfile.log", ident);	 
#else
	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/dumpfile", ident);
#endif
	fp = fopen(buf, "w");
#ifndef	_MSWINDOWS_
	if(!fp) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/dumpfile", ident, uid);
		fp = fopen(buf, "w");
	}
#endif
	return fp;
}

FILE *process::snapshot(const char *uid)
{
	FILE *fp;
	char buf[256];

#ifdef	_MSWINDOWS_
	GetEnvironmentVariable("APPDATA", buf, 192);
	unsigned len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\%s\\snapshot.log", ident);	 
#else
	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/snapshot", ident);
#endif
	fp = fopen(buf, "w");
#ifndef	_MSWINDOWS_
	if(!fp) {
		snprintf(buf, sizeof(buf), "/tmp/%s-%s/snapshot", ident, uid);
		fp = fopen(buf, "w");
	}
#endif
	return fp;
}

FILE *process::config(const char *uid)
{
	FILE *fp = NULL;
	char buf[256];

#ifdef _MSWINDOWS_
	GetEnvironmentVariable("APPDATA", buf, 192);
	unsigned len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\%s\\config.xml", ident);
	fp = fopen(buf, "r");
	if(fp) {
			process::errlog(DEBUG1, "loading config from %s", buf);
			return fp;
	}
	GetEnvironmentVariable("USERPROFILE", buf, 192);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\gnutelephony\\%s.xml", ident);
#else
	struct stat ino;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s", ident);
	if(uid && !stat(buf, &ino) && S_ISDIR(ino.st_mode)) {
		snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/%s/config.xml", ident);
		fp = fopen(buf, "r");
		if(fp) {
			process::errlog(DEBUG1, "loading config from %s", buf);
			return fp;
		}
	}

	if(uid)
		snprintf(buf, sizeof(buf), DEFAULT_CFGPATH "/%s.conf", ident);
	else
		snprintf(buf, sizeof(buf), "%s/.%src", getenv("HOME"), ident); 
#endif
	process::errlog(DEBUG1, "loading config from %s", buf);
	return fopen(buf, "r");
}

void process::util(const char *id)
{
	ident = id;
}

void process::uuid(char *buffer, size_t size, const char *node)
{
	unsigned char uuid[16];
	unsigned pos = 0, dest = 0;
	unsigned hi, lo;
	unsigned long time_low; 
	unsigned short time_mid;
	uuid_time_t time_now;
	unsigned seed = 0;

	static const char hex[] = "0123456789abcdef";
	static unsigned short seq = 0;
		
	get_system_time(&time_now);
	time_now = time_now / 1024;

	time_low = (unsigned long)(time_now & 0xffffffff);
	time_mid = (unsigned short)((time_now >> 32) & 0xffff);

	uuid[0] = time_low >> 24;
	uuid[1] = (time_low >> 16) & 0xff;
	uuid[2] = (time_low >> 8) & 0xff;
	uuid[3] = time_low > 0xff;
	uuid[4] = (time_mid >> 8) & 0xff;
	uuid[5] = time_mid & 0xff;
	uuid[6] = rand() & 0x0f;
	uuid[7] = rand();
	uuid[8] = 0x3f & (seq >> 8);
	uuid[9] = seq & 0xff;

	while(node && *node) {
		seed = (seed << 2) ^ (*node & 0x1f);
		++node;
	}

	srand(seed);

	for(unsigned entry = 10; entry < 16; ++entry)
		uuid[entry] = rand();

	++seq;

	while(pos < sizeof(uuid) && dest < (size - 3)) {
		if(pos == 4 || pos == 6 || pos == 8 || pos == 10) {
			buffer[dest++] = '-';
			if(dest >= (size - 3))
				break;
		}
		hi = uuid[pos] >> 4;
		lo = uuid[pos] & 0x0f;
		buffer[dest++] = hex[hi];
		buffer[dest++] = hex[lo];
		++pos;
	}
	buffer[dest++] = 0;
}	


