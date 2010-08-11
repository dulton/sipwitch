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
#include <sipwitch/modules.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

static const char *replytarget = NULL;

shell_t process::args;

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

size_t process::attach(void)
{
	const char *home = args.getenv("HOME");

	if(!home)
		home = get("prefix");

	set("HOME", home);

	String::set(fifopath, sizeof(fifopath), process::get("control"));
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

void process::release(void)
{
	shell::log(shell::INFO, "shutdown");
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

size_t process::attach(void)
{
	char buf[64];

	const char *home = args.getenv("HOME");

	if(!home)
		home = args.getenv("USERPROFILE");

	if(!home)
		home = get("prefix");

	set("HOME", home);

	String::set(buf, sizeof(buf), process::get("control"));
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

void process::release(void)
{
	shell::log(shell::INFO, "shutdown");

	if(hFifo != INVALID_HANDLE_VALUE) {
		CloseHandle(hFifo);
		CloseHandle(hLoopback);
		CloseHandle(hEvent);
		hFifo = hLoopback = hEvent = INVALID_HANDLE_VALUE;
	}
}

#endif

void process::printlog(const char *fmt, ...)
{
	assert(fmt != NULL && *fmt != 0);

	fsys_t log;
	va_list vargs;
	char buf[1024];
	int len;
	char *cp;

	va_start(vargs, fmt);

	fsys::create(log, process::get("logfile"), fsys::ACCESS_APPEND, 0660);
	vsnprintf(buf, sizeof(buf) - 1, fmt, vargs);
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

	shell::debug(2, "logfile: %s", buf);
	va_end(vargs);
}

void process::reply(const char *msg)
{
	assert(msg == NULL || *msg != 0);

	pid_t pid;
	char *sid;
	fsys fd;
	char buffer[256];

	if(msg)
		shell::log(shell::ERR, "control failed; %s", msg);

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

	va_list vargs;
	char buf[256];

	va_start(vargs, fmt);
	if(fmt)
		vsnprintf(buf, sizeof(buf), fmt, vargs);
	va_end(vargs);

	shell::debug(5, "executing %s", buf);

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

bool process::control(const char *fmt, ...)
{
	assert(fmt != NULL && *fmt != 0);

	char buf[512];
	fd_t fd;
	int len;
	bool rtn = true;
	va_list vargs;

	va_start(vargs, fmt);
#ifdef	_MSWINDOWS_
	fd = CreateFile(process::get("control"), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(fd == INVALID_HANDLE_VALUE)
		return false;

#else
	fd = ::open(process::get("control"), O_WRONLY | O_NONBLOCK);
	if(fd < 0)
		return false;
#endif

	vsnprintf(buf, sizeof(buf) - 1, fmt, vargs);
	va_end(vargs);
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
	String::set(buf, sizeof(buf), _STR(process::path("prefix") + "/states/" + state + ".xml"));
	if(!fsys::isfile(buf))
		return false;
	String::set(buf1, sizeof(buf1), _STR(process::path("prefix") + "state.xml"));
	remove(buf1);
	if(!stricmp(state, "up") || !stricmp(state, "none"))
		return true;

#ifdef	HAVE_SYMLINK
	if(symlink(buf, buf1))
		return false;
#else
	if(link(buf, buf1))
		return false;
#endif
	return true;
#endif
}

FILE *process::output(const char *id)
{
#ifdef	_MSWINDOWS_
	fopen(_STR(path("controls") + "/" + id + ".out"), "w");
#else
	if(replytarget && isdigit(*replytarget))
		return fopen(path("reply") + str((Unsigned)atol(replytarget)), "w");
	printf("PATH IS %s\n", _STR(path("controls") + "/" + id));
	return fopen(_STR(path("controls") + "/" + id), "w");
#endif
}

void process::uuid(char *buffer, size_t size, unsigned short seq, unsigned callid)
{
	unsigned char uuid[16];
	unsigned pos = 0, dest = 0;
	unsigned hi, lo;
	unsigned long time_low; 
	unsigned short time_mid;
	uuid_time_t time_now;

	static const char hex[] = "0123456789abcdef";
		
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

	srand(callid);

	for(unsigned entry = 10; entry < 16; ++entry)
		uuid[entry] = rand();

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


