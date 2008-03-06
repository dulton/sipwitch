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

#include <config.h>
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

#ifndef	_MSWINDOWS_

#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <limits.h>

static FILE *fifo = NULL;
static char fifopath[128] = "";

size_t process::attach(const char *uid)
{
	assert(uid != NULL && *uid != 0);

	struct stat ino;

	snprintf(fifopath, sizeof(fifopath), DEFAULT_VARPATH "/run/sipwitch");
	if(!stat(fifopath, &ino) && S_ISDIR(ino.st_mode) && !access(fifopath, W_OK)) 
		snprintf(fifopath, sizeof(fifopath), DEFAULT_VARPATH "/run/sipwitch/control");
	else
		snprintf(fifopath, sizeof(fifopath), "/tmp/sipwitch-%s/control", uid);

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

static void logfile(fsys_t &fs, const char *uid)
{
	assert(uid != NULL && *uid != 0);
	char buf[128];
	fd_t fd;

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/log/sipwitch.log");
	fsys::create(fs, buf, fsys::ACCESS_APPEND, 0660);
	if(is(fs))
		return;

	snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s/logfile", uid);
	fsys::create(fs, buf, fsys::ACCESS_APPEND, 0660); 
}

void process::release(void)
{
	errlog(INFO, "shutdown");
	if(fifopath[0]) {
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
	fgets(buf, sizeof(buf), fifo);
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
		service::publish(NULL, "- errlog %d %s", loglevel, buf); 
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

static void logfile(fsys_t& fd, const char *uid)
{
	assert(uid != NULL && *uid != 0);

	char buf[256];
	fd_t fd;
	unsigned len;

	GetEnvironmentVariable("APPDATA", buf, 192);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\sipwitch\\service.log");
	
	fsys::create(fd, buf, fsys::ACCESS_APPEND, 0660);
}

size_t process::attach(const char *uid)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "\\\\.\\mailslot\\sipwitch_ctrl");
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
		service::publish(NULL, "- errlog %d %s", loglevel, buf); 
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
	const char *uid;
	va_list args;
	char buf[1024];
	int len;
	service::keynode *env = service::getEnviron();
	char *cp;

	va_start(args, fmt);

	uid = service::getValue(env, "USER");
	logfile(log, uid);
	service::release(env);

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

	service::publish(NULL, "- logfile %s", buf); 

	debug(2, "logfile: %s", buf);
	va_end(args);
}

void process::reply(const char *msg)
{
	assert(msg == NULL || *msg != 0);

	pid_t pid;
	char *sid;

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
		if(msg)
			service::publish(replytarget, "%s msg %s", sid, msg);
		else
			service::publish(replytarget, "%s ok", sid);
	}
	replytarget = NULL;
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
	service::keynode *env = service::getEnviron();

	va_start(args, fmt);
#ifdef	_MSWINDOWS_
	snprintf(buf, sizeof(buf), "\\\\.\\mailslot\\sipwitch_ctrl");
	fd = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	service::release(env);
	if(fd == INVALID_HANDLE_VALUE)
		return false;

#else
	if(!uid)
		uid = service::getValue(env, "USER");

	snprintf(buf, sizeof(buf), DEFAULT_VARPATH "/run/sipwitch/control");
	fd = ::open(buf, O_WRONLY | O_NONBLOCK);
	if(fd < 0) {
		snprintf(buf, sizeof(buf), "/tmp/sipwitch-%s/control", uid);
		fd = ::open(buf, O_WRONLY | O_NONBLOCK);
	}
	service::release(env);
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
	if(::write(fd, buf, len) < len)
		rtn = false;
	::close(fd);
#endif
	return rtn;
}

