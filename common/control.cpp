// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015 Cherokees of Idaho.
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

#include <sipwitch-config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/control.h>
#include <sipwitch/service.h>
#include <sipwitch/modules.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

namespace sipwitch {

static const char *replytarget = NULL;

shell_t *control::args = NULL;

#ifndef _MSWINDOWS_

#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>

static FILE *fifo = NULL;
static char fifopath[128] = "";

static void cleanup(void)
{
    if(fifopath[0]) {
        ::remove(fifopath);
        char *cp = strrchr(fifopath, '/');
        String::set(cp, 10, "/pidfile");
        ::remove(fifopath);
        fifopath[0] = 0;
    }
}

size_t control::attach(shell_t *envp)
{
    args = envp;

    String::set(fifopath, sizeof(fifopath), env("control"));
    remove(fifopath);
    if(mkfifo(fifopath, fsys::GROUP_PRIVATE)) {
        fifopath[0] = 0;
        return 0;
    }
    else
        shell::exiting(&cleanup);

    fifo = fopen(fifopath, "r+");
    if(fifo)
        return 512;
    fifopath[0] = 0;
    return 0;
}

void control::release(void)
{
    shell::log(shell::INFO, "shutdown");
    cleanup();
}

char *control::receive(void)
{
    static char buf[512];
    char *cp;

    if(!fifo)
        return NULL;

    reply(NULL);

retry:
    buf[0] = 0;
    if(fgets(buf, sizeof(buf), fifo) == NULL) {
        buf[0] = 0;
        Thread::sleep(100); // throttle if dead...
    }
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

static void cleanup(void)
{
    if(hFifo != INVALID_HANDLE_VALUE) {
        CloseHandle(hFifo);
        CloseHandle(hLoopback);
        CloseHandle(hEvent);
        hFifo = hLoopback = hEvent = INVALID_HANDLE_VALUE;
    }
}

size_t control::attach(shell_t *envp)
{
    char buf[64];

    args = envp;

    String::set(buf, sizeof(buf), env("control"));
    hFifo = CreateMailslot(buf, 0, MAILSLOT_WAIT_FOREVER, NULL);
    if(hFifo == INVALID_HANDLE_VALUE)
        return 0;

    hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    hLoopback = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ovFifo.Offset = 0;
    ovFifo.OffsetHigh = 0;
    ovFifo.hEvent = hEvent;
    shell::exiting(&cleanup);
    return 464;
}

char *control::receive(void)
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

void control::release(void)
{
    shell::log(shell::INFO, "shutdown");
    cleanup();
}

#endif

void control::reply(const char *msg)
{
    assert(msg == NULL || *msg != 0);

    char *sid;
    fsys fd;
    char buffer[256];

    if(msg)
        shell::log(shell::ERR, "control failed; %s", msg);

    if(!replytarget)
        return;

    if(isdigit(*replytarget)) {
#ifndef _MSWINDOWS_
        pid_t pid = atoi(replytarget);
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
        fd.open(replytarget, fsys::WRONLY);
        if(is(fd)) {
            fd.write(buffer, strlen(buffer));
            fd.close();
        }
    }
    replytarget = NULL;
}

bool control::libexec(const char *fmt, ...)
{
    assert(fmt != NULL);

    va_list vargs;
    char buf[256];

    va_start(vargs, fmt);
    if(fmt)
        vsnprintf(buf, sizeof(buf), fmt, vargs);
    va_end(vargs);

    shell::debug(5, "executing %s", buf);

#ifdef  _MSWINDOWS_
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
    ::signal(SIGABRT, SIG_DFL);
    ::signal(SIGQUIT, SIG_DFL);
    ::signal(SIGINT, SIG_DFL);
    ::signal(SIGCHLD, SIG_DFL);
    ::signal(SIGPIPE, SIG_DFL);
    int fd = open("/dev/null", O_RDWR);
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

bool control::send(const char *fmt, ...)
{
    assert(fmt != NULL && *fmt != 0);

    char buf[512];
    fd_t fd;
    int len;
    bool rtn = true;
    va_list vargs;

    va_start(vargs, fmt);
#ifdef  _MSWINDOWS_
    fd = CreateFile(env("control"), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fd == INVALID_HANDLE_VALUE) {
        va_end(vargs);
        return false;
    }

#else
    fd = open(env("control"), O_WRONLY | O_NONBLOCK);
    if(fd < 0) {
        va_end(vargs);
        return false;
    }
#endif

    vsnprintf(buf, sizeof(buf) - 1, fmt, vargs);
    va_end(vargs);
    len = strlen(buf);
    if(buf[len - 1] != '\n')
        buf[len++] = '\n';
#ifdef  _MSWINDOWS_
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

bool control::state(const char *state)
{
#ifdef  _MSWINDOWS_
    return false;
#else
    char buf[256], buf1[256];

    String::set(buf, sizeof(buf), _STR(path("prefix") + "/states/" + state + ".xml"));
    if(!fsys::is_file(buf))
        return false;
    String::set(buf1, sizeof(buf1), _STR(path("prefix") + "state.xml"));
    remove(buf1);
    if(!stricmp(state, "up") || !stricmp(state, "none"))
        return true;

#ifdef  HAVE_SYMLINK
    if(symlink(buf, buf1))
        return false;
#else
    if(link(buf, buf1))
        return false;
#endif
    return true;
#endif
}

FILE *control::output(const char *id)
{
#ifdef  _MSWINDOWS_
    if(!id)
        return NULL;

    return fopen(_STR(path("controls") + "/" + id + ".out"), "w");
#else
    if(replytarget && isdigit(*replytarget))
        return fopen(path("reply") + str((Unsigned)atol(replytarget)), "w");
    if(!id)
        return NULL;
    return fopen(_STR(path("controls") + "/" + id), "w");
#endif
}

} // namespace sipwitch
