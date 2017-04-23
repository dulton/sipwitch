// Copyright (C) 2010-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015-2017 Cherokees of Idaho.
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

#ifdef  HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#include <sys/poll.h>
#endif

namespace sipwitch {

#ifdef HAVE_SIGWAIT

psignals psignals::thread;

psignals::psignals() :
JoinableThread()
{
    shutdown = started = false;
}

psignals::~psignals()
{
    if(!shutdown)
        cancel();
}

void psignals::cancel(void)
{
    if(started) {
        shutdown = true;
#ifdef  __FreeBSD__
        raise(SIGINT);
#endif
        pthread_kill(tid, SIGALRM);
        join();
    }
}

void psignals::run(void)
{
    int signo;
    unsigned period = 900;

    started = true;
    shell::log(DEBUG1, "starting signal handler");

    for(;;) {
        alarm(period);
#ifdef  HAVE_SIGWAIT2
        int result = sigwait(&sigs, &signo);
        if(result) {
            alarm(0);
            shell::log(shell::ERR, "signal handler error %d", errno);
            Thread::sleep(1000);
            continue;
        }
#else
        signo = sigwait(&sigs);
        if(signo < 0) {
            alarm(0);
            shell::log(shell::ERR, "signal handler error %d", errno);
            Thread:sleep(1000);
            continue;
        }
#endif
        alarm(0);
        if(shutdown)
            break;

        shell::log(DEBUG1, "received signal %d", signo);

        switch(signo) {
        case SIGALRM:
            shell::log(shell::INFO, "system housekeeping");
            // registry::cleanup(period);
            events::sync(period);
            cache::cleanup();
            break;
        case SIGINT:
        case SIGTERM:
            control::send("down");
            break;
        case SIGUSR1:
            control::send("snapshot");
            break;
        case SIGHUP:
            control::send("reload");
            break;
        default:
            break;
        }
    }
    shell::log(DEBUG1, "stopping signal handler");
}

void psignals::service(const char *name)
{
}

void psignals::setup(void)
{
    sigemptyset(&thread.sigs);
    sigaddset(&thread.sigs, SIGALRM);
    sigaddset(&thread.sigs, SIGHUP);
    sigaddset(&thread.sigs, SIGINT);
    sigaddset(&thread.sigs, SIGTERM);
    sigaddset(&thread.sigs, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &thread.sigs, NULL);

    signal(SIGPIPE, SIG_IGN);
}

void psignals::start(void)
{
    thread.background();
}

void psignals::stop(void)
{
    thread.cancel();
}

#elif defined(WIN32)

static SERVICE_STATUS_HANDLE hStatus = 0;
static SERVICE_STATUS status;

static void WINAPI handler(DWORD sigint)
{
    switch(sigint) {
    case 128:
        // control::request("reload");
        return;
    case 129:
        // control::request("snapshot");
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
        status.dwCurrentState = SERVICE_STOP_PENDING;
        status.dwWin32ExitCode = 0;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 6000;
        SetServiceStatus(hStatus, &status);
        // control::request("down");
        break;
    default:
        break;
    }
}

void psignals::service(const char *name)
{
    memset(&status, 0, sizeof(SERVICE_STATUS));
    status.dwServiceType = SERVICE_WIN32;
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
    hStatus = ::RegisterServiceCtrlHandler(name, &handler);
}

void psignals::setup(void)
{
}

void psignals::start(void)
{
    if(!hStatus)
        return;

    status.dwCurrentState = SERVICE_RUNNING;
    ::SetServiceStatus(hStatus, &status);
}

void psignals::stop(void)
{
    if(!hStatus)
        return;

    status.dwCurrentState = SERVICE_STOPPED;
    ::SetServiceStatus(hStatus, &status);
}

#else

void psignals::service(const char *name)
{
}

void psignals::setup(void)
{
}

void psignals::start(void)
{
}

void psignals::stop(void)
{
}

#endif

#ifdef  HAVE_SYS_INOTIFY_H

static const char *dirpath = NULL;
static const char *cachepath = NULL;
static fd_t watcher = -1;
static uint32_t dirnode;
static uint32_t cachenode;

notify notify::thread;

notify::notify() : JoinableThread()
{
}

notify::~notify()
{
    notify::stop();
}

void notify::start(void)
{
    dirpath = control::env("users");
    cachepath = control::env("cache");

    if(!dirpath)
        dirpath = control::env("prefix");

    if(fsys::is_dir(dirpath))
        thread.background();
    else
        shell::log(shell::ERR, "notify failed; %s missing", dirpath);
}

void notify::run(void)
{
    static bool logged = false;
    timeout_t timeout = -1;
    unsigned updates = 0;
    struct pollfd pfd;

    shell::log(DEBUG1, "notify watching %s", dirpath);

    watcher = inotify_init();
    dirnode = inotify_add_watch(watcher, dirpath, IN_CLOSE_WRITE|IN_MOVED_TO|IN_MOVED_FROM|IN_DELETE|IN_DONT_FOLLOW);
    if(cachepath) {
        cachenode = inotify_add_watch(watcher, cachepath, IN_CLOSE_WRITE|IN_MOVED_TO|IN_MOVED_FROM|IN_DELETE|IN_DONT_FOLLOW);
        shell::log(DEBUG1, "notify watching cache %s", cachepath);
    }

    while(watcher != -1) {
        // we want 500 ms of inactivity before actual updating...
        if(updates)
            timeout = 500;
        else
            timeout = 1000;

        pfd.fd = watcher;
        pfd.events = POLLIN | POLLNVAL | POLLERR;
        pfd.revents = 0;
        int result = poll(&pfd, 1, timeout);
        // if error, we sleep....we should also not get errors...
        if(result < 0) {
            if(!logged) {
                shell::log(shell::ERR, "notify error %d", errno);
                logged = true;
            }
            // throttle on repeated errors...
            Thread::sleep(1000);
            continue;
        }
        if(!result) {
            if(!updates)
                continue;

            // clear updates and process config on timeout
            control::send("reload");
            updates = 0;
            continue;
        }
        if(pfd.revents & (POLLNVAL|POLLERR))
            break;

        if(pfd.revents & POLLIN) {
            char buffer[512];
            size_t offset = 0;

            size_t len = ::read(watcher, &buffer, sizeof(buffer));
            if(len < sizeof(struct inotify_event)) {
                shell::log(shell::ERR, "notify failed to read inotify");
                continue;
            }

            while(offset < len) {
                struct inotify_event *event = (struct inotify_event *)&buffer[offset];
                if(!event->len)
                    break;

                // only if xml files updated do we care...
                const char *ext = strrchr(event->name, '.');
                if(ext && eq_case(ext, ".xml")) {
                    shell::log(DEBUG2, "%s updated", event->name);
                    ++updates;
                }
                offset += sizeof(struct inotify_event) + event->len;
            }
        }
    }

    shell::log(DEBUG1, "notify terminating");
}

void notify::stop(void)
{
    if(watcher != -1) {
        fd_t fd = watcher;
        watcher = -1;
        ::close(fd);
        thread.join();
    }
}

#else

void notify::start(void)
{
}

void notify::stop(void)
{
}

#endif

} // end namespace

