// Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
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
#include <sipwitch/events.h>
#include <sipwitch/process.h>

#ifdef  AF_UNIX
#include <sys/un.h>
#endif

#ifndef _MSWINDOWS_
#include <pwd.h>
#include <fcntl.h>
#endif

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

#ifdef  AF_UNIX

static mutex_t private_locking;

class __LOCAL dispatch : public LinkedObject
{
public:
    socket_t session;

    dispatch();

    void assign(socket_t so);
    void release(void);

    static void add(socket_t so);
    static void stop(events *message);
    static void send(events *message);
};

static LinkedObject *root = NULL;
static dispatch *freelist = NULL;

static class __LOCAL event_thread : public JoinableThread
{
private:
    void run(void);

public:
    event_thread();

} _thread_;

static socket_t ipc = INVALID_SOCKET;

dispatch::dispatch() : LinkedObject()
{
}

void dispatch::assign(socket_t so)
{
    enlist(&root);
    session = so;
}

void dispatch::release(void)
{
    ::close(session);
    delist(&root);
}

void dispatch::add(socket_t so)
{
    dispatch *node;

    private_locking.acquire();
    if(freelist) {
        node = freelist;
        freelist = (dispatch *)node->getNext();
    }
    else
        node = new dispatch;
    node->assign(so);
    private_locking.release();
}

void dispatch::stop(events *msg)
{
    private_locking.acquire();
    linked_pointer<dispatch> dp = root;

    while(is(dp)) {
        if(msg)
            ::send(dp->session, msg, sizeof(events), 0);
        ::close(dp->session);
        dp.next();
    }
    freelist = NULL;
    root = NULL;
    private_locking.release();
}

void dispatch::send(events *msg)
{
    private_locking.acquire();
    linked_pointer<dispatch> dp = root;
    LinkedObject *next;
    while(is(dp)) {
        next = dp->next;
        if(::send(dp->session, msg, sizeof(events), 0) < sizeof(events)) {
            shell::log(DEBUG3, "releasing client events for %d", dp->session);
            dp->release();
            dp->next = freelist;
            freelist = *dp;
        }
        dp = next;
    }
    private_locking.release();
}

event_thread::event_thread() : JoinableThread()
{
}

void event_thread::run(void)
{
    socket_t client;

    shell::log(DEBUG1, "starting event dispatcher");

    for(;;) {
        // when shutdown closes ipc, we exit the thread...
        client = ::accept(ipc, NULL, NULL);
        if(client < 0)
            break;

        ::shutdown(client, SHUT_RD);
        shell::log(DEBUG3, "connecting client events for %d", client);
        dispatch::add(client);
    }

    shell::log(DEBUG1, "stopping event dispatcher");
}

bool events::start(void)
{
    struct sockaddr_un abuf;

    if(ipc != INVALID_SOCKET)
        return false;

    ipc = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if(ipc == INVALID_SOCKET)
        return false;

    memset(&abuf, 0, sizeof(abuf));
    abuf.sun_family = AF_UNIX;
    String::set(abuf.sun_path, sizeof(abuf.sun_path), process::get("events"));

    ::remove(process::get("events"));
    if(::bind(ipc, (struct sockaddr *)&abuf, SUN_LEN(&abuf)) < 0) {
failed:
        Socket::release(ipc);
        return false;
    }

    if(::listen(ipc, 10) < 0)
        goto failed;

    _thread_.start();
    return true;
}

void events::stop(const char *reason)
{
    events msg;

    if(ipc == INVALID_SOCKET)
        return;

    msg.type = TERMINATE;
    String::set(msg.reason, sizeof(msg.reason), reason);

    Socket::release(ipc);
    dispatch::stop(&msg);
    ::remove(process::get("events"));
    ipc = INVALID_SOCKET;
}

#else

bool events::start(void)
{
    return false;
}

void events::stop(const char *reason)
{
}

#endif
