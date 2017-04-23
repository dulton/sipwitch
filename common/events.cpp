// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
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

#include <sipwitch-config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/events.h>
#include <sipwitch/control.h>
#include <sipwitch/mapped.h>
#include <sipwitch/service.h>

#if !defined(_MSWINDOWS_)
#include <sys/un.h>
#endif

#ifndef _MSWINDOWS_
#include <pwd.h>
#include <fcntl.h>
#endif

namespace sipwitch {

static mutex_t private_locking;
static bool shutdown_flag = false;
#ifdef  _MSWINDOWS_
static struct sockaddr_in ipc_addr;
#else
static struct sockaddr_un ipc_addr;
#endif
static socket_t ipc_socket = INVALID_SOCKET;

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
static string_t saved_state("up"), saved_realm("unknown");
static time_t started;

static class __LOCAL event_thread : public JoinableThread
{
private:
    void run(void);

public:
    event_thread();

} _thread_;

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
            ::send(dp->session, (const char *)msg, sizeof(events), 0);
        ::close(dp->session);
        dp.next();
    }
    freelist = NULL;
    root = NULL;
    private_locking.release();
}

void dispatch::send(events *msg)
{
    fd_set detect;
    struct timeval timeout;
    if(ipc_socket == INVALID_SOCKET)
        return;

    private_locking.acquire();
    linked_pointer<dispatch> dp = root;
    LinkedObject *next;
    while(is(dp)) {
        next = dp->Next;
        if(::send(dp->session, (const char *)msg, sizeof(events), 0) < (ssize_t)sizeof(events)) {
disconnect:
            shell::log(DEBUG3, "releasing client events for %ld", (long)dp->session);
            dp->release();
            dp->Next = freelist;
            freelist = *dp;
        }
        // disconnect detection...
        memset(&timeout, 0, sizeof(timeout));
        memset(&detect, 0, sizeof(detect));
        FD_SET(dp->session, &detect);
        if(select(dp->session + 1, &detect, NULL, &detect, &timeout) > 0)
            goto disconnect;
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
    events evt;

    time(&started);

    shell::log(DEBUG1, "starting event dispatcher");
    shutdown_flag = false;

    for(;;) {
        // when shutdown closes ipc, we exit the thread...
        client = ::accept(ipc_socket, NULL, NULL);
        if(shutdown_flag) {
            if(ipc_socket != INVALID_SOCKET) {
                Socket::release(ipc_socket);
                ipc_socket = INVALID_SOCKET;
            }
            break;
        }
        if(client < 0) {
            shell::log(shell::ERR, "event accept failed; error=%ld", (long)client);
            continue;
        }

        events::sync();
        shell::log(DEBUG3, "connecting client events for %ld", (long)client);

        evt.type = events::WELCOME;
        evt.msg.server.started = started;
        String::set(evt.msg.server.version, sizeof(evt.msg.server.version), VERSION);
        private_locking.acquire();
        String::set(evt.msg.server.state, sizeof(evt.msg.server.state), *saved_state);
        String::set(evt.msg.server.realm, sizeof(evt.msg.server.realm), *saved_realm);
        private_locking.release();
        ::send(client, (const char *)&evt, sizeof(evt), 0);

        String::set(evt.msg.contact, sizeof(evt.msg.contact), *service::getContact());
        evt.type = events::CONTACT;
        ::send(client, (const char *)&evt, sizeof(evt), 0);

        dispatch::add(client);
    }

    shell::log(DEBUG1, "stopping event dispatcher");
}

bool events::start(void)
{
    if(ipc_socket != INVALID_SOCKET)
        return false;

#ifdef  _MSWINDOWS_
    ipc_socket = ::socket(AF_INET, SOCK_STREAM, 0);
#else
    ipc_socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
#endif

    if(ipc_socket == INVALID_SOCKET)
        return false;

    memset(&ipc_addr, 0, sizeof(ipc_addr));
#ifdef  _MSWINDOWS_
    DWORD port;
    HKEY keys, subkey;
    socklen_t alen;

    ipc_addr.sin_family = AF_INET;
    ipc_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    ipc_addr.sin_port = 0;
    if(::bind(ipc_socket, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr)) < 0)
        goto failed;

    alen = sizeof(ipc_addr);
    ::getsockname(ipc_socket, (struct sockaddr *)&ipc_addr, &alen);
    port = ntohs(ipc_addr.sin_port);
    keys = HKEY_LOCAL_MACHINE;
    if(RegCreateKeyEx(keys, "SOFTWARE\\sipwitch", 0L, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &subkey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(subkey, "port", 0L, REG_DWORD, (const BYTE *)&port, sizeof(port));
        port = GetCurrentProcessId();
        RegSetValueEx(subkey, "pid", 0L, REG_DWORD, (const BYTE *)&port, sizeof(port));
        RegCloseKey(subkey);
    }
#else
    ipc_addr.sun_family = AF_UNIX;
    String::set(ipc_addr.sun_path, sizeof(ipc_addr.sun_path), control::env("events"));

    ::remove(control::env("events"));
    if(::bind(ipc_socket, (struct sockaddr *)&ipc_addr, SUN_LEN(&ipc_addr)) < 0)
        goto failed;
#endif

    if(::listen(ipc_socket, 10) < 0)
        goto failed;

    _thread_.start();
    return true;

failed:
    Socket::release(ipc_socket);
    ipc_socket = INVALID_SOCKET;
    return false;
}

void events::connect(cdr *rec)
{
    events evt;
    evt.type = CALL;
    evt.msg.call.started = rec->starting;
    String::set(evt.msg.call.reason, sizeof(evt.msg.call.reason), rec->reason);
    String::set(evt.msg.call.network, sizeof(evt.msg.call.network), rec->network);
    String::set(evt.msg.call.caller, sizeof(evt.msg.call.caller), rec->ident);
    String::set(evt.msg.call.dialed, sizeof(evt.msg.call.dialed), rec->dialed);
    String::set(evt.msg.call.display, sizeof(evt.msg.call.display), rec->display);
    dispatch::send(&evt);
}

void events::drop(cdr *rec)
{
    events evt;
    evt.type = DROP;
    String::set(evt.msg.call.caller, sizeof(evt.msg.call.caller), rec->ident);
    String::set(evt.msg.call.dialed, sizeof(evt.msg.call.dialed), rec->dialed);
    String::set(evt.msg.call.display, sizeof(evt.msg.call.display), rec->display);
    dispatch::send(&evt);

}

void events::activate(MappedRegistry *rr)
{
    events evt;

    evt.type = ACTIVATE;
    String::set(evt.msg.user.id, sizeof(evt.msg.user.id), rr->userid);
    evt.msg.user.extension  = rr->ext;
    dispatch::send(&evt);
}

void events::release(MappedRegistry *rr)
{
    events evt;

    evt.type = RELEASE;
    String::set(evt.msg.user.id, sizeof(evt.msg.user.id), rr->userid);
    evt.msg.user.extension  = rr->ext;
    dispatch::send(&evt);
}

void events::realm(const char *str)
{
    events evt;

    private_locking.acquire();
    saved_realm = str;
    private_locking.release();
    evt.type = REALM;
    String::set(evt.msg.server.realm, sizeof(evt.msg.server.realm), str);
    dispatch::send(&evt);
}

void events::state(const char *str)
{
    events evt;

    private_locking.acquire();
    saved_state = str;
    private_locking.release();
    evt.type = STATE;
    String::set(evt.msg.server.state, sizeof(evt.msg.server.state), str);
    dispatch::send(&evt);
}

void events::sync(unsigned sync_period)
{
    events evt;
    evt.type = SYNC;
    evt.msg.period = sync_period;
    dispatch::send(&evt);
}

void events::notice(const char *reason)
{
    events evt;

    evt.type = NOTICE;
    String::set(evt.msg.reason, sizeof(evt.msg.reason), reason);
    dispatch::send(&evt);
}

void events::warning(const char *reason)
{
    events evt;

    evt.type = WARNING;
    String::set(evt.msg.reason, sizeof(evt.msg.reason), reason);
    dispatch::send(&evt);
}

void events::failure(const char *reason)
{
    events evt;

    evt.type = FAILURE;
    String::set(evt.msg.reason, sizeof(evt.msg.reason), reason);
    dispatch::send(&evt);
}

void events::reload(void)
{
    events evt;

    evt.type = CONTACT;
    String::set(evt.msg.contact, sizeof(evt.msg.contact), *service::getContact());
    dispatch::send(&evt);

    evt.type = PUBLISH;
    volatile char *addr = service::callback::sip_publish;
    if(addr) {
        string_t uri = str("sip:") + (const char *)addr;
        String::set(evt.msg.contact, sizeof(evt.msg.contact), *uri);
        dispatch::send(&evt);
    }
}

void events::publish(const char *addr)
{
    events evt;

    evt.type = PUBLISH;
    string_t uri = str("sip:") + addr;
    String::set(evt.msg.contact, sizeof(evt.msg.contact), *uri);
    dispatch::send(&evt);
}

void events::terminate(const char *reason)
{
    events evt;

    if(shutdown_flag || ipc_socket == INVALID_SOCKET)
        return;

    shutdown_flag = true;
    evt.type = TERMINATE;
    String::set(evt.msg.reason, sizeof(evt.msg.reason), reason);

    dispatch::stop(&evt);
    socket_t tmp;
#ifdef  _MSWINDOWS_
    tmp = ::socket(AF_INET, SOCK_STREAM, 0);
    ::connect(tmp, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr));
#else
    tmp = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ::connect(tmp, (struct sockaddr *)&ipc_addr, SUN_LEN(&ipc_addr));
#endif
    Socket::release(tmp);

    ::remove(control::env("events"));
    //ipc_socket = INVALID_SOCKET;
}

} // end namespace
