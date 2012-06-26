// Copyright (C) 2011 David Sugar, Haakon Eriksen, GNU Free Call Foundation
//
// This file is part of SwitchView.
//
// SwitchView is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// SwitchView is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with SwitchView.  If not, see <http://www.gnu.org/licenses/>.

#include "switchview.h"
#if !defined(_MSWINDOWS_)
#include <sys/un.h>
#endif

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

#ifdef _MSWINDWS_
#define CONTROL_PATH "\\\\.\\mailslot\\sipwitch_ctrl"
#else
#define CONTROL_PATH "run/sipwitch.ctrl"
#endif

Events *dispatcher = NULL;
callmap_t *mapped_calls = NULL;
statmap_t *mapped_stats = NULL;
usermap_t *mapped_users = NULL;

static timedevent_t notify;
static bool stopped = false;
static bool started = false;
static string_t callmap = CALL_MAP;
static string_t usermap = REGISTRY_MAP;
static string_t statmap = STAT_MAP;
static string_t contact = "-";
static string_t publish = "-";

static socket_t ipc = INVALID_SOCKET;
#ifdef  _MSWINDOWS_
static struct sockaddr_in ipcaddr;
#else
static struct sockaddr_un ipcaddr;
#endif

static events *msgdup(events *msg)
{
    events *buf = new events;
    memcpy(buf, msg, sizeof(events));
    return buf;
}

static bool remap(void)
{
    Thread::yield();

    if(mapped_calls)
        delete mapped_calls;
    if(mapped_users)
        delete mapped_users;
    if(mapped_stats)
        delete mapped_stats;

    mapped_calls = new callmap_t(*callmap);
    mapped_users = new usermap_t(*usermap);
    mapped_stats = new statmap_t(*statmap);

    if(mapped_calls && mapped_users && mapped_stats)
        return true;

    return false;
}

static bool server_control(const char *cmd)
{
    fsys_t fs;
    string_t path = shell::path(shell::SYSTEM_VAR, CONTROL_PATH);

    fs.open(*path, fsys::ACCESS_WRONLY);
#if !defined(_MSWINDOWS_)
    if(!is(fs)) {
        string_t path = str("/tmp/sipwitch-") + shell::userid();
        fs.open(path, fsys::ACCESS_WRONLY);
    }
#endif
    if(!is(fs))
        return false;

    fs.write(cmd, strlen(cmd));
    fs.close();
    return true;
}

Events::Events() :
QObject(), JoinableThread()
{
    Q_ASSERT(dispatcher == NULL);
    dispatcher = this;

    connect(this, SIGNAL(serverOnlineSignal()),
        switchview, SLOT(online()), Qt::QueuedConnection);

    connect(this, SIGNAL(serverOfflineSignal()),
        switchview, SLOT(offline()), Qt::QueuedConnection);
}

Events::~Events()
{
}

void Events::start(void)
{
    new Events();
    dispatcher->JoinableThread::start();
}

void Events::stop(void)
{
    stopped = true;
    Socket::release(ipc);
    ipc = INVALID_SOCKET;
    notify.signal();
    delete dispatcher;
    dispatcher = NULL;
}

bool Events::dispatch(events *msg)
{
    struct tm *dt;
    char buf[128];

    switch(msg->type) {
    case events::WELCOME:
        started = true;
        dt = localtime(&msg->server.started);
        strftime(buf, sizeof(buf), "%c", dt);
        emit serverOnlineSignal();
        emit stateSignal(strdup(msg->server.state), strdup(buf));
        emit realmSignal(strdup(msg->server.realm));
        return true;
    case events::CONTACT:
        // only send for contact changes...
        if(!eq(contact, msg->contact)) {
            contact ^= msg->contact;
            emit configContact(contact.c_mem());
            Thread::yield();
        }
        return true;
    case events::PUBLISH:
        // only send for contact changes...
        if(!eq(publish, msg->contact)) {
            publish ^= msg->contact;
            emit configContact(publish.c_mem());
            Thread::yield();
        }
        return true;
    case events::STATE:
        emit stateSignal(strdup(msg->server.state), NULL);
        return true;
    case events::REALM:
        emit realmSignal(strdup(msg->server.realm));
        return true;
    case events::NOTICE:
    case events::WARNING:
    case events::FAILURE:
        emit notifySignal(msgdup(msg));
        return true;
    case events::TERMINATE:
        emit notifySignal(msgdup(msg));
        emit stateSignal(strdup("down"), strdup("offline"));
        return false;
    case events::CALL:
        emit callSignal(msgdup(msg));
        return true;
    case events::DROP:
        emit dropSignal(msgdup(msg));
        return true;
    case events::ACTIVATE:
        emit activateSignal(msgdup(msg));
        return true;
    case events::RELEASE:
        emit releaseSignal(msgdup(msg));
        return true;
    default:
        return true;
    }
}

void Events::run(void)
{
    timeout_t reconnect_timeout = reconnect();

    notify.reset();
    Thread::yield();

    for(;;) {
        event_t event;
        string_t path = shell::path(shell::SYSTEM_VAR, "run/sipwitch/events");

        if(ipc == INVALID_SOCKET && !stopped) {
            callmap = CALL_MAP;
            usermap = REGISTRY_MAP;
            statmap = STAT_MAP;

            memset(&ipcaddr, 0, sizeof(ipcaddr));
#ifdef  _MSWINDOWS_
            DWORD port = 0, pid = 0;
            DWORD plen;
            DWORD index = 0;
            TCHAR keyname[128];
            TCHAR keyvalue[128];
            DWORD size = sizeof(keyname), vsize = sizeof(keyvalue), vtype;
            DWORD *dp;

            plen = sizeof(port);
            HKEY keys = HKEY_LOCAL_MACHINE, subkey;
            if(RegOpenKeyEx(keys, "SOFTWARE\\sipwitch", 0, KEY_READ, &subkey) != ERROR_SUCCESS)
                goto drop;
            while((RegEnumValue(subkey, index++, keyname, &size, NULL, &vtype, (BYTE *)keyvalue, &vsize) == ERROR_SUCCESS) && (vtype == REG_DWORD) && (keyname[0] != 0)) {
                dp = (DWORD *)&keyvalue;
                if(eq("port", keyname))
                    port = *dp;
                else if(eq("pid", keyname))
                    pid = *dp;
                vsize = sizeof(keyvalue);
                size = sizeof(keyname);
            }
            RegCloseKey(subkey);
            if(!port)
                goto drop;

            ipc = ::socket(AF_INET, SOCK_STREAM, 0);
            ipcaddr.sin_family = AF_INET;
            ipcaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
            ipcaddr.sin_port = htons((unsigned short)port);
            if(::connect(ipc, (struct sockaddr *)&ipcaddr, sizeof(ipcaddr)) < 0)
                goto drop;
#else
            ipc = ::socket(AF_UNIX, SOCK_STREAM, 0);

            memset(&ipcaddr, 0, sizeof(ipcaddr));
            ipcaddr.sun_family = AF_UNIX;
            String::set(ipcaddr.sun_path, sizeof(ipcaddr.sun_path), *path);
            if(::connect(ipc, (struct sockaddr *)&ipcaddr, SUN_LEN(&ipcaddr)) < 0) {
                memset(&ipcaddr, 0, sizeof(ipcaddr));
                ipcaddr.sun_family = AF_UNIX;
                callmap = str(CALL_MAP "-") + shell::userid();
                statmap = str(STAT_MAP "-") + shell::userid();
                usermap = str(REGISTRY_MAP "-") + shell::userid();
                string_t path = str("/tmp/sipwitch-") + shell::userid() + str("/events");
                String::set(ipcaddr.sun_path, sizeof(ipcaddr.sun_path), *path);
                if(::connect(ipc, (struct sockaddr *)&ipcaddr, SUN_LEN(&ipcaddr)) < 0)
                    goto drop;
            }
#endif
        }

        if(ipc == INVALID_SOCKET)
            goto drop;

        if(!remap())
            goto drop;

        while(::recv(ipc, (char *)&event, sizeof(event), 0) == sizeof(event)) {
            if(!dispatch(&event))
                break;
        }

drop:
        if(ipc != INVALID_SOCKET)
            Socket::release(ipc);

        ipc = INVALID_SOCKET;

        if(stopped)
            return;

        if(started) {
            emit stateSignal(strdup("down"), strdup("offline"));
            emit serverOfflineSignal();
        }

        timeout_t timeout = reconnect_timeout;

        if(!timeout)
            timeout = 60000;

        while((notify.wait(timeout) == false) && !reconnect_timeout)
            ;
    }
}

bool Events::reconnect(void)
{
    if(!dispatcher)
        return false;

    if(ipc == INVALID_SOCKET)
        return false;

    notify.signal();
    return true;
}

void Events::reload(void)
{
    server_control("reload\n");
}

void Events::changeRealm(void)
{
    char buf[256];

    snprintf(buf, sizeof(buf), "realm %s\n", mapped->realm());
    server_control(buf);
}

void Events::changeState(void)
{
    char buf[256];

    snprintf(buf, sizeof(buf), "state %s\n", mapped->realm());
    server_control(buf);
}

bool Events::isAdmin(void)
{
    string_t path = shell::path(shell::SYSTEM_VAR, CONTROL_PATH);

    if(fsys::access(*path, W_OK) == 0)
        return true;

    return false;
}


