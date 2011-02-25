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

static class __LOCAL event_thread : public JoinableThread
{
private:
    void run(void);

public:
    event_thread();

} _thread_;

static socket_t ipc = INVALID_SOCKET;

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

        // later enlist client queue
        Socket::release(client);
    }

    shell::log(DEBUG1, "stopping event dispatcher");
}

bool events::startup(void)
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

void events::shutdown(void)
{
    if(ipc == INVALID_SOCKET)
        return;

    Socket::release(ipc);
    ::remove(process::get("events"));
    ipc = INVALID_SOCKET;
}

#else

bool events::startup(void)
{
    return false;
}

void events::shutdown(void)
{
}

#endif
