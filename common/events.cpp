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

static socket_t ipc = INVALID_SOCKET;

static struct sockaddr_un *addr(const char *path)
{
    static struct sockaddr_un abuf;
    memset(&abuf, 0, sizeof(abuf));
    abuf.sun_family = AF_UNIX;
    String::set(abuf.sun_path, sizeof(abuf.sun_path), path);
    return &abuf;
}

bool events::create(service_t service)
{
    struct sockaddr_un *ap;

    if(ipc != INVALID_SOCKET)
        return false;

    ipc = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if(ipc == INVALID_SOCKET)
        return false;

    switch(service) {
    case CLIENT:
        ap = addr(DEFAULT_VARPATH "/run/sipwitch/events");

        if(::connect(ipc, (struct sockaddr *)ap, SUN_LEN(ap)) >= 0)
            return true;

        char buffer[256];
        struct passwd *pwd = getpwuid(getuid());

        if(!pwd)
            return false;

        snprintf(buffer, sizeof(buffer), "/tmp/sipwitch-%s/events", pwd->pw_name);
        ap = addr(buffer);
        if(::connect(ipc, (struct sockaddr *)ap, SUN_LEN(ap)) > 0)
            return true;

        Socket::release(ipc);
        ipc = -1;
        return false;
    };
}

#else

bool events::create(service_t service)
{
    return false;
}

#endif

bool events::control(char **argv)
{
    char buffer[512];
    size_t len;
    fd_t fd;

#ifdef  _MSWINDOWS_
    snprintf(buffer, sizeof(buffer), "\\\\.\\mailslot\\sipwitch_ctrl");
    fd = CreateFile(buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
    fd = ::open(DEFAULT_VARPATH "/run/sipwitch/control", O_WRONLY | O_NONBLOCK);
    if(fd < 0) {
        struct passwd *pwd = getpwuid(getuid());
        if(!pwd)
            return false;

        snprintf(buffer, sizeof(buffer), "/tmp/sipwitch-%s/control", pwd->pw_name);
        fd = ::open(buffer, O_WRONLY | O_NONBLOCK);
    }
#endif

    if(fd == INVALID_HANDLE_VALUE)
        return false;

    buffer[0] = 0;

    while(*argv) {
        len = strlen(buffer);
        snprintf(buffer + len, sizeof(buffer) - len - 1, " %s", *(argv++));
    }

#ifdef  _MSWINDOWS_
    if(!WriteFile(fd, buffer, (DWORD)strlen(buffer) + 1, NULL, NULL))
        return false;
#else
    len = strlen(buffer);
    buffer[len++] = '\n';
    buffer[len] = 0;

    if(::write(fd, buffer, len) < (int)len)
        return false;

#endif
    return true;
}


