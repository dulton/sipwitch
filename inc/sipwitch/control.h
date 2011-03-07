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

/**
 * Manage control interface.
 * This manages code for the server control interface.  Access to the
 * control interface is shared between the server and plugins.
 * @file sipwitch/control.h
 */

#ifndef _SIPWITCH_CONTROL_H_
#define _SIPWITCH_CONTROL_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef _UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef _UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef _SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define DEBUG1  shell::DEBUG0
#define DEBUG2  (shell::loglevel_t(((unsigned)shell::DEBUG0 + 1)))
#define DEBUG3  (shell::loglevel_t(((unsigned)shell::DEBUG0 + 2)))

class __EXPORT control
{
private:
    static shell_t *args;

public:
    static bool send(const char *fmt, ...) __PRINTF(1, 2);
    static void result(const char *value);
    static char *receive(void);
    static void reply(const char *err = NULL);
    static size_t attach(shell_t *env);
    static void release(void);
    static bool state(const char *value);
    static bool libexec(const char *fmt, ...) __PRINTF(1, 2);
    static FILE *output(const char *id);

    inline static const char *env(const char *id)
        {return args->getsym(id);}

    inline static String path(const char *id)
        {return (String)(args->getsym(id));}
};

END_NAMESPACE

#endif
