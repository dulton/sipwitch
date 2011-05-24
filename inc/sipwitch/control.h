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

/**
 * Server control interfaces and functions.  This is an internal management
 * class for the server control fifo and for other server control operations.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class __EXPORT control
{
private:
    static shell_t *args;

public:
    /**
     * Send a printf-style message to the control fifo via the file system.
     * While plugins can also use this to send control messages back into the
     * server, we should create a method that does not require going to the
     * external filesystem to do this.
     * @param format string.
     * @return true if successful.
     */
    static bool send(const char *format, ...) __PRINTF(1, 2);

    /**
     * Used by the server to pull pending fifo requests.
     * @return string of next fifo input.
     */
    static char *receive(void);

    /**
     * Used by the server to send replies back to control requests.
     * @param error string to report or NULL for none.
     */
    static void reply(const char *error = NULL);

    /**
     * Creates the control fifo using server configuration.  This also
     * attaches the shell environment and command line arguments to the
     * current server instance so it can be accessed by other things.
     * @param env of server.
     * @return size of longest control message supported.
     */
    static size_t attach(shell_t *env);

    /**
     * Used by the server to destroy the control fifo.
     */
    static void release(void);

    /**
     * Sets server run state configuration.  This is done by symlinking
     * a state xml file when selecting a special running state.
     * @param state to select.
     * @return true if set to state.
     */
    static bool state(const char *value);

    /**
     * Execute an external shell command on behalf of the server.  This
     * might also be used by plugins to execute supporting processes.  The
     * function waits until the child process completes but does not return
     * the child exit code.
     * @param format of shell command to execute.
     * @return true if successfully executed.
     */
    static bool libexec(const char *fmt, ...) __PRINTF(1, 2);

    /**
     * Used to open an output session for returning control data.
     * @param id of output type.
     * @return file handle to write to or NULL on failure.
     */
    static FILE *output(const char *id);

    /**
     * Return the value of a server environment variable.  This is commonly
     * used by plugins to get access to the server environment.
     * @param id of environment symbol.
     * @return value of symbol or NULL if not found.
     */
    inline static const char *env(const char *id)
        {return args->getsym(id);}

    /**
     * Get a string from a server environment variable.  This is often
     * used to get pathname variables which may then be further
     * concatenated.  This is commonly used by plugins to get paths.
     * @param id of environment symbol.
     * @return string value of symbol requested.
     */
    inline static String path(const char *id)
        {return (String)(args->getsym(id));}
};

END_NAMESPACE

#endif
