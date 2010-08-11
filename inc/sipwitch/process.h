// Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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
 * Portable process management.
 * This offers a portable abstract interface class for process & ipc related
 * services that may be used by GNU Telephony servers.  This includes
 * management of the deamon environment, executing child processes, and basic
 * IPC services.  IPC services are offered through control ports which are
 * implimented as fifo's on Posix platforms, and as mailslots on w32.
 * @file sipwitch/process.h
 */

#ifndef _SIPWITCH_PROCESS_H_
#define	_SIPWITCH_PROCESS_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	_SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	DEBUG1	shell::DEBUG0
#define	DEBUG2	(shell::loglevel_t(((unsigned)shell::DEBUG0 + 1)))
#define	DEBUG3	(shell::loglevel_t(((unsigned)shell::DEBUG0 + 2)))

class __EXPORT process { public: static shell_t args;

	static void printlog(const char *fmt, ...) __PRINTF(1, 2);
	static bool control(const char *fmt, ...) __PRINTF(1, 2);
	static void result(const char *value);
	static char *receive(void);
	static void reply(const char *err = NULL);
	static size_t attach(void);
	static void release(void);
	static bool state(const char *value);
	static bool system(const char *fmt, ...) __PRINTF(1, 2);
	static FILE *output(const char *id);
	static void uuid(char *buffer, size_t size, const char *node);
	static void uuid(char *buffer, size_t size, unsigned short seq, unsigned callid);

	inline static void set(const char *id, const char *value)
		{args.setsym(id, value);}

	inline static const char *get(const char *id)
		{return args.getsym(id);}

	inline static String path(const char *id)
		{return (String)(args.getsym(id));}
};

END_NAMESPACE

#endif
