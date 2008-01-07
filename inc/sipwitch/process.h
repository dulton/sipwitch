// Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
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
 * @file gnutelephony/process.h
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

NAMESPACE_UCOMMON

typedef enum
{
	FAILURE = 0,
	ERRLOG,
	WARN,
	NOTIFY,
	NOTICE=NOTIFY,
	INFO,
	DEBUG1,
	DEBUG2,
	DEBUG3
} errlevel_t;

class __EXPORT process
{
private:
	static errlevel_t verbose;

public:
	inline static void setVerbose(errlevel_t idx)
		{verbose = idx;};

	static void printlog(const char *id, const char *uid, const char *fmt, ...) __PRINTF(3, 4);
	static void errlog(errlevel_t log, const char *fmt, ...) __PRINTF(2, 3);
	static void restart(void);
	static bool control(const char *id, const char *uid, const char *fmt, ...) __PRINTF(3, 4);
	static void result(const char *value);
	static char *receive(void);
	static void reply(const char *err = NULL);
	static void util(const char *id);
	static void foreground(const char *id, const char *uid = NULL, const char *cfgpath = NULL, unsigned priority = 0, size_t ps = 0);
	static void background(const char *id, const char *uid = NULL, const char *cfgpath = NULL, unsigned priority = 0, size_t ps = 0);
	static void release(void);
	static FILE *open(const char *id, const char *uid = NULL, const char *cfgpath = NULL);
};

#ifdef	DEBUG
#define	debug(l, s, a...)	process::errlog((errlevel_t)(INFO + l), s, ## a)
#else
#define	debug(l, s, a...)
#endif

END_NAMESPACE

#endif
