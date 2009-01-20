// Copyright (C) 2009 David Sugar, Tycho Softworks.
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
 * Basic server call statistics.
 * This provides the interface for managing stat nodes, which are kept in
 * shared memory.
 * @file sipwitch/stats.h
 */

#ifndef _SIPWITCH_STATS_H_
#define	_SIPWITCH_STATS_H_

#ifndef _UCOMMON_LINKED_H_
#include <ucommon/linked.h>
#endif

#ifndef	_UCOMMON_THREAD_H_
#include <ucommon/thread.h>
#endif

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	_CCSCRIPT_H_
#include <ccscript.h>
#endif

#ifndef	_SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	STAT_MAP	"sipwitch.stats"

class __EXPORT stats
{
public:
	char id[12];

	typedef	enum {INCOMING = 0, OUTGOING = 1} stat_t;

	struct
	{
		unsigned long total, period;
		unsigned short current, peak;
	} data[2];

	time_t lastcall;

	void assign(stat_t element);
	void release(stat_t element);
	unsigned active(void) const;

	static void period(FILE *fp = NULL);
	static stats *create(void);
	static stats *request(const char *id);
	static void allocate(unsigned count);
};

END_NAMESPACE

#endif
