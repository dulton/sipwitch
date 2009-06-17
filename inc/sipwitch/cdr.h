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
 * Basic server call detail record.
 * This provides an interface for creating call detail objects which can be
 * logged through plugins.  The cdr system has it's own thread context and
 * buffering, so cdr records can be disposed without delaying calls processing.
 * @file sipwitch/cdr.h
 */

#ifndef _SIPWITCH_CDR_H_
#define	_SIPWITCH_CDR_H_

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

#ifndef	_SIPWITCH_MAPPED_H_
#include <sipwitch/mapped.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT cdr : public LinkedObject
{
public:
	enum {START, STOP} type;
	char uuid[48];
	char ident[MAX_IDENT_SIZE];
	char dialed[MAX_IDENT_SIZE];
	char joined[MAX_IDENT_SIZE];
	char display[MAX_DISPLAY_SIZE];
	char network[MAX_NETWORK_SIZE * 2];
	char reason[16];
	unsigned cid, sequence;
	time_t starting;
	unsigned long duration;

	// get a cdr instance to fill from free list or memory...
	static cdr *get(void);

	// post cdr record and return to free...
	static void post(cdr *cdr);

	// start thread...
	static void start(void);

	// stop subsystem
	static void stop(void);
};	
	
END_NAMESPACE

#endif
