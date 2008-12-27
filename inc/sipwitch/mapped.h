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
 * Definitions for memory mapped objects that may be shared between
 * processes.  This includes the memory mapped registry and active call
 * records.
 * @file sipwitch/mapped.h
 */

#ifndef	_SIPWITCH_MAPPED_H_
#define	_SIPWITCH_MAPPED_H_

#ifndef	_SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

/**
 * Classes related to memory mapped objects from sipwitch server.
 * This covers the published interfaces to the sipwitch server itself.  These
 * are mostly classes that are mapped into shared memory blocks, and for
 * defining highly sipwitch specific plugin interfaces.
 * @file sipwitch/mapped.h
 */

#define	USER_PROFILE_DIALABLE		0x0001	// user may be dialed
#define	USER_PROFILE_REACHABLE		0x0002	// user may be reached by gateway
#define	USER_PROFILE_INTERNAL		0x0008	// user may use dialing/routing
#define	USER_PROFILE_SUBSCRIPTIONS	0x0010	// user can subscribe to others
#define	USER_PROFILE_SUBSCRIBERS	0x0020	// user can be subscribed
#define	USER_PROFILE_MULTITARGET	0x0800	// multi-target registration
#define	USER_PROFILE_INCOMING		0x1000  // user "name" id may be accessed
#define	USER_PROFILE_OUTGOING		0x2000	// may use generic uri

#define	USER_PROFILE_DEFAULT		0x0fff
#define	USER_PROFILE_RESTRICTED	(0)

#define	MAX_PATTERN_SIZE	16
#define	MAX_DISPLAY_SIZE	64
#define	MAX_USERID_SIZE		48
#define	MAX_IDENT_SIZE		(MAX_USERID_SIZE + 50)
#define	MAX_URI_SIZE		256

#define	FWD_ALL_ENABLED		0x01
#define	FWD_BUSY_ENABLED	0x02
#define	FWD_BNA_ENABLED		0x04
#define	FWD_DND_ENABLED		0x08
#define	FWD_AWAY_ENABLED	0x10
#define	FWD_PUBLIC_ENABLED	0x20

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

typedef struct {
	char id[MAX_USERID_SIZE];
	unsigned short features;
	unsigned level;
} profile_t;

class __EXPORT MappedRegistry : public ReusableObject
{
public:
	char	userid[MAX_USERID_SIZE];
	char	display[MAX_DISPLAY_SIZE];
	char	remote[MAX_USERID_SIZE];
	enum {OFFLINE = 0, IDLE, BUSY, AWAY, DND} status;
	enum {EXPIRED = 0, USER, GATEWAY, SERVICE, REJECT, REFER, TEMPORARY, EXTERNAL} type;
	bool hidden;
	int rid;					// registry remap or peer id 
	unsigned ext;				// 0 or extnum
	unsigned count;				// active regs count
	volatile unsigned inuse;	// in use for call count
	sockaddr_internet contact;	// last/newest created contact registration
	time_t	created;			// initial registration
	volatile time_t  expires;	// when registry expires as a whole
	profile_t profile;			// profile at time of registration
	LinkedObject *published;	// published routes
	LinkedObject *targets;		// active registrations (can be multiple)
	LinkedObject *routes;		// active route records
};

class __EXPORT MappedCall : public ReusableObject
{
public:
	time_t	created;
	time_t	active;
	char	authorized[MAX_USERID_SIZE];
	char from[MAX_URI_SIZE], to[MAX_URI_SIZE];
	unsigned sourceext, targetext;
	sockaddr_internet source, target;
	unsigned count;				// active segments
};

END_NAMESPACE

#endif
