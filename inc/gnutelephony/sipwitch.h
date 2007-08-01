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

#ifndef	_GNUTELEPHONY_SIPWITCH_H_
#define	_GNUTELEPHONY_SIPWITCH_H_

#include <ucommon/ucommon.h>
#include <gnutelephony/mapped.h>
#include <gnutelephony/service.h>
#include <gnutelephony/digest.h>

#define SIPWITCH_NAMESPACE  sipwitch
#define NAMESPACE_SIPWITCH  namespace sipwitch {

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define	USER_PROFILE_DIALABLE		0x0001	// user may be dialed
#define	USER_PROFILE_REACHABLE		0x0002	// user may be reached by gateway
#define	USER_PROFILE_EXTERNAL		0x0004	// user may route external
#define	USER_PROFILE_INTERNAL		0x0008	// user may use dialing/routing
#define	USER_PROFILE_SUBSCRIPTIONS	0x0010	// user can subscribe to others
#define	USER_PROFILE_SUBSCRIBERS	0x0020	// user can be subscribed
#define	USER_PROFILE_MULTITARGET	0x0800	// multi-target registration

#define	USER_PROFILE_DEFAULT		0x0fff
#define	USER_PROFILE_RESTRICTED	(0)

#define	MAX_PATTERN_SIZE	16
#define	MAX_USERID_SIZE		32
#define	MAX_URI_SIZE		256

typedef struct {
	char id[MAX_USERID_SIZE];
	unsigned short features;
	unsigned level;
} profile_t;

typedef enum {
	REG_EXPIRED = 0,	// expired record
	REG_USER,			// user records with profiles
	REG_GATEWAY,		// registered and static
	REG_SERVICE,		// routes for contacts
	REG_REFER			// registered and static
} regtype_t;

class __EXPORT MappedRegistry : public ReusableObject
{
public:
	char	userid[MAX_USERID_SIZE];
	unsigned ext;				// 0 or extnum
	unsigned count;				// active regs count
	regtype_t type;				// registry type
	sockaddr_internet latest;	// last/newest created registration
	time_t  expires;			// when registry expires as a whole
	profile_t profile;			// profile at time of registration
	LinkedObject *targets;		// active registrations (can be multiple)
	LinkedObject *routes;		// active route records
};

class __EXPORT MappedCall : public ReusableObject
{
public:
	time_t	created;
	time_t	active;
	char	sourceid[MAX_USERID_SIZE];
	char	targetid[MAX_USERID_SIZE];
	unsigned sourceext, targetext;
	sockaddr_internet source, target;
	unsigned count;				// active segments
};

END_NAMESPACE

#endif
