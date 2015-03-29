// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015 Cherokees of Idaho.
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

#ifndef _SIPWITCH_MAPPED_H_
#define _SIPWITCH_MAPPED_H_

#ifndef _SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

#ifndef _SIPWITCH_VOIP_H_
#include <sipwitch/voip.h>
#endif

#ifndef _SIPWITCH_STATS_H_
#include <sipwitch/stats.h>
#endif

/**
 * Classes related to memory mapped objects from sipwitch server.
 * This covers the published interfaces to the sipwitch server itself.  These
 * are mostly classes that are mapped into shared memory blocks, and for
 * defining highly sipwitch specific plugin interfaces.
 * @file sipwitch/mapped.h
 */

// user and device properties...

#define USER_PROFILE_DIALABLE       0x0001  // user may be dialed
#define USER_PROFILE_REACHABLE      0x0002  // user may be reached by gateway
#define USER_PROFILE_INTERNAL       0x0008  // user may use dialing/routing
#define USER_PROFILE_SUBSCRIPTIONS  0x0010  // user can subscribe to others
#define USER_PROFILE_SUBSCRIBERS    0x0020  // user can be subscribed
#define USER_PROFILE_INCOMING       0x1000  // user "name" id may be accessed
#define USER_PROFILE_OUTGOING       0x2000  // may use generic uri
#define USER_PROFILE_SUPERUSER      0x8000  // has admin flag

#define USER_PROFILE_ADMIN          0xffff
#define USER_PROFILE_LOCAL          0x0fff
#define USER_PROFILE_DEVICE         0x0f0f
#define USER_PROFILE_SERVICE        0x7f0f
#define USER_PROFILE_SYSTEM         0x2f08
#define USER_PROFILE_DEFAULT        0x7fff
#define USER_PROFILE_RESTRICTED (0)

#define MAX_NETWORK_SIZE    16      // based on cidr name size...
#define MAX_PATTERN_SIZE    16
#define MAX_DISPLAY_SIZE    64
#define MAX_USERID_SIZE     48
#define MAX_IDENT_SIZE      (MAX_USERID_SIZE + 50)
#define MAX_URI_SIZE        256
#define MAX_SDP_BUFFER      1024

namespace sipwitch {

#define CALL_MAP        "sipwitch.calls"
#define REGISTRY_MAP    "sipwitch.regs"

/**
 * User profiles are used to map features and toll restriction level together
 * under a common identifier.
 */
typedef struct {
    char id[MAX_USERID_SIZE];
    unsigned short features;
    unsigned level;
} profile_t;

/**
 * Representation of a mapped active user record.  These exist in shared
 * memory.  They are used as data structures inside the server, and also
 * can be examined by external client applications.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class MappedRegistry : public LinkedObject
{
public:
    typedef enum {OFFLINE = 0, IDLE, BUSY, AWAY, DND} status_t;

    char    userid[MAX_USERID_SIZE];
    char    display[MAX_DISPLAY_SIZE];
    char    remote[MAX_USERID_SIZE];
    char    network[MAX_NETWORK_SIZE];
    status_t status;
    enum {EXPIRED = 0, USER, GATEWAY, SERVICE, REJECT, REFER, TEMPORARY, EXTERNAL} type;
    bool hidden;
    voip::reg_t rid;            // registry remap or peer id
    unsigned ext;               // 0 or extnum
    unsigned count;             // active regs count
    volatile unsigned inuse;    // in use for call count
    sockaddr_internet contact;  // last/newest created contact registration
    time_t  created;            // initial registration
    volatile time_t  expires;   // when registry expires as a whole
    profile_t profile;          // profile at time of registration
    union {
        struct {                // external registry properties...
            const char *identity;   // forced identity string when calling
            const char *connect;    // invite uri host identity
            stats *statnode;        // associated stat node...
        } external;
        struct {                // internal registry properties
            LinkedObject *published;    // published routes
            LinkedObject *targets;  // active registrations (can be multiple)
            LinkedObject *routes;   // active route records
        } internal;
    } source;

    inline bool is_user(void) const
        {return (type == USER);}

    inline bool is_profiled(void) const
        {return (type == USER || type == SERVICE);}

    inline bool is_admin(void) const
        {return (is_profiled() && (profile.features & USER_PROFILE_SUPERUSER));}

    inline bool has_feature(unsigned short X) const
        {return is_profiled() && (profile.features & X);}
};

/**
 * Representation of an active call record.  These exist in shared
 * memory.  They are used as data structures inside the server, and also
 * can be examined by external client applications.
 * @author David Sugar <dyfet@gnutelephony.org>
 */
class MappedCall : public LinkedObject
{
public:
    time_t  created;
    time_t  active;
    char state[16];
    char authorized[MAX_USERID_SIZE];
    char source[MAX_IDENT_SIZE], target[MAX_IDENT_SIZE];
    char display[MAX_DISPLAY_SIZE];
    uint32_t sequence;
    int cid;
};

} // namespace sipwitch

#endif
