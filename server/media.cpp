// Copyright (C) 2010 David Sugar, Tycho Softworks.
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

#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static unsigned port = 5062;
static bool ipv6 = false;
static LinkedObject *idle = NULL;
static LinkedObject *runlist = NULL;
static condlock_t runlock, idlelock; 

media::sdp::sdp()
{
	outdata = bufdata = NULL;
}

media::sdp::sdp(char *source, char *target, size_t len)
{
	set(source, target, len);
}

void media::sdp::set(char *source, char *target, size_t len)
{
	outdata = target;
	bufdata = source;
	outpos = 0;
}

char *media::sdp::get(char *buffer, size_t len)
{
	char *base = buffer;

	// if eod, return NULL
	if(!bufdata || *bufdata == 0) {
		*buffer = 0;
		return NULL;
	}

	while(len > 1 && *bufdata != 0) {
		if(*bufdata == '\r') {
			++bufdata;
			continue;
		}
		else if(*buffer == '\n') {
			*buffer = 0;
			return base;
		}
		*(buffer++) = *(bufdata++);
		--len;
	}
	*buffer = 0;
	return base;
}

size_t media::sdp::put(char *buffer)
{
	size_t count = 0;

	if(!outdata)
		return 0;	

	while(*buffer && outpos < (MAX_SDP_BUFFER - 2)) {
		++count;
		*(outdata++) = *(buffer++);
	}
	
	*(outdata++) = '\r';
	*(outdata++) = '\n';
	*outdata = 0;
	return count + 2;
}

void media::enableIPV6(void)
{
	ipv6 = true;
}

void media::release(LinkedObject **nat, unsigned expires)
{
	assert(nat != NULL);

	time_t expire = 0;

	if(!*nat)
		return;

	if(expires) {
		time(&expire);
		expire += expires;
	}

	// linked_pointer set for nat...
	// chain walked...
	// if expires, move to runlist for transition, else move to idle list for re-assign...
	*nat = NULL;
}

bool media::isDirect(const char *source, const char *target)
{
	assert(source != NULL);
	assert(target != NULL);

	// if same subnets, then we know is direct
	if(String::equal(source, target))
		return true;

	// if unknown networks then we cannot determine...
	if(String::equal(source, "-") || String::equal(target, "-"))
		return true;

	// if sdp source is external, we do not need to proxy (one-legged only)
	// since we assume we can trust external user's public sdp
	if(String::equal(source, "*"))
		return true;

	// if external is remote and also we're ipv6, no need to proxy...
	if(String::equal(target, "*") && ipv6)
		return true;

	// will become false later...
	return true;
}

char *media::invite(stack::session *session, const char *target, LinkedObject **nat, char *sdp, size_t size)
{
	assert(session != NULL);
	assert(target != NULL);
	assert(nat != NULL);

	*nat = NULL;

	if(isDirect(session->network, target)) {
		String::set(sdp, size, session->sdp);
		return sdp;
	}

	// no proxy code yet...
	return NULL;
}

END_NAMESPACE
