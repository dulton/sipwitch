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

media::sdp::sdp()
{
	outdata = bufdata = NULL;
}

media::sdp::sdp(char *buffer, char *target, size_t len)
{
	set(buffer, target, len);
}

void media::sdp::set(char *buffer, char *target, size_t len)
{
	outdata = target;
	bufdata = buffer;
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

END_NAMESPACE
