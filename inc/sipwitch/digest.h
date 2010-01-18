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
 * Compute cryptographic hashes and cipher memory.
 * Common cryptographic hash support depends on the underlying crypto
 * library that we are linked with.  This is used to compute hashes for
 * digest authentication.
 * @file sipwitch/digest.h
 */

#ifndef _SIPWITCH_DIGEST_H_
#define	_SIPWITCH_DIGEST_H_

#ifndef	_UCOMMON_STRING_H_
#include <ucommon/string.h>
#endif

#ifndef	__SIPWITCH_NAMESPACE_H_
#include <sipwitch/namespace.h>
#endif

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __EXPORT digest 
{
public:
	static unsigned md5(unsigned char *buf, const char *str);
	static unsigned md5(string_t &d, const char *str = NULL);
	static unsigned sha1(unsigned char *buf, const char *str);
	static unsigned sha1(string_t &d, const char *str = NULL);
	static unsigned rmd160(unsigned char *buf, const char *str);
	static unsigned rmd160(string_t &d, const char *str = NULL);
	static void clear(void);
	static const char *get(const char *id);
	static bool set(const char *id, const char *hash);
	static void release(const char *hash);
	static void load(void);
};

END_NAMESPACE

#endif
