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
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

#define	DEBUG
#include <gnutelephony/sipwitch.h>

#include <stdio.h>

using namespace UCOMMON_NAMESPACE;

static int init_callback = 0;
static int load_callback = 0;

static class testCallback : public service::callback
{
public:
	testCallback() : service::callback(1, "test") 
		{if(++init_callback == 2) active_flag = true;};
	bool reload(service *cfg) 
		{++load_callback; return true;};
}	testcalls, extra;

extern "C" int main()
{
	service *cfg = new service("test");
	assert(cfg != NULL);
	// constructors built
	assert(init_callback == 2);
	// test reloading
	assert(cfg->commit(NULL) == true);
	assert(load_callback == 2);
	assert(service::getComponent("test") == &extra);
};
