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

#include <sipwitch/sipwitch.h>
#include <config.h>

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

class __LOCAL forward : public modules::sipwitch
{
public:
	String server;
	time_t	expires;
	bool enabled;

	forward();

private:
	void start(service *cfg);
	bool reload(service *cfg);
	void activating(MappedRegistry *rr);
	void expiring(MappedRegistry *rr);
};

static forward forward_plugin;

forward::forward() :
modules::sipwitch()
{
	process::errlog(INFO, "server forward plugin loaded");	
	enabled = false;
}

bool forward::reload(service *cfg)
{
	assert(cfg != NULL);

	bool enable = false;
	const char *key = NULL, *value;
	linked_pointer<service::keynode> fp = cfg->getList("forward");
	
	while(is(fp)) {
		key = fp->getId();
		value = fp->getPointer();
		if(key && value) {
			if(String::equal(key, "server")) {
				enable = true;
				server = value;
			}
			else if(String::equal(key, "expires"))
				expires = atoi(value);
		}
		fp.next();
	}
	enabled = enable;
	return true;
}

void forward::start(service *cfg)
{
	assert(cfg != NULL);
}

void forward::activating(MappedRegistry *rr)
{
	if(!enabled)
		return;
}

void forward::expiring(MappedRegistry *rr)
{
	if(!enabled)
		return;
}

END_NAMESPACE
