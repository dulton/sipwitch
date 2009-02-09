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

using namespace UCOMMON_NAMESPACE;
using namespace SIPWITCH_NAMESPACE;

#include <ucommon/ucommon.h>
#include <sipwitch/mapped.h>
#include <config.h>
#ifndef	_MSWINDOWS_
#include <signal.h>
#include <pwd.h>
#endif

static enum {
	OK = 0,
	ERR_REQUEST,
	ERR_TIMEOUT,
	ERR_NOATTACH,
	ERR_NOTFOUND,
	ERR_INVSTATS,
	ERR_INVCALLS
} error_code;

static bool initial = false;
static fsys	fifo;

static char **userindex;
static char **callindex, *callkeys, *calllist;
static char **statindex, *statkeys;
static mapped_view<stats> *statmap = NULL;
static mapped_view<MappedCall> *callmap = NULL;
static mapped_view<MappedRegistry> *regmap = NULL;

static void lock(void)
{
	Mutex::protect(&error_code);
	error_code = OK;
}

static void unlock(void)
{
	Mutex::release(&error_code);
}

static int error(void)
{
	return (int)error_code;
}

static void attach(void)
{
	unsigned count, index;
	if(error_code || initial)
		return;

#ifdef _MSWINDOWS_
	fifo.open("\\\\.mailslot\\sipwitch_ctrl", fsys::ACCESS_WRONLY);
#else
	fifo.open(DEFAULT_VARPATH "/run/sipwitch/control", fsys::ACCESS_WRONLY);
	if(!is(fifo)) {
		char buffer[512];
		struct passwd *pwd = getpwuid(getuid());
		snprintf(buffer, sizeof(buffer), "/tmp/sipwitch-%s/control", pwd->pw_name);
		endpwent();
		fifo.open(buffer, fsys::ACCESS_WRONLY);
	}
#endif

	if(!is(fifo))
		goto failed;

	statmap = new mapped_view<stats>(STAT_MAP);
	count = statmap->getCount();
	if(!count) {
		delete statmap;
		statmap = NULL;
failed:
		error_code = ERR_NOATTACH;
		return;
	}

	statindex = new char *[count + 1];
	statkeys = new char[count * 8];
	
	for(index = 0; index < count; ++index) {
		statindex[index] = &statkeys[index * 8];
		snprintf(&statkeys[index * 8], 8, "%d", index);
	}
	statindex[index] = 0;
	
	callmap = new mapped_view<MappedCall>(CALL_MAP);
	count = callmap->getCount();
	if(!count) {
		delete callmap;
		callmap = NULL;
		goto failed;
	}

	callindex = new char *[count + 1];
	callkeys = new char[count * 20];
	calllist = new char[count + 1];
	memset(calllist, 0, count);
	calllist[count] = 0;

	regmap = new mapped_view<MappedRegistry>(REGISTRY_MAP);
	count = regmap->getCount();
	if(!count) {
		delete regmap;
		regmap = NULL;
		goto failed;
	}

	userindex = new char *[regmap->getCount() + 1];
	initial = true;
}

static char *realm(void)
{
	static char buffer[128];
	fsys_t fd;

	memset(buffer, 0, sizeof(buffer));

	fsys::open(fd, "/tmp/siprealm", fsys::ACCESS_RDONLY);
	if(is(fd)) {
		fsys::read(fd, buffer, sizeof(buffer) - 1);
		fsys::close(fd);
		return buffer;
	}

	error_code = ERR_NOATTACH;
	return NULL;
}

static char *status(void)
{
	unsigned index = 0;
	unsigned count;
	const volatile MappedCall *map;

	attach();
	if(error_code)
		return NULL;

	count = callmap->getCount();
	while(index < count) {
		map = (*callmap)(index);
		calllist[index++] = map->state[0];
	}
	return calllist;
}

static char **statrange(void)
{
	attach();
	if(error_code)
		return NULL;

	return statindex;
}

static char **calls(void)
{
	unsigned index = 0, mapped = 0;
	volatile const MappedCall *map;

	attach();
	if(error_code)
		return NULL;

	time_t now;
	time(&now);

	while(index < callmap->getCount()) {
		map = (*callmap)(index++);

		if(!map->created)
			continue;

		snprintf(&callkeys[mapped * 20], 20, "%08x:%d", map->sequence, map->cid);
		callindex[mapped] = &callkeys[mapped * 20];
		++mapped;
	}
	callindex[mapped] = NULL;
	return callindex;
}

static char **users(void)
{
	unsigned index = 0, mapped = 0;
	volatile const MappedRegistry *map;

	attach();
	if(error_code)
		return NULL;

	time_t now;
	time(&now);

	while(index < regmap->getCount()) {
		map = (*regmap)(index++);

		if(map->status == MappedRegistry::OFFLINE)
			continue;

		if(map->type != MappedRegistry::USER && map->type != MappedRegistry::SERVICE) 
			continue;

		userindex[mapped++] = const_cast<char *>(map->userid);		
	}
	userindex[mapped] = NULL;
	return userindex;
}		

static void regcopy(const MappedRegistry *reg, struct Users *copy)
{
	const char *status = "idle";

	String::set(copy->userid, sizeof(copy->userid), reg->userid);
	if(reg->ext)
		snprintf(copy->extension, sizeof(copy->extension), "%u", reg->ext);
	else
		String::set(copy->extension, sizeof(copy->extension), reg->userid);
	String::set(copy->display, sizeof(copy->display), reg->display);
	String::set(copy->service, sizeof(copy->service), reg->profile.id);
	if(reg->inuse)
		status = "busy";
	else
		switch(reg->status) {
		case MappedRegistry::AWAY:
			status = "away";
			break;
		case MappedRegistry::DND:
			status = "dnd";
			break;
		case MappedRegistry::BUSY:
			status = "busy";
			break;
		default:
			break;
		}

	String::set(copy->status, sizeof(copy->status), status);
	copy->active = reg->inuse;
	copy->trs = reg->profile.level;
}

static void getextension(struct Users *copy, unsigned ext)
{
	unsigned index = 0;
	MappedRegistry buffer;
	memset(copy, 0, sizeof(MappedRegistry));
	attach();
	if(error_code)
		return;

	if(!regmap->getCount()) {
invalid:
		error_code = ERR_NOTFOUND;
		return;
	}

	const MappedRegistry *map;
	time_t now;

	time(&now);

	while(index < regmap->getCount()) {
		map = const_cast<const MappedRegistry *>((*regmap)(index));
		if(map->status == MappedRegistry::OFFLINE) {
			++index;
			continue;
		}

		if(map->type != MappedRegistry::USER && map->type != MappedRegistry::SERVICE) {
			++index;
			continue;
		}

		if(map->expires < now) {
			++index;
			continue;
		}

		do {
			memcpy(&buffer, map, sizeof(buffer));
		} while(memcmp(&buffer, map, sizeof(buffer)));
		map = &buffer;
		if(map->ext == ext)
			break;
		++index;
	}

	if(index >= regmap->getCount())
		goto invalid;
	
	regcopy(map, copy);
}

static void getuserid(struct Users *copy, const char *userid)
{
	unsigned index = 0;
	MappedRegistry buffer;
	memset(copy, 0, sizeof(MappedRegistry));
	attach();
	if(error_code)
		return;

	if(!regmap->getCount()) {
invalid:
		error_code = ERR_NOTFOUND;
		return;
	}

	const MappedRegistry *map;
	time_t now;

	time(&now);

	while(index < regmap->getCount()) {
		map = const_cast<const MappedRegistry *>((*regmap)(index));
		if(map->status == MappedRegistry::OFFLINE) {
			++index;
			continue;
		}

		if(map->type != MappedRegistry::USER && map->type != MappedRegistry::SERVICE) {
			++index;
			continue;
		}

		if(map->expires < now) {
			++index;
			continue;
		}

		do {
			memcpy(&buffer, map, sizeof(buffer));
		} while(memcmp(&buffer, map, sizeof(buffer)));
		map = &buffer;
		if(String::equal(map->userid, userid))
			break;
		++index;
	}

	if(index >= regmap->getCount())
		goto invalid;
	
	regcopy(map, copy);
}

static void getcallsbyid(struct Calls *copy, const char *sid)
{
	unsigned index = 0;
	MappedCall buffer;
	memset(copy, 0, sizeof(MappedCall));
	attach();
	if(error_code)
		return;

	if(!callmap->getCount()) {
invalid:
		error_code = ERR_INVCALLS;
		return;
	}

	const MappedCall *map;
	time_t now;

	time(&now);

	while(index < callmap->getCount()) {
		map = const_cast<const MappedCall *>((*callmap)(index));
		if(!map->created) {
			++index;
			continue;
		}

		do {
			memcpy(&buffer, map, sizeof(buffer));
		} while(memcmp(&buffer, map, sizeof(buffer)));
		map = &buffer;
		snprintf(copy->sid, sizeof(copy->sid), "%08x:%d", map->sequence, map->cid);
		if(String::equal(copy->sid, sid))
			break;
		++index;
	}

	if(index >= callmap->getCount())
		goto invalid;
	
	String::set(copy->state, sizeof(copy->state), map->state + 1);
	String::set(copy->source, sizeof(copy->source), map->source);
	String::set(copy->display, sizeof(copy->display), map->display);
	String::set(copy->target, sizeof(copy->target), map->target);
	copy->started = now - map->created;
	if(map->active)
		copy->active = now - map->active;
	else
		copy->active = 0;
}

static void getcalls(struct Calls *copy, unsigned index)
{
	MappedCall buffer;
	memset(copy, 0, sizeof(MappedCall));
	attach();
	if(error_code)
		return;

	if(index >= callmap->getCount()) {
invalid:
		error_code = ERR_INVCALLS;
		return;
	}

	time_t now;
	const MappedCall *map = const_cast<const MappedCall *>((*callmap)(index));
	if(!map->created)
		goto invalid;

	do {
		memcpy(&buffer, map, sizeof(buffer));
	} while(memcmp(&buffer, map, sizeof(buffer)));
	map = &buffer;

	time(&now);

	snprintf(copy->sid, sizeof(copy->sid), "%08x:%d", map->sequence, map->cid);
	String::set(copy->state, sizeof(copy->state), map->state + 1);
	String::set(copy->source, sizeof(copy->source), map->source);
	String::set(copy->target, sizeof(copy->target), map->target);
	copy->started = now - map->created;
	if(map->active)
		copy->active = now - map->active;
	else
		copy->active = 0;
}

static void getstats(struct Stats *copy, unsigned index)
{
	stats buffer;
	memset(copy, 0, sizeof(struct Stats));
	attach();
	if(error_code)
		return;

	if(index >= statmap->getCount()) {
invalid:
		error_code = ERR_INVSTATS;
		return;
	}

	time_t now;
	const stats *map = const_cast<const stats *>((*statmap)(index));
	if(!map->id[0])
		goto invalid;

	do {
		memcpy(&buffer, map, sizeof(buffer));
	} while(memcmp(&buffer, map, sizeof(buffer)));
	map = &buffer;

	time(&now);

	String::set(copy->id, 12, const_cast<const char *>(map->id));
	copy->members = map->limit;	
	if(map->lastcall)
		copy->lastcall = now - map->lastcall;
	else
		copy->lastcall = 0;

	for(unsigned entry = 0; entry < 2; ++entry) {
		copy->data[entry].total = map->data[entry].total;
		copy->data[entry].current = map->data[entry].current;
		copy->data[entry].peak = map->data[entry].peak;
	}
}

static void getpstats(struct PStats *copy, unsigned index)
{
	memset(copy, 0, sizeof(struct Stats));
	attach();
	if(error_code)
		return;

	if(index >= statmap->getCount()) {
invalid:
		error_code = ERR_INVSTATS;
		return;
	}

	time_t now;
	const volatile stats *map = (*statmap)(index);
	if(!map->id[0])
		goto invalid;

	time(&now);

	String::set(copy->id, 12, const_cast<const char *>(map->id));
	copy->members = map->limit;	
	if(map->lastcall)
		copy->lastcall = now - map->lastcall;
	else
		copy->lastcall = 0;

	for(unsigned entry = 0; entry < 2; ++entry) {
		copy->period[entry].total = map->data[entry].pperiod;
		copy->period[entry].min = map->data[entry].pmin;
		copy->period[entry].max = map->data[entry].pmax;
	}
}

static void release(void)
{
	if(!initial || error_code)
		return;

	if(is(fifo))
		fifo.close();
	if(statmap) {
		delete[] statindex;
		delete[] statkeys;
		delete statmap;
		statmap = NULL;
	}
	if(callmap) {
		delete callmap;
		delete[] callindex;
		delete[] callkeys;
		delete[] calllist;
		callmap = NULL;
	}
	if(regmap) {
		delete regmap;
		delete[] userindex;
		regmap = NULL;
	}
	initial = false;
}

static bool check(void)
{
	attach();
	error_code = OK;
	return initial;
}

static int control(const char *string)
{
	attach();
	if(error_code)
		return error_code;

	char buffer[511];

#ifdef	_MSWINDOWS_
	snprintf(buffer, sizeof(buffer) - 1, "%s\n", string);
#else
	snprintf(buffer, sizeof(buffer) - 1, "%d %s\n", getpid(), string);

	sigset_t sigs, old;
	int signo;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sigs, &old);
#endif

	// we must always have a newline at end of command...
	char *ep = strchr(buffer, '\n');
	ep[1] = 0;

	fifo.write(buffer, strlen(buffer));

#ifndef	_MSWINDOWS_
	alarm(60);
#ifdef	HAVE_SIGWAIT2
	sigwait(&sigs, &signo);
#else
	signo = sigwait(&sigs);
#endif
	alarm(0);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if(signo == SIGALRM) {
		error_code = ERR_TIMEOUT;
		release();
	}
	else if(signo == SIGUSR2)
		error_code = ERR_REQUEST;
#endif		
	return error_code;
}

unsigned count(void)
{
	attach();
	if(error_code)
		return 0;

	if(callmap)
		return callmap->getCount();
	return 0;
}
