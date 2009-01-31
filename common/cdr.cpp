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

#include <config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/cdr.h>
#include <sipwitch/process.h>
#include <sipwitch/service.h>
#include <sipwitch/modules.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

class __LOCAL thread : public DetachedThread, public Conditional
{
public:
	thread();

	inline void lock(void)
		{Conditional::lock();};

	inline void unlock(void)
		{Conditional::unlock();};

	inline void signal(void)
		{Conditional::signal();};

private:
	void exit(void);
	void run(void);
};

static LinkedObject *freelist = NULL;
static LinkedObject *runlist = NULL;
static Mutex locking;
static memalloc heap;
static thread run;
static bool running = false;
static bool down = false;

thread::thread() : DetachedThread(), Conditional()
{
}

void thread::exit(void)
{
}

void thread::run(void)
{
	running = true;
	linked_pointer<cdr> cp;
	LinkedObject *next;
	FILE *fp;

	process::errlog(DEBUG1, "starting cdr thread");

	for(;;) {
		Conditional::lock();
		if(!running) {
			Conditional::unlock();
			process::errlog(DEBUG1, "stopped cdr thread");
			down = true;
			return;
		}
		Conditional::wait();
		cp = runlist;
		fp = NULL;
		if(runlist)
			fp = process::callfile();
		runlist = NULL;
		Conditional::unlock();
		while(is(cp)) {
			next = cp->getNext();
			modules::cdrlog(fp, *cp);
			locking.lock();
			cp->enlist(&freelist);
			locking.release();
			cp = next;
		}
		if(fp)
			fclose(fp);
	}
}

void cdr::post(cdr *rec)
{
	run.lock();
	rec->enlist(&runlist);
	run.signal();
	run.unlock();
}
	
cdr *cdr::get(void) {
	cdr *rec;

	locking.lock();
	if(freelist) {
		rec = (cdr *)freelist;
		freelist = rec->next;
		locking.release();
		memset(rec, 0, sizeof(cdr));
		return rec;
	}
	locking.release();
	return (cdr *)(heap.zalloc(sizeof(cdr)));
}

void cdr::start(void)
{
	run.start();
}

void cdr::stop(void)
{
	run.lock();
	running = false;
	run.signal();
	run.unlock();

	while(!down)
		Thread::sleep(20);
}
				
