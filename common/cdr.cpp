// Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
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
static Mutex private_lock;
static memalloc private_heap;
static thread run;
static bool running = false;
static bool down = false;
static bool logging = false;

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

    shell::log(DEBUG1, "starting cdr thread");

    for(;;) {
        Conditional::lock();
        if(!running) {
            Conditional::unlock();
            shell::log(DEBUG1, "stopped cdr thread");
            down = true;
            return;
        }
        Conditional::wait();
        cp = runlist;
        fp = NULL;
        if(runlist && logging)
            fp = fopen(process::get("calls"), "a");
        runlist = NULL;
        logging = false;
        Conditional::unlock();
        while(is(cp)) {
            next = cp->getNext();
            modules::cdrlog(fp, *cp);
            private_lock.acquire();
            cp->enlist(&freelist);
            private_lock.release();
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
    if(rec->type == STOP)
        logging = true;
    run.signal();
    run.unlock();
}

cdr *cdr::get(void) {
    cdr *rec;

    private_lock.acquire();
    if(freelist) {
        rec = (cdr *)freelist;
        freelist = rec->next;
        private_lock.release();
        rec->uuid[0] = 0;
        rec->ident[0] = 0;
        rec->dialed[0] = 0;
        rec->joined[0] = 0;
        rec->display[0] = 0;
        rec->network[0] = 0;
        rec->reason[0] = 0;
        rec->cid = rec->sequence = 0;
        rec->starting = 0;
        rec->duration = 0;
        return rec;
    }
    private_lock.release();
    return (cdr *)(private_heap.zalloc(sizeof(cdr)));
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

