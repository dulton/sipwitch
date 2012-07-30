// Copyright (C) 2009-2010 David Sugar, Tycho Softworks.
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

#include <sipwitch-config.h>
#include <ucommon/ucommon.h>
#include <ucommon/export.h>
#include <sipwitch/stats.h>
#include <sipwitch/control.h>

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

static unsigned used = 0, total = 7;
static stats *base = NULL;

static class __LOCAL sta : public mapped_array<stats>
{
public:
    sta();

    void init(void);
} shm;

sta::sta() : mapped_array<stats>()
{
}

void sta::init(void)
{
    const char *statmap = control::env("statmap");
    ::remove(statmap);
    create(statmap, total);
}

stats *stats::create(void)
{
    shm.init();
    base = request("system");
    request("extension");
    request("service");
    request("gateway");
    request("external");
    request("other");
    return base;
}

stats *stats::request(const char *id)
{
    assert(id && *id);

    if(used >= total)
        return NULL;

    stats *node = shm(used++);
    snprintf(node->id, sizeof(node->id), "%s", id);
    return node;
}

void stats::allocate(unsigned count)
{
    assert(count > 0);

    total += count;
}

unsigned stats::active(void) const
{
    return data[0].current + data[1].current;
}

void stats::assign(stat_t entry)
{
    Mutex::protect(this);
    ++data[entry].period;
    ++data[entry].total;
    ++data[entry].current;
    if(data[entry].current > data[entry].peak)
        data[entry].peak = data[entry].current;
    if(data[entry].current > data[entry].max)
        data[entry].max = data[entry].current;
    Mutex::release(this);
    if(this != base)
        base->assign(entry);
}

void stats::release(void)
{
    shm.release();
    shm.remove(control::env("statmap"));
}

void stats::release(stat_t entry)
{
    Mutex::protect(this);
    if(active() == 1)
        time(&lastcall);
    --data[entry].current;
    if(data[entry].current < data[entry].min)
        data[entry].min = data[entry].current;
    Mutex::release(this);
    if(this != base)
        base->release(entry);
}

void stats::period(FILE *fp)
{
    unsigned pos = 0;
    char text[80];
    size_t len;
    time_t last;

    while(pos < total) {
        stats *node = shm(pos++);
        if(!node->id[0])
            continue;

        if(fp) {
            snprintf(text, sizeof(text), " %-12s", node->id);
            len = strlen(text);
        }
        else
            len = 0;

        Mutex::protect(node);
        for(unsigned entry = 0; entry < 2; ++entry) {
            if(fp) {
                snprintf(text + len, sizeof(text) - len, " %09lu %05hu %05hu",
                node->data[entry].period, node->data[entry].min, node->data[entry].max);
                len = strlen(text);
            }
            node->data[entry].pperiod = node->data[entry].period;
            node->data[entry].pmin = node->data[entry].min;
            node->data[entry].pmax = node->data[entry].max;
            node->data[entry].min = node->data[entry].max = node->data[entry].current;
            node->data[entry].period = 0;
        }
        last = node->lastcall;
        Mutex::release(node);
        if(fp)
            fprintf(fp, "%s %ld\n", text, (long)last);
    }
}

