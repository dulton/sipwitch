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

static mutex_t histlock;
static OrderedIndex histindex;
static unsigned histcount = 0;
static unsigned histlimit = 0;

history::history(shell::loglevel_t lid, const char *msg) :
OrderedObject(&histindex)
{
    ++histcount;
    set(lid, msg);
}

void history::set(shell::loglevel_t lid, const char *msg)
{
    Time now;
    char buf[20];

    now.get(buf);
    snprintf(text, sizeof(text), "%s %02d %s",
        buf, (int)lid, msg);

    char *cp = strchr(text, '\n');
    if(cp)
        *cp = 0;
}

void history::add(shell::loglevel_t lid, const char *msg)
{
    history *reuse;

    // if no logging active, nothing to add...
    if(!histlimit)
        return;

    histlock.acquire();
    // if not to buffer limit, start by allocating
    // maybe we could use a pager heap....
    if(histcount < histlimit) {
        new history(lid, msg);
        histlock.release();
        return;
    }

    reuse = (history *)histindex.begin();
    reuse->delist(&histindex);
    reuse->set(lid, msg);
    reuse->enlist(&histindex);
    histlock.release();
}

void history::set(unsigned limit)
{
    history *reuse;

    histlock.acquire();
    while(histcount > limit) {
        reuse = (history *)histindex.begin();
        reuse->delist(&histindex);
        delete reuse;
    }
    histlimit = limit;
    histlock.release();
}

void history::out(void)
{
    if(!histlimit)
        return;

    FILE *fp = process::output("history");

    if(!fp)
        return;

    histlock.acquire();
    linked_pointer<history> hp = histindex.begin();
    while(is(hp)) {
        fprintf(fp, "%s\n", hp->text);
        hp.next();
    }
    histlock.release();
    fclose(fp);
}

END_NAMESPACE

