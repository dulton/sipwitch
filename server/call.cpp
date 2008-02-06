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

#include "server.h"

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

stack::call::call() : TimerQueue::event(Timer::reset), segments()
{
}

void stack::call::disconnect(void)
{
	debug(4, "disconnecting call %08x:%u\n", source->sequence, source->cid);

	linked_pointer<segment> sp = segments.begin();
	while(sp) {
		if(sp->sid.reg) {
			sp->sid.reg->decUse();
			sp->sid.reg = NULL;
		}
		if(sp->sid.cid > 0 && sp->sid.state != session::CLOSED) {
			sp->sid.state = session::CLOSED;
			eXosip_lock();
			eXosip_call_terminate(sp->sid.cid, sp->sid.did);
			eXosip_unlock();
		}
		sp.next();
	}

	if(state != INITIAL) {
		state = FINAL;
		set((timeout_t)7000);
		update();
	}
}

void stack::call::closing(session *s)
{
	assert(s != NULL);

	if(invited) {
		switch(s->state)
		{
		case session::RING:
			--ringing;
			break;
		case session::FWD:
			--forwarding;
			break;
		case session::BUSY:
			--ringbusy;
			break;
		case session::REORDER:
			--unreachable;
			break;
		default:
			break;
		}
		--invited;
	}

	if(invited) {
		update();
		return;
	}

	disconnect();
}

void stack::call::update(void)
{
	// TODO: switch by call state to see if we send reply code!
	if(state == INITIAL) {
		// if(forwarding && invited - unreachable - ringbusy == forwarding)
		// else if(ringing && invited - unreachable - ringbusy == ringing + forwarding)...
		// else if(ringbusy && invited - unreachable == ringbusy) ...
		// else if(invited == unreachable) ...
	}
}

void stack::call::expired(void)
{
	linked_pointer<segment> sp;
	osip_message_t *reply = NULL;

	mutex::protect(this);
	switch(state) {
	case HOLDING:	// hold-recall timer expired...

	case RINGING:	// maybe ring-no-answer with forward? invite expired?
	case BUSY:		// invite expired
	case ACTIVE:	// active call session expired without re-invite
		if(experror != 0 && source != NULL && source->state != session::CLOSED)
			break;

	case FINAL:		// session expects to be cleared....
	case REORDER:	// only different in logging
	case TRYING:	// gateway trying attempt, waiting for 183...

					// TODO: initial may have special case if pending!!!
	case INITIAL:	// if session never used, garbage collect at expire...
		debug(4, "expiring call %08x:%u\n", source->sequence, source->cid);
		mutex::release(this);
		stack::destroy(this);
		return;
	}

	if(experror && source) {
		debug(4, "suspending call %08x:%u, error=%d\n", source->sequence, source->cid, experror);
		// drop any active invites...
		stack::disjoin(this);

		// notify caller....
		eXosip_call_send_answer(source->tid, experror, NULL);
		experror = 0;
		state = REORDER;
	}

	mutex::release(this);
}

END_NAMESPACE
