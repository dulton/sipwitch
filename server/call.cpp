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
	arm(stack::resetTimeout());
	count = 0;
	fwdmask = 0;
	forwarding = FWD_IGNORE;
	invited = ringing = ringbusy = unreachable = 0;
	phone = false;
	expires = 0l;
	target = source = NULL;
	state = INITIAL;
	enlist(&stack::sip);
	starting = 0l;
}

void stack::call::disconnectLocked(void)
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

	state = FINAL;
	arm(stack::resetTimeout());
}

void stack::call::closingLocked(session *s)
{
	assert(s != NULL);

	if(invited) {
		switch(s->state)
		{
		case session::RING:
			--ringing;
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

	if(!invited)
		disconnectLocked();
}

void stack::call::busy(thread *thread)
{
	bool logging = false;
	bool sending = false;
	
	mutex::protect(this);
	if(state != INITIAL && state != BUSY)
		logging = true;
	if(state != BUSY)
		sending = true;
	state = BUSY;
	disarm();
	mutex::release(this);
	if(sending)
		thread->send_reply(SIP_BUSY_HERE);
	if(logging)
		stack::logCall("busy", source);
}

void stack::call::trying(thread *thread)
{
	// if we are in initial state, then send call trying, otherwise
	// turn-over state and set timer to wait for all invites to become
	// busy or one or more to start ringing...
	if(state == INITIAL)
		thread->send_reply(SIP_TRYING);

	mutex::protect(this);
	state = TRYING;
	arm(stack::ringTimeout());
	mutex::release(this);
}

void stack::call::expired(void)
{
	linked_pointer<segment> sp;
	osip_message_t *reply = NULL;

	Mutex::protect(this);
	switch(state) {
	case HOLDING:	// hold-recall timer expired...

	case RINGING:	// maybe ring-no-answer with forward? invite expired?
	case RINGBACK:
	case BUSY:		// invite expired
	case JOINED:	// active call session expired without re-invite
		if(experror != 0 && source != NULL && source->state != session::CLOSED)
			break;

	case REORDER:	// session recycled that is in reorder state
	case TRYING:	// session expired before any ringing or all bisy
	case FINAL:		// session expired that expects to be recycled.
	case INITIAL:	// never used session recycled.
		// The call record is garbage collected
		debug(4, "expiring call %08x:%u\n", source->sequence, source->cid);
		Mutex::release(this);
		stack::destroy(this);
		return;
	}

	if(experror && source) {
		debug(4, "suspending call %08x:%u, error=%d\n", source->sequence, source->cid, experror);
		// drop any active invites...
		stack::disjoin(this);

		// notify caller....
		eXosip_lock();
		eXosip_call_build_answer(source->tid, experror, &reply);
		stack::siplog(reply);
		eXosip_call_send_answer(source->tid, experror, reply);
		eXosip_unlock();
		experror = 0;
		state = REORDER;
	}

	Mutex::release(this);
}

END_NAMESPACE
