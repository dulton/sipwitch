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
	starting = ending = 0l;
	reason = joined = NULL;
}

void stack::call::terminateLocked(void)
{
	if(state != INITIAL)
		state = TERMINATE;
	disconnectLocked();
}

void stack::call::disconnectLocked(void)
{
	debug(4, "disconnecting call %08x:%u\n", source->sequence, source->cid);

	switch(state) {
	case RINGING:
	case RINGBACK:
		reason = "declined";
		reply_source(SIP_DECLINE);
		break;
	case REORDER:
		reason = "rejected";
		break;
	case BUSY:
		reason = "busy";
		reply_source(SIP_BUSY_HERE);
		break;
	case TRYING:
	case ANSWERED:
	case FAILED:
		reason = "failed";
		break;
	case JOINED:
		reason = "expired";
		break;
	case HOLDING:
	case TERMINATE:
		reason = "terminated";
		break;
	case INITIAL:
	case FINAL:
		break;
	}
		
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

	if(state != INITIAL && state != FINAL) {
		time(&ending);
		state = FINAL;
	}
	
	arm(stack::resetTimeout());
}

void stack::call::closingLocked(session *s)
{
	assert(s != NULL);

	if(invited)
		--invited;

	if(!invited)
		disconnectLocked();
}

void stack::call::reply_source(int error)
{
	osip_message_t *reply = NULL;
	eXosip_lock();
	eXosip_call_build_answer(source->tid, error, &reply);
	if(reply != NULL) {
		stack::siplog(reply);
		eXosip_call_send_answer(source->tid, error, reply);
	}
	else
		eXosip_call_send_answer(source->tid, SIP_BAD_REQUEST, NULL);
	eXosip_unlock();
}

void stack::call::ring(thread *thread, session *s)
{
	assert(thread != NULL);

	bool starting = false;

	mutex::protect(this);
	switch(state) {
	case TRYING:
	case INITIAL:
	case BUSY:	
		// we offset the first ring by 1 second because some servers
		// send a 180 immediately followed by a 200 because they do
		// artificial ringback within a connected session (asterisk for
		// example).  Also, we might get a 200 OK accept from another
		// invited ua, and so we do not want to start a partial ring
		// followed by a connect...
		state = RINGING;
		starting = true;
		arm(1000);
	case RINGING:
		if(s && s != source && s->state != session::RING) {
			++ringing;
			s->state = session::RING;
		}
		else if(!s)
			++ringing;
	default:
		break;
	}
	mutex::release(this);
}

void stack::call::failed(thread *thread, session *s)
{
	assert(thread != NULL);

	mutex::protect(this);
	switch(state) {
	case JOINED:
	case ANSWERED:
	case FINAL:
	case TERMINATE:
	case FAILED:
	case HOLDING:
		mutex::release(this);
		return;
	}

	if(s->state == session::RING)
		--ringing;
	else if(s->state == session::BUSY)
		--ringbusy;
	if(s->state != session::CLOSED)
		s->state = session::OPEN;

	switch(state) {
	case RINGING:
		if(!ringing && ringbusy)
			state = BUSY;
		else if(!ringing) {
			arm(stack::resetTimeout());
			state = FAILED;
		}
		break;
	case INITIAL:
		state = FAILED;	
		arm(stack::resetTimeout());
		break;
	case BUSY:
		if(!ringbusy) {
			state = FAILED;
			arm(stack::resetTimeout());
		}
	default:
		break;
	}
	mutex::release(this);
	stack::close(s);
}

void stack::call::answer(thread *thread, session *s)
{
}

void stack::call::confirm(thread *thread, session *s)
{
	assert(thread != NULL);
	assert(s != NULL);

	osip_message_t *ack = NULL;
	time_t now;

	mutex::protect(this);
	if(s != source) {
		debug(2, "cannot confirm call %08x:%u from session %08x:%u\n", 
			source->sequence, source->cid, s->sequence, s->cid); 
	}
	else if(state != ANSWERED && state != JOINED) {
		if(state != FINAL)
			debug(2, "cannot confirm unaswered call %08x:%u\n",
				source->sequence, source->cid);
	}
	else if(target && target->state != session::CLOSED && source->state != session::CLOSED) {
		eXosip_lock();
		eXosip_call_build_ack(target->did, &ack);
		if(ack) {
			state = JOINED;
			stack::siplog(ack);
			eXosip_call_send_ack(target->did, ack);
		}
		else {
			debug(2, "confirm failed for call %08x:%u",
				source->sequence, source->cid);
		}
		eXosip_unlock();
	}
	else {
		debug(2, "failed confirming call %08x:%u",
			source->sequence, source->cid);
		state = FAILED;
		disconnectLocked();
	}
	if(state == JOINED) {
		source->state = target->state = session::OPEN;
		if(thread->sevent->did > -1)
			s->did = thread->sevent->did;
		if(expires) {
			time(&now);
			arm((timeout_t)((expires - now) * 1000l));
		}
		else
			arm((timeout_t)DAY_TIMEOUT);
	}
	mutex::release(this);
}

void stack::call::busy(thread *thread, session *s)
{
	assert(thread != NULL);

	mutex::protect(this);
	switch(state) {
	case FINAL:
	case HOLDING:
	case JOINED:
	case ANSWERED:
	case FAILED:
		mutex::release(this);
		return;
	}
	
	if(s && s != source) {
		if(s->state == session::RING)
			--ringing;
		if(s->state != session::BUSY) {
			++ringbusy;
			s->state = session::BUSY;
		}
	}
	else if(!s)
		++ringbusy;

	switch(state) {
	case INITIAL:
	case RINGING:
	case RINGBACK:
		if(!ringing && ringbusy) {
			state = BUSY;
			disarm();
		}
	}

	mutex::release(this);
	if(s)
		stack::close(s);
	else 
		stack::close(source);
}

void stack::call::trying(thread *thread)
{
	// if we are in initial state, then send call trying, otherwise
	// turn-over state and set timer to wait for all invites to become
	// busy or one or more to start ringing...
	//
	if(state == INITIAL) 
		// we cannot reply_source because build always fails!
		eXosip_call_send_answer(source->tid, SIP_TRYING, NULL);

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

	case RINGING:	// re-generate ring event to origination...
			arm(stack::ringTimeout());	
			mutex::release(this);
			reply_source(SIP_RINGING);
			return;
			
	case RINGBACK:
	case BUSY:		// invite expired
	case JOINED:	// active call session expired without re-invite
	case ANSWERED:	
	case REORDER:
	case TRYING:
	case FAILED:
			disconnectLocked();
			break;
	case FINAL:		// session expired that expects to be recycled.
	case INITIAL:	// never used session recycled.
		// The call record is garbage collected
		debug(4, "expiring call %08x:%u\n", source->sequence, source->cid);
		Mutex::release(this);
		stack::destroy(this);
		return;
	}

	Mutex::release(this);
}

void stack::call::log(void)
{
	struct tm *dt;
	call *cr;

	if(!reason)
		return;

	if(!starting)
		return;

	if(!ending)
		time(&ending);

	if(!joined && target)
		joined = target->sysident;

	if(!joined)
		joined = "n/a";

	dt = localtime(&starting);

	process::printlog("call %08x:%u %s %04d-%02d-%02d %02d:%02d:%02d %ld %s %s %s %s\n",
		source->sequence, source->cid, reason,
		dt->tm_year + 1900, dt->tm_mon + 1, dt->tm_mday,
		dt->tm_hour, dt->tm_min, dt->tm_sec, ending - starting,
		source->sysident, dialed, joined, source->display);		
	
	starting = 0l;
}


END_NAMESPACE
