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
	rtp = NULL;
}

void stack::call::terminateLocked(void)
{
	if(state != INITIAL)
		state = TERMINATE;
	disconnectLocked();
}

void stack::call::joinLocked(session *join)
{
	linked_pointer<segment> sp = segments.begin();
	session *s;

	if(target)
		return;

	debug(2, "joining call %08x:%u with session %08x:%u",
		source->sequence, source->cid, join->sequence, join->cid);

	target = join;
	while(sp) {
		s = &(sp->sid);
		if(s != source && s != target) {
			if(s->reg) {
				s->reg->decUse();
				s->reg = NULL;
			}
			if(s->state == session::REFER)
				s->state = session::CLOSED;
			else if(s->cid > 0 && s->state != session::CLOSED) {
				s->state = session::CLOSED;
				eXosip_lock();
				eXosip_call_terminate(s->cid, s->did);
				eXosip_unlock();
			}
		}
		sp.next();
	}
	source->state = target->state = session::OPEN;
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
	case TRANSFER:
		reason = "transfer";
		break;
	case REDIRECT:
		reason = "redirect";
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
		if(sp->sid.state == session::REFER)
			sp->sid.state = session::CLOSED;
		else if(sp->sid.cid > 0 && sp->sid.state != session::CLOSED) {
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

void stack::call::bye(thread *thread, session *s)
{
	bool closing = false;

	Mutex::protect(this);
	s->tid = 0;	// cleared already....

	switch(state) {
	case JOINED:
	case ANSWERED:
	case HOLDING:
		if(s == source || s == target) {
			s->state = session::CLOSED;
			terminateLocked();
		}
		break;
	case TRYING:
	case RINGING:
	case RINGBACK:
		if(s == source) {
			s->state = session::CLOSED;
			disconnectLocked();
		}
		else
			closing = true;
		break;
	}
	Mutex::release(this);
	if(closing)
		stack::close(s);
}
		
void stack::call::ring(thread *thread, session *s)
{
	assert(thread != NULL);

	Mutex::protect(this);
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
	Mutex::release(this);
}

void stack::call::failed(thread *thread, session *s)
{
	assert(thread != NULL);

	Mutex::protect(this);
	switch(state) {
	case JOINED:
	case FINAL:
	case TERMINATE:
	case FAILED:
	case HOLDING:
		Mutex::release(this);
		return;
	}

	if(s->state == session::RING)
		--ringing;
	else if(s->state == session::BUSY)
		--ringbusy;
	else if(s->state == session::REFER)
		s->state = session::CLOSED;
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
	case ANSWERED:
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
	Mutex::release(this);
	stack::close(s);
}

void stack::call::reinvite(thread *thread, session *s)
{
	osip_message_t *reply = NULL;
	osip_body_t *body = NULL;
	int did;

	assert(thread != NULL);
	assert(s != NULL);

	Mutex::protect(this);
	s->did = thread->sevent->did;
	if(s == source) {
		if(target)
			did = target->did;
		else
			goto unconnected;
	}
	else
		did = source->did;

	s->tid = thread->sevent->tid;
	body = NULL;
	osip_message_get_body(thread->sevent->request, 0, &body);
	if(body && body->body)
		String::set(s->sdp, sizeof(s->sdp), body->body);

	switch(state) {
	case RINGING:
	case RINGBACK:
	case TRYING:
	case ANSWERED:
		if(s == source) {
unconnected:
			Mutex::release(this);
			eXosip_lock();
			eXosip_call_build_answer(source->tid, 500, &reply);
			if(reply != NULL) {
				osip_message_set_header(reply, "Reply-After", "8");
				stack::siplog(reply);
				eXosip_call_send_answer(source->tid, 500, reply);
			}
			eXosip_unlock();
			return;
		}
		if(state != ANSWERED && state != RINGBACK) {
			joinLocked(s);
			if(state != ANSWERED)
				state = RINGBACK;
		}
		time(&expires);
		expires += thread->header_expires;
		arm((timeout_t)(thread->header_expires * 1000l));
		Mutex::release(this);
		eXosip_lock();
		eXosip_call_build_answer(source->tid, 200, &reply);
		if(reply != NULL) {
			osip_message_set_require(reply, "100rel");
			osip_message_set_header(reply, "RSeq", "1");
			if(body && body->body) {
				osip_message_set_body(reply, body->body, strlen(body->body));
				osip_message_set_content_type(reply, "application/sdp");
			}
			stack::siplog(reply);
			eXosip_call_send_answer(source->tid, 200, reply);
		}
		eXosip_unlock();
		return;
	case HOLDING:
	case JOINED:
		state = JOINED;
		time(&expires);
		expires += thread->header_expires;
		arm((timeout_t)(thread->header_expires * 1000l));
		Mutex::release(this);
		eXosip_lock();
		eXosip_call_build_request(did, "INVITE", &reply);
		if(reply != NULL) {
			osip_message_set_supported(reply, "100rel,replaces");
			if(body && body->body) {
				osip_message_set_body(reply, body->body, strlen(body->body));
				osip_message_set_content_type(reply, "application/sdp");
			}
			stack::siplog(reply);
			eXosip_call_send_request(did, reply);
		}
		eXosip_unlock();
		return;
	}
	Mutex::release(this);
	debug(2, "reinvite failed for call %08x:%u",
			source->sequence, source->cid);
		failed(thread, s);
}
		
void stack::call::answer(thread *thread, session *s)
{
	osip_message_t *reply = NULL;
	osip_body_t *body = NULL;
	int did, tid;

	assert(thread != NULL);
	assert(s != NULL);

	Mutex::protect(this);
	if(s == source || (target != NULL && target != s)) {
		Mutex::release(this);
		debug(2, "cannot answer call %08x:%u from specified session", 
			source->sequence, source->cid);
		return;
	} 
	switch(state) {
	case RINGING:
	case RINGBACK:
	case TRYING:
		joinLocked(s);
		state = ANSWERED;
		arm(16000l);
	case ANSWERED:
		if(thread->sevent->did > -1)
			s->did = thread->sevent->did;
		tid = source->tid;
		break;
	case JOINED:
	case HOLDING:
		// if already joined, then we assume that the target ua never
		// saw the ack the originating ua had sent although we did, and 
		// so we resend it.
		if(thread->sevent->did > -1)
			s->did = thread->sevent->did;
		did = target->did;
		Mutex::release(this);
		eXosip_lock();
		eXosip_call_send_ack(did, NULL);
		eXosip_unlock();
		return;	
	default:
		Mutex::release(this);
		debug(2, "cannot answer non-ringing call %08x:%u",
			source->sequence, source->cid);
		return;
	}
	Mutex::release(this);	
	eXosip_lock();
	eXosip_call_build_answer(tid, SIP_OK, &reply);
	if(reply != NULL) {
		osip_message_set_body(reply, s->sdp, strlen(s->sdp));
		osip_message_set_content_type(reply, "application/sdp");
		stack::siplog(reply);
		eXosip_call_send_answer(tid, SIP_OK, reply);
		eXosip_unlock();
	}
	else {
		eXosip_unlock();
		debug(2, "answer failed for call %08x:%u",
			source->sequence, source->cid);
		failed(thread, source);
	}
}

void stack::call::message_reply(thread *thread, session *s)
{
	assert(thread != NULL);
	assert(s != NULL);

	int tid;
	osip_message_t *reply = NULL;

	Mutex::protect(this);
	tid = s->tid;
	Mutex::release(this);

	if(tid < 1)
		return;

	eXosip_lock();
	eXosip_call_send_answer(tid, thread->sevent->response->status_code, NULL);
	eXosip_unlock();
}


void stack::call::call_reply(thread *thread, session *s)
{
	assert(thread != NULL);
	assert(s != NULL);

	int tid;
	osip_body_t *body = NULL;
	osip_message_t *reply = NULL;

	Mutex::protect(this);
	tid = s->tid;
	Mutex::release(this);
	if(tid < 1)
		return;

	eXosip_lock();
	eXosip_call_build_answer(tid, thread->sevent->response->status_code, &reply);
	if(reply) {
		osip_message_set_require(reply, "100rel");
		osip_message_set_header(reply, "RSeq", "1");
		if(body && body->body) {
			osip_message_set_body(reply, body->body, strlen(body->body));
			osip_message_set_content_type(reply, "application/sdp");
		}
		eXosip_call_send_answer(tid, thread->sevent->response->status_code, reply);
	}
	eXosip_unlock();
}

void stack::call::confirm(thread *thread, session *s)
{
	assert(thread != NULL);
	assert(s != NULL);

	osip_message_t *ack = NULL;
	time_t now;
	int did;

	Mutex::protect(this);
	if(s != source || target == NULL) {
		Mutex::release(this);
		debug(2, "cannot confirm call %08x:%u from session %08x:%u\n", 
			source->sequence, source->cid, s->sequence, s->cid); 
		return;
	}
	switch(state)
	{
	case ANSWERED:
	case JOINED:
		state = JOINED;
		source->state = target->state = session::OPEN;
		if(thread->sevent->did > -1)
			s->did = thread->sevent->did;
		if(expires) {
			time(&now);
			arm((timeout_t)((expires - now) * 1000l));
		}
		else
			arm((timeout_t)DAY_TIMEOUT);
	case HOLDING:
		did = target->did;
		break;
	default:
		Mutex::release(this);
		debug(2, "cannot confirm unanswered call %08x:%u",
			source->sequence, source->cid);
		return;
	}
	Mutex::release(this);
	eXosip_lock();
	eXosip_call_build_ack(did, &ack);
	if(ack) {
		stack::siplog(ack);
		eXosip_call_send_ack(did, ack);
	}
	else {
		debug(2, "confirm failed to send for call %08x:%u",
			source->sequence, source->cid);
	}
	eXosip_unlock();
}

void stack::call::busy(thread *thread, session *s)
{
	assert(thread != NULL);

	Mutex::protect(this);
	switch(state) {
	case INITIAL:
		if(!s) {
			state = BUSY;
			disconnectLocked();
			Mutex::release(this);
			return;
		}
	case FINAL:
	case HOLDING:
	case JOINED:
	case ANSWERED:
	case FAILED:
		Mutex::release(this);
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
			disconnectLocked();
		}
	}

	Mutex::release(this);
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

	Mutex::protect(this);
	state = TRYING;
	arm(stack::ringTimeout());
	Mutex::release(this);
}

void stack::call::expired(void)
{
	linked_pointer<segment> sp;
	osip_message_t *reply = NULL;

	Mutex::protect(this);
	switch(state) {
	case TRANSFER:
	case HOLDING:	// hold-recall timer expired...

	case RINGING:	// re-generate ring event to origination...
			arm(stack::ringTimeout());	
			Mutex::release(this);
			reply_source(SIP_RINGING);
			return;
			
	case REDIRECT:	// FIXME: add refer select of next segment if list....
	
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
