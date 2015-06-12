// Copyright (C) 2006-2014 David Sugar, Tycho Softworks.
// Copyright (C) 2015 Cherokees of Idaho.
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

namespace sipwitch {

static volatile unsigned allocated_segments = 0;
static volatile unsigned active_segments = 0;
static volatile unsigned allocated_calls = 0;
static volatile unsigned allocated_maps = 0;
static volatile unsigned active_calls = 0;
static unsigned mapped_calls = 0;
static LinkedObject *freesegs = NULL;
static LinkedObject *freecalls = NULL;
static LinkedObject *freemaps = NULL;
static LinkedObject **hash = NULL;
static unsigned keysize = 177;
static condlock_t locking;
static mutex_t mapping;

stack::background *stack::background::thread = NULL;

static bool tobool(const char *s)
{
    assert(s != NULL);

    switch(*s)
    {
    case 'n':
    case 'N':
    case 'f':
    case 'F':
    case '0':
        return false;
    }
    return true;
}

stack stack::sip;

static const char *ifaddr(const char *addr, const char *id)
{
    if(eq(id, "any") || eq(id, "world") || eq(id, "nat"))
        return "0.0.0.0/0";

    return addr;
}

stack::subnet::subnet(cidr::policy **acl, const char *addr, const char *id) :
cidr(acl, ifaddr(addr, id), id)
{
    union {
        struct sockaddr_storage dest;
        struct sockaddr_in in;
#ifdef  AF_INET6
        struct sockaddr_in6 in6;
#endif
    } us;

    unsigned char *lp;
    unsigned bits = getMask();
    char buf[256];

    active = true;
    String::set(netname, sizeof(netname), id);

    shell::log(DEBUG3, "adding policy %s for %s", id, addr);

    if(eq(id, "world") || eq(id, "any") || eq(id, "nat")) {
        if(eq(id, "nat") || eq(id, "any"))
            String::set(netname, sizeof(netname), "*");

        if(eq(id, "nat"))
            service::publish(addr);

        Socket::address ifs(addr, sip_port);
        Socket::store(&iface, ifs.getAddr());
        return;
    }

    memset(&us.dest, 0, sizeof(us.dest));
    us.in.sin_family = Family;
    switch(Family) {
    case AF_INET:
        us.in.sin_port = htons(1);
        memcpy(&us.in.sin_addr, &Network, sizeof(us.in.sin_addr));
        lp = ((unsigned char *)(&us.in.sin_addr)) + sizeof(us.in.sin_addr) - 1;
        if(bits < 31)
            ++*lp;
        break;
#ifdef  AF_INET6
    case AF_INET6:
        us.in6.sin6_port = htons(1);
        memcpy(&us.in6.sin6_addr, &Network, sizeof(us.in6.sin6_addr));
        lp = ((unsigned char *)(&us.in6.sin6_addr)) + sizeof(us.in6.sin6_addr) - 1;
        if(bits < 127)
            ++*lp;
        break;
#endif
    default:
        return;
    }
    Socket::query((struct sockaddr *)&us.dest, buf, sizeof(buf));

    if(Socket::via((struct sockaddr *)&iface, (struct sockaddr *)&us.dest))
        memset(&iface, 0, sizeof(iface));
    // gateway special rule to specify a gateway public interface...
    else if(eq(id, "gateway")) {
        String::set(netname, sizeof(netname), "*");
        Socket::query((struct sockaddr *)&iface, buf, sizeof(buf));
        service::publish(buf);
    }
    // if interface outside cidr...?
    else if(!is_member((struct sockaddr *)&iface)) {
        String::set(netname, sizeof(netname), "*");
        service::published(&iface);
    }
}

stack::segment::segment(voip::context_t context, call *cr, int cid, int did, int tid) : OrderedObject()
{
    assert(cr != NULL);
    assert(cid > 0);

    time_t now;

    if(!context)
        context = stack::sip.out_context;

    ++cr->count;
    time(&now);
    enlist(&(cr->segments));
    sid.context = context;
    sid.enlist(&hash[cid % keysize]);
    sid.sequence = (uint32_t)now;
    sid.sequence &= 0xffffffffl;
    sid.expires = 0l;
    sid.nat = NULL;
    sid.cid = cid;
    sid.did = did;
    sid.tid = tid;
    sid.parent = cr;
    sid.state = session::OPEN;
    sid.sdp[0] = 0;
    sid.reg = NULL;
    sid.closed = false;

    secure::uuid(sid.uuid);
}

void *stack::segment::operator new(size_t size)
{
    assert(size == sizeof(stack::segment));

    return server::allocate(size, &freesegs, &allocated_segments);
}

void stack::segment::operator delete(void *obj)
{
    assert(obj != NULL);

    ((LinkedObject*)(obj))->enlist(&freesegs);
}

void *stack::call::operator new(size_t size)
{
    assert(size == sizeof(stack::call));

    ++active_calls;
    return server::allocate(size, &freecalls, &allocated_calls);
}

void stack::call::operator delete(void *obj)
{
    assert(obj != NULL);

    ((LinkedObject*)(obj))->enlist(&freecalls);
    --active_calls;
}

stack::background::background(timeout_t iv) : DetachedThread(), Conditional(), expires(Timer::inf)
{
    cancelled = false;
    signalled = false;
    interval = iv;
}

void stack::background::create(timeout_t iv)
{
    thread = new background(iv);
    thread->start();
}

void stack::background::cancel(void)
{
    thread->Conditional::lock();
    thread->cancelled = true;
    thread->Conditional::signal();
    thread->Conditional::unlock();
}

void stack::background::notify(void)
{
    thread->Conditional::lock();
    thread->signalled = true;
    thread->Conditional::signal();
    thread->Conditional::unlock();
}

void stack::background::run(void)
{
    shell::log(DEBUG1, "starting background thread");
    timeout_t timeout, current;
    Timer expiration = interval;
    time_t then = 0, now;
    stack::call *next;
    time_t period = 10;

    time(&then);
    then /= period;

    for(;;) {
        Conditional::lock();
        if(cancelled) {
            Conditional::unlock();
            shell::log(DEBUG1, "stopping background thread");
            thread = NULL;
            return; // exits thread...
        }
        timeout = expiration.get();
        if(!signalled && timeout) {
            if(timeout > interval)
                timeout = interval;
            Conditional::wait(timeout);
        }
        timeout = expiration.get();
        if(signalled || !timeout) {
            signalled = false;
            // release lock in case expire calls update timer methods...
            Conditional::unlock();
            timeout = interval;
            locking.access();
            linked_pointer<stack::call> cp = stack::sip.begin();
            while(cp) {
                next = (stack::call *)cp->getNext();
                current = cp->getTimeout();
                if(current && current < timeout)
                    timeout = current;
                cp = next;
            }
            locking.release();
            expiration = timeout;
        }
        else {
            signalled = false;
            Conditional::unlock();
        }
        time(&now);
        now /= period;
        if(now > then) {
            then = now;
            unsigned released = registry::cleanup(period);
            if(released)
                shell::debug(9, "registry cleanup; %d expired", released);
            else
                shell::debug(9, "registry cleanup; no entries expired");
        }
        messages::automatic();
    }
}

stack::stack() :
service::callback(1), mapped_array<MappedCall>(), OrderedIndex()
{
    stacksize = 0;
    threading = 2;
    priority = 1;
    timing = 500;
    iface = NULL;
    send101 = 1;
    dumping = false;
    incoming = false;
    outgoing = false;
    agent = "sipwitch-" VERSION "/eXosip";
    system = "sipwitch";
    anon = "anonymous";
    restricted = trusted = published = proxy = NULL;
    localnames = "localhost, localhost.localdomain";
    ring_timer = 4000;
    cfna_timer = 16000;
    reset_timer = 6000;
    invite_expires = 120;
}

void stack::release(void)
{
    LinkedObject::release();
}

void stack::disableDumping(void)
{
    stack::sip.dumping = false;
}

void stack::clearDumping(void)
{
    ::remove(DEFAULT_VARPATH "/log/sipdump.log");
    ::remove(_STR(control::path("controls") + "/sipdump.log"));
}

void stack::enableDumping(void)
{
    clearDumping();
    stack::sip.dumping = true;
}

void stack::siplog(voip::msg_t msg)
{
    fsys_t log;
    char *text = NULL;
    size_t tlen;

    if(!msg || !stack::sip.dumping)
        return;

    osip_message_to_str(msg, &text, &tlen);
    if(text) {
        log.open(control::env("siplogs"), fsys::GROUP_PRIVATE, fsys::APPEND);
        if(is(log)) {
            Mutex::protect(&stack::sip.dumping);
            log.write(text, tlen);
            log.write("---\n\n", 5);
            Mutex::release(&stack::sip.dumping);
            log.close();
        }
        osip_free(text);
    }
}

void stack::close(session *s)
{
    assert(s != NULL);

    call *cr;

    if(!s)
        return;

    cr = s->parent;

    if(!s->closed) {
        if(s == cr->source)
            registry::decUse(s->reg, stats::INCOMING);
        else
            registry::decUse(s->reg, stats::OUTGOING);
        s->closed = true;
    }

    Mutex::protect(cr);
    if(s->state != session::CLOSED) {
        s->state = session::CLOSED;
        if(s == cr->source)
            cr->terminateLocked();
        else
            cr->closingLocked(s);
    }
    Mutex::release(cr);
}

void stack::clear(session *s)
{
    assert(s != NULL);

    call *cr;

    if(!s)
        return;

    cr = s->parent;

    if(!s->closed) {
        if(s == cr->source)
            registry::decUse(s->reg, stats::INCOMING);
        else
            registry::decUse(s->reg, stats::OUTGOING);
        s->closed = true;
    }

    Mutex::protect(cr);

    if(--cr->count == 0) {
        shell::debug(4, "clearing call %08x:%u\n",
            cr->source->sequence, cr->source->cid);
        Mutex::release(cr);
        destroy(cr);
        return;
    }

    if(s->cid > 0) {
        Mutex::release(cr);
        locking.exclusive();
        shell::debug(4, "clearing call %08x:%u session %08x:%u\n",
            cr->source->sequence, cr->source->cid, s->sequence, s->cid);
        if(s->state != session::CLOSED) {
            s->state = session::CLOSED;
            voip::release_call(s->context, s->cid, s->did);
        }
        s->delist(&hash[s->cid % keysize]);
        s->cid = 0;
        s->did = -1;
        locking.share();
    }
    else
        Mutex::release(cr);
}

void stack::destroy(session *s)
{
    assert(s != NULL);

    if(!s || !s->parent)
        return;

    destroy(s->parent);
}

void stack::setDialog(session *s, voip::did_t did)
{
    assert(s != NULL && s->parent != NULL);
    Mutex::protect(s->parent);
    s->did = did;
    Mutex::release(s->parent);
}

int stack::getDialog(session *s)
{
    voip::did_t did = -1;

    if(s && s->parent) {
        Mutex::protect(s->parent);
        did = s->did;
        Mutex::release(s->parent);
    }
    return did;
}

void stack::refer(session *source, voip::event_t sevent)
{
    assert(source);
    assert(sevent);

    voip::hdr_t header = NULL;
    voip::msg_t msg = NULL;
    session *target = NULL;
    call *cr = source->parent;
    voip::did_t did;

    if(cr->source == source)
        target = cr->target;
    else if(cr->target == source)
        target = cr->source;

    osip_message_header_get_byname(sevent->request, "Refer-To", 0, &header);
    if(!header || !header->hvalue)
        goto failed;

    did = getDialog(target);
    if(did < 1)
        goto failed;

    if(!voip::make_dialog_refer(target->context, did, header->hvalue, &msg)) {
failed:
        voip::send_answer_response(source->context, sevent->tid, SIP_SERVICE_UNAVAILABLE, NULL);
        return;
    }
    voip::server_allows(msg);
    voip::header(msg, "Referred-By", source->identity);
    voip::send_dialog_message(target->context, did, msg);
    target->state = session::REFER;
    target->tid = sevent->tid;
}

void stack::infomsg(session *source, voip::event_t sevent)
{
    assert(source);
    assert(sevent);

    char type[128];
    voip::ctype_t ct;
    voip::msg_t msg = NULL;
    voip::body_t body = NULL;
    session *target = NULL;
    call *cr = source->parent;

    if(cr->source == source)
        target = cr->target;
    else if(cr->target == source)
        target = cr->source;

    voip::did_t did = getDialog(target);
    if(did < 1)
        return;

    ct = sevent->request->content_type;
    if(!ct || !ct->type)
        return;

    osip_message_get_body(sevent->request, 0, &body);
    if(!voip::make_dialog_info(target->context, did, &msg))
        return;
    if(ct->subtype)
        snprintf(type, sizeof(type), "%s/%s", ct->type, ct->subtype);
    else
        snprintf(type, sizeof(type), "%s", ct->type);
    voip::attach(msg, type, body->body);
    voip::server_allows(msg);
    voip::send_dialog_message(target->context, did, msg);
}

void stack::disjoin(call *cr)
{
    assert(cr != NULL);

    linked_pointer<segment> sp = cr->segments.begin();
    while(sp) {
        session *s = sp->get();
        if(s != cr->source) {
            if(!s->closed) {
                registry::decUse(s->reg, stats::OUTGOING);
                s->closed = true;
            }
            if(s->cid > 0 && s->state != session::CLOSED) {
                voip::release_call(s->context, s->cid, s->did);
                s->state = session::CLOSED;
            }
        }
        sp.next();
    }
}

void stack::destroy(call *cr)
{
    assert(cr != NULL);
    MappedCall *map;

    linked_pointer<segment> sp;

    cdr *clog = cr->log();

    // we assume access lock was already held when we call this...

    locking.exclusive();
    sp = cr->segments.begin();
    while(sp) {
        --active_segments;
        segment *next = sp.getNext();

        if(!sp->sid.closed) {
            if(&(sp->sid) == cr->source)
                registry::decUse(sp->sid.reg, stats::INCOMING);
            else
                registry::decUse(sp->sid.reg, stats::OUTGOING);
            sp->sid.closed = true;
        }

        if(sp->sid.cid > 0) {
            if(sp->sid.state != session::CLOSED) {
                voip::release_call(sp->sid.context, sp->sid.cid, sp->sid.did);
            }
            sp->sid.delist(&hash[sp->sid.cid % keysize]);
        }
        if(sp->sid.nat)
            media::release(&sp->sid.nat);
        delete *sp;
        sp = next;
    }
    map = cr->map;
    cr->delist();
    delete cr;
    locking.share();
    release(map);
    if(clog)
        cdr::post(clog);
}

void stack::release(MappedCall *map)
{
    if(map) {
        String::set(map->state, sizeof(map->state), "-");
        map->created = map->active = 0;
        mapping.lock();
        map->enlist(&freemaps);
        mapping.release();
    }
}

MappedCall *stack::get(void)
{
    MappedCall *map = NULL;

    mapping.lock();
    if(freemaps) {
        map = (MappedCall *)freemaps;
        freemaps = map->getNext();
    }
    else if(allocated_maps < mapped_calls)
        map = sip(allocated_maps++);
    mapping.release();
    if(!map)
        return NULL;

    String::set(map->state, sizeof(map->state), "iinit");
    map->active = 0;
    map->authorized[0] = 0;
    map->source[0] = 0;
    map->target[0] = 0;

    time(&map->created);
    return map;
}

void stack::getInterface(struct sockaddr *iface, struct sockaddr *dest)
{
    assert(iface != NULL && dest != NULL);

    Socket::via(iface, dest);
    switch(iface->sa_family) {
    case AF_INET:
        ((struct sockaddr_in*)(iface))->sin_port = htons(sip_port);
        break;
#ifdef  AF_INET6
    case AF_INET6:
        ((struct sockaddr_in6*)(iface))->sin6_port = htons(sip_port);
        break;
#endif
    }
}

stack::session *stack::create(voip::context_t context, call *cr, voip::call_t cid)
{
    assert(cr != NULL);
    assert(cid > 0);

    locking.exclusive();
    segment *sp = new segment(context, cr, cid);
    ++cr->invited;
    locking.share();
    return &sp->sid;
}

stack::session *stack::create(voip::context_t context, voip::call_t cid, voip::did_t did, voip::tid_t tid)
{
    assert(cid > 0);

    MappedCall *map = get();

    if(!map)
        return NULL;

    call *cr;
    segment *sp;

    locking.modify();
    cr = new call;
    sp = new segment(context, cr, cid, did, tid);    // after count set to 0!
    cr->source = &(sp->sid);
    cr->map = map;

    locking.share();
    return cr->source;
}

stack::session *stack::access(voip::call_t cid)
{
    assert(cid > 0);

    linked_pointer<session> sp;

    locking.access();
    sp = hash[cid % keysize];
    while(sp) {
        if(sp->cid == cid)
            break;
        sp.next();
    }
    if(!sp) {
        locking.release();
        return NULL;
    }
    return *sp;
}

void stack::detach(session *s)
{
    if(s)
        locking.release();
}

void stack::start(service *cfg)
{
    assert(cfg != NULL);

#ifdef  EXOSIP_API4
    unsigned ver = 4;
#else
    unsigned ver = 3;
#endif

    if(!iface && sip_iface)
        iface = sip_iface;

    thread *thr;
    shell::log(DEBUG1, "starting sip stack v%d; %d maps", ver, mapped_calls);

    mapped_array<MappedCall>::create(control::env("callmap"), mapped_calls);
    if(!sip)
        shell::log(shell::FAIL, "calls could not be mapped");
    initialize();

#ifdef  HAVE_TLS
    if(sip_tlsmode) {
        eXosip_tls_ctx_t ctx;
        int ctx_error;

        memset(&ctx, 0, sizeof(ctx));
        String::set(ctx.random_file, sizeof(ctx.random_file),
            sip_tlsdev);
        String::set(ctx.dh_param, sizeof(ctx.dh_param),
            sip_tlsdh);
        String::set(ctx.root_ca_cert, sizeof(ctx.root_ca_cert),
            sip_tlsca);
        String::set(ctx.server.cert, sizeof(ctx.server.cert),
            sip_tlscert);
        String::set(ctx.server.priv_key, sizeof(ctx.server.priv_key),
            sip_tlskey);
        String::set(ctx.server.priv_key_pw, sizeof(ctx.server.priv_key_pw),
            sip_tlspwd);
        if ((ctx_error = eXosip_set_tls_ctx(&ctx)) != TLS_OK)
            shell::log(shell::FAIL,
                "sip set tls credentials failed %i", ctx_error);
    }
#endif

#if UCOMMON_ABI > 5
    Socket::query(sip_family);
#else
    Socket::family(sip_family);
#endif
    osip_trace_initialize_syslog(TRACE_LEVEL0, (char *)"sipwitch");

    if(sip_protocol == IPPROTO_TCP) {
        voip::create(&tcp_context, agent, sip_family);
        voip::create(&udp_context, agent, sip_family);
        out_context = tcp_context;
    }
    else {
        voip::create(&udp_context, agent, sip_family);
        voip::create(&tcp_context, agent, sip_family);
        out_context = udp_context;
    }

#ifdef  HAVE_TLS
    voip::create(&tls_context, agent, family);
#endif

#if defined(EXOSIP2_OPTION_SEND_101) && !defined(EXOSIP_API4)
    eXosip_set_option(EXOSIP_OPT_DONT_SEND_101, &send101);
#endif

    threading = 0;
    if(udp_context) {
        ++threading;
        if(!voip::listen(udp_context, IPPROTO_UDP, iface, sip_port))
            shell::log(shell::FAIL, "cannot listen port %u for udp", sip_port);
        else
            shell::log(shell::NOTIFY, "listening port %u for udp", sip_port);
        thr = new thread(udp_context, "udp");
        thr->start(priority);
    }

    if(tcp_context) {
        ++threading;
        if(!voip::listen(tcp_context, IPPROTO_TCP, iface, sip_port))
            shell::log(shell::FAIL, "cannot listen port %u for tcp", sip_port);
        shell::log(shell::NOTIFY, "listening port %u for tcp", sip_port);
        thr = new thread(tcp_context, "tcp");
        thr->start(priority);

    }

    if(tls_context) {
        ++threading;
        if(!voip::listen(tls_context, IPPROTO_TCP, iface, sip_port, true))
            shell::log(shell::FAIL, "cannot listen port %u for tls", sip_port + 1);
        shell::log(shell::NOTIFY, "listening port %u for tls", sip_port + 1);
        thr = new thread(tls_context, "tls");
        thr->start(priority);
    }

    thread::wait(threading);
    background::create(timing);
}

void stack::stop(service *cfg)
{
    assert(cfg != NULL);

    shell::log(DEBUG1, "stopping sip stack");
    background::cancel();
    thread::shutdown();
    Thread::yield();
    MappedMemory::release();
    MappedMemory::remove(control::env("callmap"));
}

bool stack::check(void)
{
    if(tcp_context) {
        shell::log(shell::INFO, "checking tcp context...");
        voip::lock(tcp_context);
        voip::unlock(tcp_context);
    }
    if(udp_context) {
        shell::log(shell::INFO, "checking udp context...");
        voip::lock(udp_context);
        voip::unlock(udp_context);
    }
    if(tls_context) {
        shell::log(shell::INFO, "checking tls context...");
        voip::lock(tls_context);
        voip::unlock(tls_context);
    }
    return true;
}

void stack::snapshot(FILE *fp)
{
    assert(fp != NULL);

    linked_pointer<call> cp;
    fprintf(fp, "SIP:\n");
    locking.access();
    fprintf(fp, "  mapped calls: %d\n", mapped_calls);
    fprintf(fp, "  active calls: %d\n", active_calls);
    fprintf(fp, "  active sessions: %d\n", active_segments);
    fprintf(fp, "  allocated calls: %d\n", allocated_calls);
    fprintf(fp, "  allocated sessions: %d\n", allocated_segments);
    cp = begin();
    while(cp) {
        cp.next();
    }
    locking.release();
}

void stack::reload(service *cfg)
{
    assert(cfg != NULL);

    const char *new_proxy = NULL;
    const char *key = NULL, *value;
    linked_pointer<service::keynode> sp = cfg->getList("stack");
    linked_pointer<service::keynode> tp = cfg->getList("timers");
    int val;
    const char *localhosts = "localhost, localhost.localdomain";

    unsigned cfna_value = 0;
    unsigned ring_value = 0;
    unsigned reset_value = 0;

    char buf[256];
    if(!gethostname(buf, sizeof(buf))) {
        String::add(buf, sizeof(buf), ", localhost, localhost.localdomainb");
        localhosts = buf;
    }

    sip_domain = registry::getDomain();

    while(sp) {
        key = sp->getId();
        value = sp->getPointer();
        if(key && value) {
            if(eq(key, "threading") && !is_configured())
                threading = atoi(value);
            else if(eq(key, "priority") && !is_configured())
                priority = atoi(value);
            else if(eq(key, "timing"))
                timing = atoi(value);
            else if(eq(key, "incoming"))
                incoming = tobool(value);
            else if(eq(key, "outgoing"))
                outgoing = tobool(value);
            else if(eq(key, "trace") || eq(key, "dumping"))
                dumping = tobool(value);
            else if(eq(key, "keysize") && !is_configured())
                keysize = atoi(value);
            else if(eq(key, "interface") && !is_configured()) {
                sip_family = AF_INET;
                sip_iface = NULL;
#ifdef  AF_INET6
                if(strchr(value, ':') != NULL)
                    sip_family = AF_INET6;
#endif
                if(eq(value, ":::") || eq(value, "::0") || eq(value, "::*") || eq(value, "*") || eq(value, "0.0.0.0") || !*value)
                    value = NULL;
                if(value)
                    value = strdup(value);
                sip_iface = value;
            }
            else if(eq(key, "send101") && !is_configured() && tobool(value))
                send101 = 0;
            else if(eq(key, "keepalive") && !is_configured()) {
                val = atoi(value);
                voip::option(udp_context, EXOSIP_OPT_UDP_KEEP_ALIVE, &val);
            }
            else if(eq(key, "learn") && !is_configured()) {
                val = tobool(value);
                voip::option(udp_context, EXOSIP_OPT_UDP_LEARN_PORT, &val);
            }
            else if(eq(key, "restricted")) {
                if(eq(value, "none"))
                    restricted = NULL;
                else
                    restricted = cfg->dup(value);
            }
            else if(eq(key, "localnames"))
                localhosts = cfg->dup(value);
            else if(eq(key, "trusted")) {
                if(eq(value, "none"))
                    trusted = NULL;
                else
                    trusted = cfg->dup(value);
            }
            else if(eq(key, "system"))
                system = value;
            else if(eq(key, "anon"))
                anon = value;
            else if(eq(key, "contact"))
                cfg->setContact(value);
            else if(eq(key, "published") || eq(key, "public"))
                published = cfg->dup(value);
            else if(eq(key, "peering") || eq(key, "gateway"))
                service::publish(value);
            else if(eq(key, "proxy") || eq(key, "outbound"))
                new_proxy = cfg->dup(value);
            else if(eq(key, "agent") && !is_configured())
                agent = value;
            else if(eq(key, "port") && !is_configured())
                sip_port = atoi(value);
            else if(eq(key, "mapped") && !is_configured())
                mapped_calls = atoi(value);
            else if(eq(key, "password") && !is_configured())
                sip_tlspwd = strdup(value);
            else if(eq(key, "keyfile") && !is_configured())
                sip_tlskey = strdup(value);
            else if(eq(key, "random") && !is_configured())
                sip_tlsdev = strdup(value);
            else if(eq(key, "certfile") && !is_configured())
                sip_tlscert = strdup(value);
            else if(eq(key, "dhfile") && !is_configured())
                sip_tlsdh = strdup(value);
            else if(eq(key, "authfile") && !is_configured())
                sip_tlsca = strdup(value);
            else if(eq(key, "transport") && !is_configured()) {
                if(eq(value, "tcp") || eq(value, "tls"))
                    sip_protocol = IPPROTO_TCP;
                if(eq(value, "tls"))
                    sip_tlsmode = 1;
            }
        }
        sp.next();
    }

    while(is(tp)) {
        key = tp->getId();
        value = tp->getPointer();
        if(key && value) {
            if(eq(key, "ring"))
                ring_value = atoi(value);
            else if(eq(key, "cfna"))
                cfna_value = atoi(value);
            else if(eq(key, "reset"))
                reset_value = atoi(value);
            else if(eq(key, "invite"))
                invite_expires = atoi(value);
        }
        tp.next();
    }

    localnames = localhosts;
    proxy = new_proxy;

    if(sip_family != AF_INET)
        media::enableIPV6();

    if(ring_value && ring_value < 100)
        ring_timer = ring_value * 1000l;
    else if(ring_value >= 100)
        ring_timer = ring_value;

    if(cfna_value && cfna_value < 1000)
            cfna_timer = ring_timer *cfna_value;
    else if(cfna_value >= 1000)
        cfna_timer = cfna_value;

    if(reset_value && reset_value < 100)
        reset_timer = reset_value * 1000l;
    else if(reset_value >= 100)
        reset_timer = reset_value;

    if(!mapped_calls)
        mapped_calls = registry::getEntries();
    if(!hash) {
        hash = new LinkedObject*[keysize];
        memset(hash, 0, sizeof(LinkedObject *) * keysize);
    }
}

const char *stack::getScheme(void)
{
    if(sip_tlsmode)
        return "sips";
    return "sip";
}

char *stack::sipPublish(struct sockaddr_internet *addr, char *buf, const char *user, size_t size)
{
    assert(addr != NULL);
    assert(buf != NULL);
    assert(user == NULL || *user != 0);
    assert(size > 0);

    char pbuf[10];
    bool ipv6 = false;

    if(sip.published == NULL)
        return sipAddress(addr, buf, user, size);

    if(sip_tlsmode)
        String::set(buf, size, "sips:");
    else
        String::set(buf, size, "sip:");

    if(strchr(sip.published, ':'))
        ipv6 = true;

    if(user) {
        String::add(buf, size, user);
        if(ipv6)
            String::add(buf, size, "@[");
        else
            String::add(buf, size, "@");
    }
    else if(ipv6)
        String::add(buf, size, "[");

    String::add(buf, size, sip.published);
    if(ipv6)
        snprintf(pbuf, sizeof(pbuf), "]:%u", sip_port);
    else
        snprintf(pbuf, sizeof(pbuf), ":%u", sip_port);
    String::add(buf, size, pbuf);
    return buf;
}

char *stack::sipAddress(struct sockaddr_internet *addr, char *buf, const char *user, size_t size)
{
    assert(addr != NULL);
    assert(buf != NULL);
    assert(user == NULL || *user != 0);
    assert(size > 0);

    char pbuf[10];
    unsigned port = 0;
    bool ipv6 = false;
    const char *defaddr = NULL;

    *buf = 0;
    size_t len;

    if(!size)
        size = MAX_URI_SIZE;

    if(!addr)
        return NULL;

    switch(addr->address.sa_family) {
    case AF_INET:
        port = ntohs(addr->ipv4.sin_port);
        break;
#ifdef  AF_INET6
    case AF_INET6:
        ipv6 = true;
        port = ntohs(addr->ipv6.sin6_port);
        break;
#endif
    default:
        defaddr = registry::getDomain();
    }
    if(!port)
        port = sip_port;

    if(sip_tlsmode)
        String::set(buf, size, "sips:");
    else
        String::set(buf, size, "sip:");

    if(user) {
        String::add(buf, size, user);
        if(ipv6)
            String::add(buf, size, "@[");
        else
            String::add(buf, size, "@");
    }
    else if(ipv6)
        String::add(buf, size, "[");

    if(defaddr) {
        String::add(buf, sizeof(buf), defaddr);
        return buf;
    }

    len = strlen(buf);
    Socket::query((struct sockaddr *)addr, buf + len, size - len);
    if(ipv6)
        snprintf(pbuf, sizeof(pbuf), "]:%u", port);
    else
        snprintf(pbuf, sizeof(pbuf), ":%u", port);
    String::add(buf, size, pbuf);
    return buf;
}

Socket::address *stack::getAddress(const char *addr, Socket::address *ap)
{
    assert(addr != NULL && *addr != 0);

    char buffer[MAX_URI_SIZE];
    int family = sip_family;
    const char *svc = "sip";
    const char *sp;
    char *ep;

    sp = strchr(addr, '<');
    if(sp)
        addr = ++sp;

    if(!strnicmp(addr, "sip:", 4))
        addr += 4;
    else if(!strnicmp(addr, "sips:", 5))
        addr += 5;

    if(strchr(addr, '@'))
        addr = strchr(addr, '@') + 1;

#ifdef  AF_INET6
    if(*addr == '[') {
        String::set(buffer, sizeof(buffer), ++addr);
        if(sp) {
            ep = strchr(buffer, '>');
            if(ep)
                *ep = 0;
        }
        family = AF_INET6;
        ep = strchr(buffer, ']');
        if(ep)
            *(ep++) = 0;
        if(*ep == ':')
            svc = ++ep;
        goto set;
    }
#endif
    String::set(buffer, sizeof(buffer), addr);
    if(sp) {
        ep = (char *)strchr(buffer, '>');
        if(ep)
            *ep = 0;
    }
    ep = strchr(buffer, ':');
    if(ep) {
        *(ep++) = 0;
        svc = ep;
    }

set:
    if(svc) {
        ep = (char *)strchr(svc, ';');
        if(ep)
            *ep = 0;
    }

    if(ap)
        ap->add(buffer, svc, family);
    else
        ap = new Socket::address(family, buffer, svc);

    if(ap && !ap->getList()) {
        delete ap;
        ap = NULL;
    }
    return ap;
}

void stack::divert(stack::call *call, voip::msg_t invite)
{
    char route[MAX_URI_SIZE];
    char touri[MAX_URI_SIZE];

    if(!call->diverting)
        return;

    uri::publish(call->request, route, call->divert, sizeof(route));

    if(String::equal(call->diverting, "all")) {
        snprintf(touri, sizeof(touri), "<%s>;reason=unconditional", route);
        voip::header(invite, "Diversion", touri);
    }
    else if(String::equal(call->diverting, "na")) {
        snprintf(touri, sizeof(touri), "<%s>;reason=no-answer", route);
        voip::header(invite, "Diversion", touri);
    }
    else if(String::equal(call->diverting, "busy")) {
        snprintf(touri, sizeof(touri), "<%s>;reason=user-busy", route);
        voip::header(invite, "Diversion", touri);
    }
    else if(String::equal(call->diverting, "dnd")) {
        snprintf(touri, sizeof(touri), "<%s>;reason=do-not-disturb", route);
        voip::header(invite, "Diversion", touri);
    }
    else if(String::equal(call->diverting, "away")) {
        snprintf(touri, sizeof(touri), "<%s>;reason=away", route);
        voip::header(invite, "Diversion", touri);
    }
}

int stack::inviteRemote(stack::session *s, const char *uri_target, const char *digest)
{
    assert(s != NULL && s->parent != NULL);
    assert(uri_target != NULL);

    stack::session *invited;
    stack::call *call = s->parent;
    linked_pointer<stack::segment> sp = call->segments.begin();
    char username[MAX_USERID_SIZE];
    char network[MAX_NETWORK_SIZE];
    char touri[MAX_URI_SIZE];
    char route[MAX_URI_SIZE];
    voip::msg_t invite = NULL;
    char expheader[32];
    char seqid[64];
    int cid;
    unsigned icount = 0;
    time_t now;
    srv resolv;
    struct sockaddr_storage peering;
    voip::context_t context = resolv.route(uri_target, route, sizeof(route));
    const char *schema = NULL;
    char rewrite[MAX_URI_SIZE];

    if(!context)
        return icount;

/*
    struct sockaddr_storage peering, abuf;
    voip::context_t context = stack::sip.out_context;
    const char *out_target = uri_target;
    char rewrite[MAX_URI_SIZE];
    const char *schema = server::resolve(out_target, &abuf);
*/

    if(eq(uri_target, "tcp:", 4)) {
        uri_target += 4;
        schema = "sip";
    }
    else if(eq(uri_target, "udp:", 4)) {
        uri_target += 4;
        schema = "sip";
    }

    if(schema) {
        snprintf(rewrite, sizeof(rewrite), "%s:%s", schema, uri_target);
        uri_target = rewrite;
    }

    time(&now);

    // compute network and subnet..
    String::set(network, sizeof(network), "*");
    uri::userid(uri_target, username, sizeof(username));

    stack::subnet *subnet = server::getPolicy(*resolv);
    if(subnet) {
        memcpy(&peering, &subnet->iface, sizeof(struct sockaddr_storage));
        String::set(network, sizeof(network), subnet->getId());
    }
    else
        service::published(&peering);
    server::release(subnet);

    // make sure we do not re-invite an existing active member again
    while(is(sp)) {
        if(!stricmp(sp->sid.identity, uri_target) && sp->sid.state != stack::session::CLOSED)
            return icount;
        sp.next();
    }

    snprintf(touri, sizeof(touri), "<%s>", uri_target);

    invite = NULL;

    if(!voip::make_invite_request(context, touri, s->from, call->subject, &invite, route)) { 
        shell::log(shell::ERR, "cannot invite %s; build failed", uri_target);
        return icount;
    }

    divert(call, invite);

    voip::server_allows(invite);
    voip::server_supports(invite, "100rel,replaces,timer");

    if(digest && s->reg) {
        char *authbuf = new char[1024];
        stringbuf<64> response;
        stringbuf<64> once;
        char nounce[64];
        char *req = NULL;
        osip_uri_to_str(invite->req_uri, &req);
        snprintf(authbuf, 1024, "%s:%s", invite->sip_method, req);
        Random::uuid(nounce);

        digest_t auth = "md5";
        auth.puts(nounce);
        once = *auth;
        auth = registry::getDigest();
        auth.puts(authbuf);
        response = *auth;
        snprintf(authbuf, 1024, "%s:%s:%s", digest, *once, *response);
        auth.reset();
        auth.puts(authbuf);
        response = *auth;
        snprintf(authbuf, 1024,
            "Digest username=\"%s\""
            ",realm=\"%s\""
            ",uri=\"%s\""
            ",response=\"%s\""
            ",nonce=\"%s\""
            ",algorithm=%s"
            ,s->reg->userid, registry::getRealm(), req, *response, *once, registry::getDigest());
        voip::header(invite, AUTHORIZATION, authbuf);
        delete[] authbuf;
        osip_free(req);
    }
    else
        voip::header(invite, P_SIPWITCH_NODE, "no");

    if(call->expires) {
        snprintf(expheader, sizeof(expheader), "%ld", (long)(call->expires - now));
        voip::header(invite, SESSION_EXPIRES, expheader);
    }

    char sdp[MAX_SDP_BUFFER];
    LinkedObject *nat = NULL;

    if(media::invite(s, network, &nat, sdp) == NULL) {
        shell::log(shell::ERR, "cannot assign media proxy for %s", uri_target);
        voip::free_message_request(context, invite);
        return icount;
    }

    voip::attach(invite, SDP_BODY, sdp);
    stack::siplog(invite);
    cid = voip::send_invite_request(context, invite);
    if(cid > 0) {
        snprintf(seqid, sizeof(seqid), "%08x-%d", s->sequence, s->cid);
        uri::publish(call->request, route, seqid, sizeof(route));
        voip::call_reference(context, cid, route);
        ++icount;
    }
    else {
        media::release(&nat);
        shell::log(shell::ERR, "invite failed for %s", uri_target);
        return icount;
    }

    invited = stack::create(context, call, cid);
    registry::incUse(NULL, stats::OUTGOING);
    String::set(invited->identity, sizeof(invited->identity), uri_target);
    String::set(invited->display, sizeof(invited->display), username);
    snprintf(invited->from, sizeof(invited->from), "<%s>", uri_target);
    String::set(invited->network, sizeof(invited->network), network);
    invited->nat = nat;
    uri::identity(*resolv, invited->sysident, username, sizeof(invited->sysident));
    invited->peering = peering;

    shell::debug(3, "inviting %s\n", uri_target);
    return icount;
}

bool stack::forward(stack::call *cr)
{
    unsigned invited = cr->invited;

repeat:
    service::usernode user;
    service::keynode *fwd;
    const char *forwarding = cr->forwarding;
    const char *target;
    char buffer[MAX_URI_SIZE];
    registry::mapped *rr = NULL;

    String::set(cr->divert, sizeof(cr->divert), cr->forward);
    cr->forwarding = NULL;
    cr->diverting = NULL;

    if(!forwarding)
        return false;

    server::getProvision(cr->forward, user);
    if(!user.keys)
        return false;

    fwd = user.keys->getChild("forwarding");
    if(!fwd)
        goto failed;

    target = server::getValue(fwd, forwarding);

    if((!target || !*target) && (String::equal(forwarding, "away") || String::equal(forwarding, "dnd")))
        target = server::getValue(fwd, "busy");

    if(!target || !*target)
        goto failed;

    cr->diverting = forwarding;

    if(strchr(target, '@'))
        goto remote;

    String::set(cr->forward, sizeof(cr->forward), target);
    target = cr->forward;
    server::release(user);

    shell::debug(3, "call forward <%s> to %s", forwarding, target);

    rr = registry::access(target);
    if(rr) {
        cr->forwarding = "na";
        inviteLocal(cr->source, rr, FORWARDED);
        if(cr->forwarding && !String::equal("na", cr->forwarding) && cr->invited == invited) {
            registry::detach(rr);
            goto repeat;
        }
        registry::detach(rr);
    }

    goto test;

remote:
    if(!String::equal(target, "sip:", 4) && !String::equal(target, "sips:", 5))
        snprintf(buffer, sizeof(buffer), "%s:%s", getScheme(), target);
    else
        String::set(buffer, sizeof(buffer), target);
    target = buffer;
    server::release(user);
    shell::debug(3, "call forward <%s> to %s", forwarding, target);
    inviteRemote(cr->source, target);
    goto test;

failed:
    server::release(user);
    return false;

test:
    if(cr->invited > invited)
        return true;

    return false;
}

int stack::inviteLocal(stack::session *s, registry::mapped *rr, destination_t dest)
{
    assert(s != NULL && s->parent != NULL);
    assert(rr != NULL);

    linked_pointer<registry::target> tp = rr->source.internal.targets;
    stack::session *invited;
    stack::call *call = s->parent;
    linked_pointer<stack::segment> sp = call->segments.begin();
    LinkedObject *nat;
    char sdp[MAX_SDP_BUFFER];

    time_t now;
    voip::msg_t invite;
    char expheader[32];
    char seqid[64];
    char route[MAX_URI_SIZE];
    char touri[MAX_URI_SIZE];
    int cid;
    unsigned icount = 0;

    time(&now);

    if(rr->expires && rr->expires < now + 1)
        return icount;

    // make sure we do not re-invite an existing active member again
    while(is(sp)) {
        if(sp->sid.reg == rr && sp->sid.state == stack::session::OPEN) {
            return icount;
        }
        sp.next();
    }

    while(is(tp)) {
        invited = NULL;
        if(tp->expires && tp->expires < now + 1)
            goto next;

        switch(tp->status) {
        case registry::target::BUSY:        // can still try invite...
        case registry::target::READY:
            break;
        default:
            goto next;
        }

        invite = NULL;

        if(dest == ROUTED) {
            stack::sipPublish(&tp->address, route, call->dialed, sizeof(route));
            snprintf(touri, sizeof(touri), "\"%s\" <%s;user=phone>", call->dialed, route);
        }
        else if(call->phone)
            snprintf(touri, sizeof(touri), "<%s;user=phone>", tp->contact);
        else
            snprintf(touri, sizeof(touri), "<%s>", tp->contact);

        stack::sipPublish(&tp->address, route + 1, NULL, sizeof(route) - 5);
        route[0] = '<';
        String::add(route, sizeof(route), ";lr>");

        if(!voip::make_invite_request(tp->context, touri, s->from, call->subject, &invite, route)) { 
            stack::sipPublish(&tp->address, route, NULL, sizeof(route));
            shell::log(shell::ERR, "cannot invite %s; build failed", route);
            goto next;
        }

        // if not routing, then separate to from request-uri for forwarding
        if(dest != ROUTED) {
            stack::sipPublish(&tp->address, route, call->dialed, sizeof(route));
            if(call->phone)
                String::add(route, sizeof(route), ";user=phone");
            snprintf(touri, sizeof(touri), "\"%s\" <%s>", call->dialed, route);
            if(invite->to) {
                osip_to_free(invite->to);
                invite->to = NULL;
            }
            osip_message_set_to(invite, touri);
        }

        divert(call, invite);

        voip::server_allows(invite);
        voip::server_supports(invite, "100rel,replaces,timer");

        if(call->expires) {
            snprintf(expheader, sizeof(expheader), "%ld", (long)(call->expires - now));
            voip::header(invite, SESSION_EXPIRES, expheader);
        }

        nat = NULL;
        if(media::invite(s, tp->network, &nat, sdp) == NULL) {
            stack::sipPublish(&tp->address, route, NULL, sizeof(route));
            shell::log(shell::ERR, "no media proxy available for %s", route);
            voip::free_message_request(tp->context, invite);
            goto next;
        }

        voip::attach(invite, SDP_BODY, sdp);
        stack::siplog(invite);
        cid = voip::send_invite_request(tp->context, invite);
        if(cid > 0) {
            snprintf(seqid, sizeof(seqid), "%08x-%d", s->sequence, s->cid);
            stack::sipAddress((struct sockaddr_internet *)&tp->peering, route, seqid, sizeof(route));
            voip::call_reference(tp->context, cid, route);
            ++icount;
        }
        else {
            media::release(&nat);
            stack::sipPublish(&tp->address, route, NULL, sizeof(route));
            shell::log(shell::ERR, "invite failed for %s", route);
            goto next;
        }

        invited = stack::create(tp->context, call, cid);

        String::set(invited->network, sizeof(invited->network), tp->network);
        invited->peering = tp->peering;
        invited->nat = nat;

        if(rr->ext)
            snprintf(invited->sysident, sizeof(invited->sysident), "%u", rr->ext);
        else
            String::set(invited->sysident, sizeof(invited->sysident), rr->userid);
        if(rr->display[0])
            String::set(invited->display, sizeof(invited->display), rr->display);
        else
            String::set(invited->display, sizeof(invited->display), invited->sysident);
        stack::sipPublish((struct sockaddr_internet *)&tp->peering, invited->identity, invited->sysident, sizeof(invited->identity));
        if(rr->ext && !rr->display[0])
            snprintf(invited->from, sizeof(invited->from),
                "\"%s\" <%s;user=phone>", invited->sysident, invited->identity);
        else if(rr->display[0])
            snprintf(invited->from, sizeof(invited->from),
                "\"%s\" <%s>", rr->display, invited->identity);
        else
            snprintf(invited->from, sizeof(invited->from),
                "<%s>", invited->identity);
        registry::incUse(rr, stats::OUTGOING);
        invited->reg = rr;

        stack::sipPublish(&tp->address, route, NULL, sizeof(route));
        switch(dest) {
        case ROUTED:
            shell::debug(3, "routing to %s\n", route);
            break;
        default:
            shell::debug(3, "inviting %s\n", route);
        }

next:
        tp.next();
    }

    if(call->count > 0 || call->forwarding == NULL)
        return icount;

    switch(rr->status) {
    case MappedRegistry::BUSY:
        call->forwarding = "busy";
        return icount;
    case MappedRegistry::OFFLINE:
        call->forwarding = "gone";
        return icount;
    case MappedRegistry::DND:
        call->forwarding = "dnd";
        return icount;
    case MappedRegistry::AWAY:
        call->forwarding = "away";
        return icount;
    default:
        break;
    }
    return icount;
}

} // end namespace
