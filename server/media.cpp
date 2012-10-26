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
using namespace UCOMMON_NAMESPACE;

static unsigned tpriority = 0;
static unsigned baseport = 5062;
static bool ipv6 = false;
static LinkedObject *runlist = NULL;
static mutex_t lock;
static media::proxy *list = NULL;
static fd_set connections;
static media::proxy *proxymap[sizeof(connections) * 8];
static volatile bool running = false;
static volatile int hiwater = 0;

#ifdef  _MSWINDOWS_
static socket_t control;
static unsigned portcount = 0;
#else
static int control[2];
static unsigned portcount = 38;
#endif

static media _proxy;
static media::thread *th = NULL;

static unsigned align(unsigned value)
{
    return ((value + 1) / 2) * 2;
}

media::thread::thread() : DetachedThread()
{
}

void media::thread::startup(void)
{
    th = new thread();
    th->start(tpriority);
}

void media::thread::notify(void)
{
#ifdef  _MSWINDOWS_
#else
    char buf[1];
    if(::write(control[1], &buf, 1) < 1)
        shell::log(shell::ERR, "media notify failure");
#endif
}

void media::thread::shutdown(void)
{
    running = false;

    notify();

    while(!running) {
        Thread::sleep(100);
    }
}

void media::thread::run(void)
{
    fd_set session;
    socket_t max;

    shell::log(DEBUG1, "starting media thread");
    running = true;
    socket_t so;
    media::proxy *mp;
    time_t now;

    while(running) {
        lock.acquire();
        max = hiwater;
        memcpy(&session, &connections, sizeof(session));
        lock.release();
        select(max, &session, NULL, NULL, NULL);
        if(!running)
            break;

        time(&now);
        for(so = 0; so < max; ++so) {
#ifdef  _MSWINDOWS_
#else
            char buf[1];
            if(so == control[0] && FD_ISSET(so, &session)) {
                if(::read(so, buf, 1) < 1)
                    shell::log(shell::ERR, "media control failure");
                continue;
            }
#endif
            mp = NULL;
            if(!FD_ISSET(so, &session))
                continue;

            lock.acquire();
            mp = proxymap[so];
            if(mp->so == INVALID_SOCKET) {
                proxymap[so] = NULL;
                mp = NULL;
            }

            if(mp && mp->expires && mp->expires < now)
                mp->release(0);
            else if(mp)
                mp->copy();

            lock.release();
        }
    }

    shell::log(DEBUG1, "stopping media thread");
    running = true;
}

media::proxy::proxy() :
LinkedObject(&runlist)
{
    so = INVALID_SOCKET;
    expires = 0l;
    port = baseport++;
    fw = false;
}

media::proxy::~proxy()
{
    Socket::release(so);
}

void media::proxy::copy(void)
{
    char buffer[1024];
    struct sockaddr_storage where;
    struct sockaddr *wp = (struct sockaddr *)&where;
    ssize_t count = Socket::recvfrom(so, buffer, sizeof(buffer), 0, &where);

    if(count < 1)
        return;

    if(Socket::equal(wp, (struct sockaddr *)&local)) {
        Socket::sendto(so, buffer, count, 0, (struct sockaddr *)&remote);
        return;
    }
    Socket::store(&remote, wp);
    Socket::sendto(so, buffer, count, 0, (struct sockaddr *)&local);
}

void media::proxy::reconnect(struct sockaddr *host)
{
    struct sockaddr *hp = (struct sockaddr *)&local;

    switch(host->sa_family) {
#ifdef  AF_INET6
    case AF_INET6:
        ((struct sockaddr_in6*)(host))->sin6_port =
            ((struct sockaddr_in6 *)(hp))->sin6_port;
        break;
#endif
    case AF_INET:
        ((struct sockaddr_in*)(host))->sin_port =
            ((struct sockaddr_in *)(hp))->sin_port;
    }
    Socket::store(&local, host);
}

bool media::proxy::activate(media::sdp *parser)
{
    struct sockaddr *iface = parser->peering;
    struct sockaddr *host = (struct sockaddr *)&parser->local;

    release(0);
    Socket::store(&local, host);

    switch(iface->sa_family) {
#ifdef  AF_INET6
    case AF_INET6:
        so = Socket::create(AF_INET6, SOCK_DGRAM, 0);
        ((struct sockaddr_in6*)(host))->sin6_port = htons(++parser->mediaport);
        ((struct sockaddr_in6*)(iface))->sin6_port = htons(port);
        break;
#endif
    case AF_INET:
        so = Socket::create(AF_INET, SOCK_DGRAM, 0);
        ((struct sockaddr_in*)(host))->sin_port = htons(++parser->mediaport);
        ((struct sockaddr_in*)(iface))->sin_port = htons(port);
    }

    if(so == INVALID_SOCKET)
        return false;

    memset(&remote, 0, sizeof(remote));
    Socket::store(&peering, iface);
    Socket::bindto(so, iface);
    FD_SET(so, &connections);
    if(so >= (socket_t)hiwater)
        hiwater = so + 1;
    proxymap[so] = this;
    return true;
}

void media::proxy::release(time_t expire)
{
    expire = expires;
    if(expire || so == INVALID_SOCKET)
        return;

    FD_CLR(so, &connections);
    proxymap[so] = NULL;
    Socket::release(so);
    so = INVALID_SOCKET;
}

media::sdp::sdp()
{
    outdata = result = NULL;
    bufdata = NULL;
    mediacount = 0;
    mediaport = 0;
    nat = NULL;
    memset(&local, 0, sizeof(local));
    memset(&top, 0, sizeof(local));
}

media::sdp::sdp(const char *source, char *target, size_t len)
{
    set(source, target, len);
}

void media::sdp::reconnect(void)
{
    linked_pointer<media::proxy> pp = *nat;

    while(is(pp) && mediacount--) {
        pp->reconnect((struct sockaddr *)&local);
        pp.next();
    }
    memcpy(&local, &top, sizeof(local));
}

void media::sdp::set(const char *source, char *target, size_t len)
{
    outdata = result = target;
    bufdata = source;
    outpos = 0;
}

char *media::sdp::get(char *buffer, size_t len)
{
    char *base = buffer;
    size_t blen = len;

    // if eod, return NULL
    if(!bufdata || *bufdata == 0) {
        *buffer = 0;
        return NULL;
    }

    while(len > 1 && *bufdata != 0) {
        if(*bufdata == '\r') {
            ++bufdata;
            continue;
        }
        else if(*bufdata == '\n') {
            ++bufdata;
            break;
        }
        *(buffer++) = *(bufdata++);
        --len;
    }
    *buffer = 0;
    check_connect(base, blen);

    if(!result)
        return NULL;

    return base;
}

void media::sdp::check_media(char *buffer, size_t len)
{
    char *cp, *ep, *sp;
    char tmp[128];
    char mtype[32];
    unsigned tport;
    unsigned count = 1;
    media::proxy *pp;

    if(strnicmp(buffer, "m=", 2))
        return;

    cp = sp = strchr(buffer, ' ');
    if(!cp)
        return;

    while(isspace(*cp))
        ++cp;

    tport = atoi(cp);
    if(!tport)
        return;

    ep = strchr(cp, '/');
    if(ep)
        count = atoi(ep + 1);

    // at the moment we can only do rtp/rtcp pairs...
    if(count > 2) {
        result = NULL;
        return;
    }

    mediacount = count;
    count = align(count);

    ep = strchr(cp, ' ');
    if(!ep)
        ep = (char *)"";
    else while(isspace(*ep))
        ++ep;

    mediaport = tport;
    mediacount = count;
    tport = 0;

    lock.acquire();
    String::set(tmp, sizeof(tmp), ep);
    while(count--) {
        pp = media::get(this);
        if(!pp) {
            result = NULL;
            lock.release();
            return;
        }
        if(!tport)
            tport = (pp->port / 2) * 2;
    }
    lock.release();

    *sp = 0;
    String::set(mtype, sizeof(mtype), buffer);
    if(mediacount > 1)
        snprintf(buffer, len, "%s %u/%u %s",
            mtype, tport, mediacount, tmp);
    else
        snprintf(buffer, len, "%s %u %s",
            mtype, tport, tmp);

    mediacount = align(mediacount);
}

void media::sdp::check_connect(char *buffer, size_t len)
{
    char *cp = buffer + 4;
    char *ap;
    char ttl[16];
    struct sockaddr *hp;

    if(strnicmp(buffer, "c=in", 4))
        return;

    while(isspace(*cp))
        ++cp;

    if(ipv6 && strnicmp(cp, "ip6", 3))
        return;
    else if(!ipv6 && strnicmp(cp, "ip4", 3))
        return;

    ap = cp + 3;
    while(isspace(*ap))
        ++ap;

    cp = strchr(ap, '/');
    if(cp) {
        String::set(ttl, sizeof(ttl), cp);
        *cp = 0;
    }
    else
        ttl[0] = 0;

    if(!Socket::isNumeric(ap)) {
invalid:
        *cp = '/';
        return;
    }

    Socket::address addr(ap);
    hp = addr.getAddr();
    if(!hp)
        goto invalid;

    Socket::store(&local, hp);
    if(!mediaport)
        Socket::store(&top, hp);
    else
        reconnect();

    Socket::getaddress((struct sockaddr *)&peering, ap, len - 8);
    String::add(buffer, len, ttl);
}

size_t media::sdp::put(char *buffer)
{
    size_t count = 0;

    if(!outdata)
        return 0;

    while(*buffer && outpos < (MAX_SDP_BUFFER - 2)) {
        ++count;
        *(outdata++) = *(buffer++);
    }

    *(outdata++) = '\r';
    *(outdata++) = '\n';
    *outdata = 0;
    return count + 2;
}

media::media() :
service::callback(2)
{
}

void media::reload(service *cfg)
{
    assert(cfg != NULL);

    if(is_configured())
        return;

    baseport = sip_port + 2;

    linked_pointer<service::keynode> mp = cfg->getList("media");
    const char *key = NULL, *value;

    while(is(mp)) {
        key = mp->getId();
        value = mp->getPointer();
        if(key && value) {
            if(!stricmp(key, "port"))
                baseport = (atoi(value) / 2) * 2;
            else if(!stricmp(key, "priority"))
                tpriority = atoi(value);
            else if(!stricmp(key, "count"))
                portcount = align(atoi(value));
        }
        mp.next();
    }
    if(portcount)
        shell::log(DEBUG2, "media proxy configured for %d ports", portcount);
    else
        shell::log(DEBUG1, "media proxy disabled");
}

void media::start(service *cfg)
{
    if(portcount)
        shell::log(DEBUG1, "starting media proxy");
    else
        return;

    memset(proxymap, 0, sizeof(proxymap));
    memset(&connections, 0, sizeof(connections));

#ifdef  _MSWINDOWS_
#else
    if(pipe(control)) {
        shell::log(shell::ERR, "media proxy startup failed");
        return;
    }

    FD_SET(control[0], &connections);
    hiwater = control[0] + 1;
#endif

    list = new media::proxy[portcount];

    thread::startup();
}

void media::stop(service *cfg)
{
    if(portcount)
        shell::log(DEBUG1, "stopping media proxy");
    else
        return;

    thread::shutdown();
    delete[] list;
}

void media::enableIPV6(void)
{
    ipv6 = true;
}

media::proxy *media::get(media::sdp *parser)
{
    time_t now;
    time(&now);

    linked_pointer<media::proxy> pp = runlist;
    while(is(pp)) {
        if(pp->expires && pp->expires < now)
            pp->release(0);

        if(pp->so == INVALID_SOCKET && !pp->fw) {
            if(pp->activate(parser))
            {
                pp->delist(&runlist);
                media::thread::notify();
                pp->enlist(parser->nat);
                return *pp;
            }
            else
                break;
        }
        pp.next();
    }
    return NULL;
}

void media::release(LinkedObject **nat, unsigned expires)
{
    assert(nat != NULL);

    proxy *member;
    time_t expire = 0;

    if(!*nat)
        return;

    if(expires) {
        time(&expire);
        expire += expires;
    }

    lock.acquire();
    linked_pointer<proxy> pp = *nat;
    while(is(pp)) {
        member = *pp;
        pp.next();
        member->release(expires);
        member->enlist(&runlist);
    }
    lock.release();

    *nat = NULL;
}

bool media::isProxied(const char *source, const char *target, struct sockaddr_storage *peering)
{
    assert(source != NULL);
    assert(target != NULL);
    assert(peering != NULL);

    bool proxy = false;

    // if no port count, then proxy is disabled...
    if(!portcount)
        return false;

    // if same subnets, then we know is not proxied
    if(String::equal(source, target))
        return false;

    // if unknown networks then we cannot proxy...
    if(String::equal(source, "-") || String::equal(target, "-"))
        return false;

    // if sdp source is external, we do not need to proxy (one-legged only)
    // since we assume we can trust external user's public sdp
    if(String::equal(source, "*"))
        return false;

    // if external is remote and also we're ipv6, no need to proxy either...
    if(String::equal(target, "*") && ipv6)
        return false;

    // if remote, then peering for proxy is public address
    if(String::equal(target, "*")) {
        server::published(peering);
        return true;
    }

    // get subnets from policy name
    stack::subnet *src = server::getSubnet(source);
    stack::subnet *dst = server::getSubnet(target);

    if(!src || !dst)
        goto exit;

    // check by interface to see if same subnet, else to get subnet peering
    if(!Socket::equal((struct sockaddr *)(&src->iface), (struct sockaddr *)(&dst->iface))) {
        memcpy(peering, &dst->iface, sizeof(struct sockaddr_storage));
        proxy = true;
    }

exit:
    server::release(src);
    server::release(dst);
    // will become true later...
    return proxy;
}

char *media::reinvite(stack::session *session, const char *sdpin)
{
    assert(session != NULL);
    assert(sdpin != NULL);

    stack::call *cr = session->parent;
    struct sockaddr_storage peering;
    stack::session *target = NULL;
    LinkedObject **nat;

    if(session == cr->source)
        target = cr->target;
    else
        target = cr->source;

    // in case we had a nat chain...
    nat = &target->nat;
    media::release(nat, 2);

    if(!isProxied(session->network, target->network, &peering)) {
        String::set(session->sdp, sizeof(session->sdp), sdpin);
        return session->sdp;
    }

    shell::log(DEBUG3, "reinvite proxied %s to %s", session->network, target->network);
    sdp parser(sdpin, session->sdp, sizeof(session->sdp));
    parser.peering = (struct sockaddr *)&peering;
    parser.nat = nat;

    return rewrite(&parser);
}

char *media::answer(stack::session *session, const char *sdpin)
{
    assert(session != NULL);
    assert(sdpin != NULL);

    LinkedObject **nat;
    stack::call *cr = session->parent;
    stack::session *target = cr->source;
    struct sockaddr_storage peering;

    if(session == target || (cr->target != NULL && cr->target != session))
        return NULL;

    // in case we had a nat chain...
    nat = &target->nat;
    media::release(nat, 2);

    if(!isProxied(session->network, target->network, &peering)) {
        String::set(session->sdp, sizeof(session->sdp), sdpin);
        return session->sdp;
    }

    shell::log(DEBUG3, "answer proxied %s to %s", session->network, target->network);
    sdp parser(sdpin, session->sdp, sizeof(session->sdp));
    parser.peering = (struct sockaddr *)&peering;
    parser.nat = nat;

    return rewrite(&parser);
}

char *media::invite(stack::session *session, const char *target, LinkedObject **nat, char *sdpout, size_t size)
{
    assert(session != NULL);
    assert(target != NULL);
    assert(nat != NULL);

    *nat = NULL;
    struct sockaddr_storage peering;

    if(!isProxied(session->network, target, &peering)) {
        String::set(sdpout, size, session->sdp);
        return sdpout;
    }

    shell::log(DEBUG3, "invite proxied %s to %s", session->network, target);
    sdp parser(session->sdp, sdpout, size);
    parser.peering = (struct sockaddr *)&peering;
    parser.nat = nat;

    return rewrite(&parser);
}

char *media::rewrite(media::sdp *parser)
{
    char buffer[256];

    // simple copy rewrite parser for now....
    while(NULL != parser->get(buffer, sizeof(buffer))) {
        if(!parser->put(buffer))
            return NULL;

    }
    return parser->result;
}

END_NAMESPACE
