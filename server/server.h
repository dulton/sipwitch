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

#undef  HAVE_CONFIG_H

#include <sipwitch-config.h>
#include <sipwitch/sipwitch.h>
#include <ucommon/secure.h>

#ifdef  HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef WIN32
#undef alloca
#endif

#include <ctype.h>

#define SECOND_TIMEOUT  (1000l)
#define MINUTE_TIMEOUT  (SECOND_TIMEOUT * 60l)
#define HOUR_TIMEOUT    (MINUTE_TIMEOUT * 60l)
#define DAY_TIMEOUT     (HOUR_TIMEOUT * 24l)

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

#define PAGING_SIZE (2048l * sizeof(void *))

#define ALLOWS_INVITE       0x0001
#define ALLOWS_MESSAGE      0x0002
#define ALLOWS_DEFAULT      0x0003

class thread;

typedef enum {EXTERNAL, LOCAL, PUBLIC, ROUTED, FORWARDED, REDIRECTED} destination_t;

class __LOCAL digests
{
public:
    static void reload(void);

    static const char *get(const char *id);

    static bool set(const char *id, const char *hash);

    static void release(const char *hash);

    static void load(void);
};

class __LOCAL registry : private service::callback, private mapped_array<MappedRegistry>
{
public:
    class __LOCAL mapped : public MappedRegistry
    {
    public:
        void update(Socket::address& addr, int changed);
        void update(void);
        bool expire(Socket::address& addr);
        bool refresh(Socket::address& addr, time_t expires, const char *target_contact);
        unsigned setTargets(Socket::address& addr, voip::context_t context);
        unsigned addTarget(Socket::address& via, time_t expires, const char *contact, const char *policy, struct sockaddr *peer, voip::context_t context);
        unsigned setTarget(Socket::address& via, time_t expires, const char *contact, const char *policy, struct sockaddr *peer, voip::context_t context);
        void addContact(const char *id);
        void addPublished(const char *id);
        void addRoute(const char *pat, unsigned pri, const char *prefix, const char *suffix);
    };

    class __LOCAL pointer
    {
    private:
        mapped *entry;

    public:
        pointer();
        pointer(const char *id);
        pointer(pointer const &copy);
        ~pointer();

        void operator=(mapped *ptr);

        inline operator bool() const
            {return entry != NULL;};

        inline bool operator!() const
            {return entry == NULL;};

        inline mapped *operator->() const
            {return entry;};

        inline mapped *operator*() const
            {return entry;};
    };

    class __LOCAL target : public LinkedObject
    {
    public:
        typedef enum {READY, BUSY, AWAY, DND, OFFLINE, UNKNOWN} status_t;
        // internal hidden address indexing object
        class indexing : public LinkedObject
        {
        public:
            struct sockaddr *address;
            mapped *registry;
            target *getTarget(void);
        } index;
        struct sockaddr_internet address;
        struct sockaddr_storage peering;
        voip::context_t context;

        time_t created;
        status_t status;
        volatile time_t expires;
        unsigned long allows;
        char contact[MAX_URI_SIZE];
        char network[MAX_NETWORK_SIZE];

        static void *operator new(size_t size);
        static void operator delete(void *ptr);
    };

    class __LOCAL pattern : public LinkedObject
    {
    public:
        mapped *registry;
        unsigned priority;
        char text[MAX_USERID_SIZE];
        char prefix[MAX_USERID_SIZE];
        char suffix[MAX_USERID_SIZE];
    };

private:
    class __LOCAL route : public LinkedObject
    {
    public:
        pattern entry;

        static void *operator new(size_t size);
        static void operator delete(void *ptr);
    };

    bool check(void);
    void reload(service *cfg);
    void start(service *cfg);
    void stop(service *cfg);
    void snapshot(FILE *fp);

    static void clear(mapped *rr);
    static void expire(mapped *rr);
    static mapped *find(const char *id);

    static registry reg;

    volatile time_t expires;

    char * volatile digest;
    char * volatile realm;
    unsigned prefix;
    unsigned range;
    unsigned routes;

public:
    registry();

    inline static const char *getRealm(void)
        {return (const char *)reg.realm;};

    inline static const char *getDigest(void)
        {return (const char *)reg.digest;};

    inline static time_t getExpires(void)
        {return reg.expires;};

    inline static unsigned getPrefix(void)
        {return reg.prefix;};

    inline static unsigned getRange(void)
        {return reg.range;};

    inline static unsigned getRoutes(void)
        {return reg.routes;};

    static const char *getDomain(void);
    static void incUse(mapped *rr, stats::stat_t stat);
    static void decUse(mapped *rr, stats::stat_t stat);
    static unsigned getEntries(void);
    static unsigned getIndex(mapped *rr);
    static bool isExtension(const char *id);
    static bool isUserid(const char *id);
    static mapped *address(struct sockaddr *addr);
    static mapped *contact(const char *uri);
    static mapped *contact(struct sockaddr *addr, const char *uid);
    static mapped *getExtension(const char *id);
    static mapped *allocate(const char *id);
    static mapped *access(const char *id);
    static mapped *invite(const char *id, stats::stat_t stat);
    static mapped *dialing(const char *id);
    static bool exists(const char *id);
    static pattern *getRouting(unsigned trs, const char *id);
    static void detach(mapped *m);
    static bool remove(const char *id);
    static unsigned cleanup(time_t period);
};

class __LOCAL stack : public service::callback, private mapped_array<MappedCall>, public OrderedIndex
{
private:
    friend class proxy;
    friend class thread;
    friend class messages;
    friend class media;

    class call;

    class __LOCAL background : public DetachedThread, public Conditional
    {
    public:
        static void create(timeout_t interval);
        static void cancel(void);

        static background *thread;

        static void notify(void);

    private:
        bool cancelled;
        bool signalled;
        timeout_t interval;
        Timer expires;

        background(timeout_t sync);
        void run(void);
    };

    class __LOCAL session : public LinkedObject
    {
    public:
        registry::mapped *reg;
        voip::call_t cid;
        voip::tid_t tid;
        voip::did_t did;
        voip::context_t context;
        time_t activates;
        uint32_t sequence;
        call *parent;
        time_t expires;                 // session/invite expires...
        time_t ringing;                 // ring no-answer timer...
        bool closed;

        enum {OPEN, CLOSED, RING, BUSY, REORDER, REFER, REINVITE} state;

        char sdp[MAX_SDP_BUFFER];       // sdp body to use in exchange
        char identity[MAX_URI_SIZE];    // our effective contact/to point...
        char sysident[MAX_IDENT_SIZE];  // ident of this session
        char display[MAX_DISPLAY_SIZE]; // callerid reference field
        char network[MAX_NETWORK_SIZE]; // network policy affinity for nat
        char from[MAX_URI_SIZE + MAX_DISPLAY_SIZE]; // formatted from line for endpoint
        char uuid[48];

        LinkedObject *nat;              // media nat chain...
        struct sockaddr_storage peering;

        char authid[MAX_USERID_SIZE];   // for authentication...
        char secret[MAX_USERID_SIZE];
        enum {NONE, DIGEST} authtype;

        inline bool isSource(void) const
            {return (this == parent->source);};

        inline bool isTarget(void) const
            {return (this == parent->target);};
    };

    class __LOCAL segment : public OrderedObject
    {
    public:
        segment(voip::context_t context, call *cr, voip::call_t cid, voip::did_t did = -1, voip::tid_t tid = 0);

        static void *operator new(size_t size);
        static void operator delete(void *obj);

        session sid;

        inline session *get(void)
            {return &sid;};
    };

    class __LOCAL call : public LinkedList
    {
    public:
        typedef enum {INITIAL, TRYING, RINGING, RINGBACK, REORDER, HOLDING, ANSWERED, JOINED, TRANSFER, REDIRECT, BUSY, TERMINATE, FAILED, FINAL} state_t;

        enum {DIRECTED, CIRCULAR, TERMINAL, REDIRECTED, DISTRIBUTED} mode;

        destination_t type;

        call();

        Timer timer;
        state_t state;
        char forward[MAX_USERID_SIZE];  // ref id for forwarding...
        char divert[MAX_USERID_SIZE];   // used in forward management
        char dialed[MAX_IDENT_SIZE];    // user or ip address...
        char subject[MAX_URI_SIZE];     // call subject
        char request[MAX_URI_SIZE];     // requesting identity for refer flip

        void disarm(void);
        void arm(timeout_t timeout);
        void reply_source(int error);
        void ring(thread *thread, session *s = NULL);
        void busy(thread *thread, session *s = NULL);
        void failed(thread *thread, session *s);
        void answer(thread *thread, session *s);
        void relay(thread *thread, session *s);
        void message_reply(thread *thread, session *s);
        void reinvite(thread *thread, session *s);
        void trying(thread *thread);
        void confirm(thread *thread, session *s);
        timeout_t getTimeout(void);
        void closingLocked(session *s);
        void terminateLocked(void);
        void disconnectLocked(void);
        void joinLocked(session *s);
        void cancelLocked(void);
        cdr *log(void);
        void bye(thread *thread, session *s);
        void set(state_t state, char id, const char *text);

        OrderedIndex segments;
        const char *reason;
        const char *joined;
        session *source;
        session *target;
        segment *select;
        MappedCall *map;
        const char *forwarding;
        const char *diverting;
        unsigned answering;     // answer ring supervision...
        unsigned count;         // total open segments
        unsigned invited;       // pending segments with invites
        unsigned ringing;       // number of ringing segments
        unsigned ringbusy;      // number of busy segments
        unsigned unreachable;   // number of unreachable segments
        time_t expires, starting, ending;
        int experror;           // error at expiration...
        bool phone;

        static void *operator new(size_t size);
        static void operator delete(void *obj);

    private:
        void expired(void);
    };

    void reload(service *cfg);
    void start(service *cfg);
    void stop(service *cfg);
    void snapshot(FILE *fp);
    bool check(void);

    static void divert(stack::call *cr, voip::msg_t msg);

    unsigned threading, priority;
    size_t stacksize;

    volatile int timing;

    const char *volatile localnames;
    const char *volatile restricted;
    const char *volatile trusted;
    const char *volatile published;
    const char *volatile proxy;
    const char *iface;
    String agent;
    String system;
    String anon;
    bool incoming, outgoing, dumping;
    int send101;
    timeout_t ring_timer, cfna_timer, reset_timer;
    unsigned invite_expires;

public:
    static stack sip;

    class __LOCAL subnet : public cidr
    {
    private:
        char netname[MAX_NETWORK_SIZE];
        bool active;

    public:
        subnet(cidr::policy **acl, const char *rule, const char *name);

        struct sockaddr_storage iface;

        const char *getId(void)
            {return netname;};

        inline struct sockaddr *getInterface(void)
            {return (struct sockaddr *)&iface;};

        inline operator bool()
            {return active;};

        inline bool operator!()
            {return !active;};

        inline void up(void)
            {active = true;};

        inline void down(void)
            {active = false;};

        inline bool offline(void)
            {return active == false;};
    };

    stack();

    static const char *getScheme(void);
    static void getInterface(struct sockaddr *iface, struct sockaddr *dest);
    static session *create(voip::context_t context, voip::call_t cid, voip::did_t did, voip::tid_t tid);
    static session *create(voip::context_t context, call *cr, voip::call_t cid);
    static void destroy(session *s);
    static void destroy(call *cr);
    static void disjoin(call *cr);
    static void detach(session *s);
    static void clear(session *s);
    static void close(session *s);
    static session *access(voip::call_t cid);
    static char *sipAddress(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_URI_SIZE);
    static char *sipPublish(struct sockaddr_internet *addr, char *buf, const char *user = NULL, size_t size = MAX_URI_SIZE);
    static char *sipContact(struct sockaddr_internet *addr, char *buf, const char *user = NULL, const char *display = NULL, size_t size = MAX_URI_SIZE);
    static Socket::address *getAddress(const char *uri, Socket::address *addr = NULL);
    static void siplog(voip::msg_t msg);
    static void enableDumping(void);
    static void clearDumping(void);
    static void disableDumping(void);
    static void refer(session *session, voip::event_t sevent);
    static void infomsg(session *session, voip::event_t sevent);
    static void setDialog(session *session, voip::did_t did);
    static int getDialog(session *session);
    static void release(MappedCall *map);
    static MappedCall *get(void);
    static bool forward(stack::call *cr);
    static int inviteRemote(stack::session *session, const char *uri, const char *digest = NULL);
    static int inviteLocal(stack::session *session, registry::mapped *rr, destination_t dest);

    inline static timeout_t ringTimeout(void)
        {return stack::sip.ring_timer;};

    inline static timeout_t cfnaTimeout(void)
        {return stack::sip.cfna_timer;};

    inline static timeout_t resetTimeout(void)
        {return stack::sip.reset_timer;};

    inline static unsigned inviteExpires(void)
        {return stack::sip.invite_expires;};
};

class __LOCAL server : public service
{
private:
    typedef linked_value<profile_t, LinkedObject> profile;

    cidr::policy *acl;
    keynode **extmap;
    keynode *provision;
    LinkedObject *profiles;

    bool create(const char *id, keynode *node);
    keynode *find(const char *id);

    void confirm(void);
    void dump(FILE *fp);

public:
    static shell::logmode_t logmode;
    static unsigned uid;
    static const char *sipusers;
    static const char *sipadmin;
    static int exit_code;

    server(const char *id);

    static bool check(void);
    static profile_t *getProfile(const char *id);
    static keynode *getRouting(const char *id);
    static void getProvision(const char *id, usernode& user);
    static void getDialing(const char *id, usernode& user);
    static keynode *getConfig(void);
    static void listPolicy(FILE *fp);
    static stack::subnet *getPolicy(struct sockaddr *addr);
    static stack::subnet *getSubnet(const char *id);
    static bool isLocal(struct sockaddr *addr);
    static void release(stack::subnet *access);
    static void release(keynode *node);
    static void release(usernode& user);
    static void reload(void);
    static Socket::address *getContact(const char *id);
    static void plugins(const char *argv0, const char *names);
    static void run(void);
    static void stop(void);
    static caddr_t allocate(size_t size, LinkedObject **list, volatile unsigned *count = NULL);
    static unsigned allocate(void);

    static bool announce(MappedRegistry *rr, const char *msgtype, const char *event, const char *expires, const char *body);
    static void activate(MappedRegistry *rr);
    static void expire(MappedRegistry *rr);
    static void logging(MappedRegistry *rr, const char *reason);
    static void registration(voip::reg_t id, modules::regmode_t mode);
    static bool authenticate(voip::reg_t id, const char *realm);
    static const char *referLocal(MappedRegistry *rr, const char *target, char *buffer, size_t size);
    static const char *referRemote(MappedRegistry *rr, const char *target, char *buffer, size_t size);
    static bool checkId(const char *id);
    static void printlog(const char *fmt, ...) __PRINTF(1, 2);
};

class __LOCAL messages : public service::callback
{
private:
    class __LOCAL message : public LinkedObject
    {
    public:
        time_t expires;
        char user[MAX_USERID_SIZE];
        char type[64];
        char from[MAX_URI_SIZE];
        char body[1024];
        char reply[MAX_USERID_SIZE];
        int msglen;
        void create();
    };

    static messages manager;

    bool check(void);
    void reload(service *cfg);
    void cleanup(void);
    void snapshot(FILE *fp);

    static int deliver(message *msg);
    static int remote(const char *to, message *msg, const char *digest = NULL);

public:
    messages();

    static void automatic(void);
    static void update(const char *userid);
    static int deliver(const char *to, const char *reply, const char *from, caddr_t body, size_t size, const char *msgtype, const char *digest = NULL);
    static int system(const char *to, const char *message);
};


class __LOCAL thread : private DetachedThread
{
private:
    friend class stack;
    friend class stack::call;

    const char *instance;
    unsigned extension;
    stack::subnet *access;
    char network[MAX_NETWORK_SIZE];
    struct sockaddr_storage peering;
    service::usernode authorized;
    service::usernode dialed;
    service::keynode *routed;
    registry::mapped *reginfo;
    MappedRegistry *accepted;
    voip::event_t sevent;
    bool activated;
    char binding[MAX_URI_SIZE];
    char buffer[MAX_URI_SIZE];
    char buftemp[MAX_URI_SIZE];
    char identbuf[MAX_USERID_SIZE + 12];
    char identity[MAX_USERID_SIZE];
    char dialing[MAX_USERID_SIZE];
    char display[MAX_DISPLAY_SIZE];
    char requesting[MAX_URI_SIZE];
    Socket::address via_address, request_address, contact_address;
    stack::session *session;
    voip::hdr_t header;
    long header_expires;
    voip::via_t via_header;
    voip::from_t from;
    voip::to_t to;
    voip::uri_t uri;
    const char *via_host, *contact_host;
    unsigned via_hops;
    unsigned via_port, from_port, contact_port;
    destination_t destination;
    voip::context_t context;

    char *sip_realm;
    voip::proxyauth_t proxy_auth;
    voip::proxyauth_t www_auth;

    enum {CALL, MESSAGE, REGISTRAR, NONE} authorizing;

    thread(voip::context_t ctx, const char *tag);

    static void wait(unsigned count);
    static const char *eid(eXosip_event_type ev);

    void send_reply(int error);
    void expiration(void);
    void invite(void);
    void identify(void);
    bool getsource(void);
    bool unauthenticated(void);
    bool authenticate(void);
    bool authenticate(stack::session *session);
    bool authorize(void);
    void registration(void);
    void validate(void);
    void message(void);
    void publish(void);
    void reregister(const char *contact, time_t interval);
    void deregister(void);
    void challenge(void);
    void options(void);
    void run(void);
    void getDevice(registry::mapped *rr);
    const char *getIdent(void);

public:
    static void shutdown(void);
};

// media proxy support for NAT transversal is being moved to here...
class __LOCAL media : public service::callback
{
public:
    // support thread
    class __LOCAL thread : public DetachedThread
    {
    public:
        static void startup(void);

        static void notify(void);

        static void shutdown(void);

    private:
        thread();

        void run(void);
    };

    // a support class to help in sdp parsing
    class __LOCAL sdp
    {
    public:
        const char *bufdata;
        char *outdata, *result;
        size_t buflen, outpos;
        struct sockaddr *peering;
        struct sockaddr_storage local, top;
        LinkedObject **nat;
        unsigned mediacount;
        unsigned short mediaport;

        sdp();
        sdp(const char *source, char *target, size_t len = MAX_SDP_BUFFER);

        inline struct sockaddr *get(void)
            {return (struct sockaddr *)&local;};

        void set(const char *source, char *target, size_t len = MAX_SDP_BUFFER);
        char *get(char *buffer, size_t len);
        size_t put(char *buffer);

        // check connect in sdp output
        void check_connect(char *buffer, size_t len);
        void check_media(char *buffer, size_t len);

        // can do backfill of NAT if connect in media record
        void reconnect(void);
    };

    // proxy socket class
    class __LOCAL proxy : public LinkedObject
    {
    public:
        socket_t so;
        time_t expires;
        uint16_t port;
        struct sockaddr_storage local, remote, peering;
        bool fw;    // to be used when we add ipfw rules support

        proxy();
        ~proxy();

        bool activate(media::sdp *parser);
        void release(time_t expire = 0l);
        void reconnect(struct sockaddr *address);
        void copy(void);
    };

    media();

    void start(service *cfg);
    void stop(service *cfg);
    void reload(service *cfg);

    // get and activate nat instance if any are free...
    static proxy *get(media::sdp *parser);

    // set ipv6 flag, removes need to proxy any external addresses...
    static void enableIPV6(void);

    // release any existing media proxy for the call session, proxy can be kept active for re-invite transition
    static void release(LinkedObject **nat, unsigned expires = 0);

    // rewrite an invite for a call target if different, otherwise uses original source sdp...
    static char *invite(stack::session *session, const char *target, LinkedObject **nat, char *sdp, size_t size = MAX_SDP_BUFFER);

    // rewrite or copy sdp of session on answer for connection
    static char *answer(stack::session *session, const char *sdp);

    // re-assign or copy sdp on re-invite; clears and rebuilds media proxy if needed...
    static char *reinvite(stack::session *session, const char *sdp);

private:
    // low level rewrite & proxy assignment
    static char *rewrite(media::sdp *parser);

    // see if connected directly or if requires proxy
    static bool isProxied(const char *source, const char *target, struct sockaddr_storage *peering);
};

class __LOCAL history : public OrderedObject, public control
{
public:
    char text[128];

    history(shell::loglevel_t lid, const char *msg);

    void set(shell::loglevel_t lid, const char *msg);

    static void add(shell::loglevel_t lid, const char *msg);
    static void set(unsigned size);
    static void out(void);
};

#ifdef HAVE_SIGWAIT

class __LOCAL signals : private JoinableThread
{
private:
    bool shutdown;
    bool started;

    sigset_t sigs;

    void run(void);
    void cancel(void);

    signals();
    ~signals();

    static signals thread;

public:
    static void service(const char *name);
    static void setup(void);
    static void start(void);
    static void stop(void);
};

#else
class __LOCAL signals
{
public:
    static void service(const char *name);
    static void setup(void);
    static void start(void);
    static void stop(void);
};
#endif

#ifdef  HAVE_SYS_INOTIFY_H

class __LOCAL notify : private JoinableThread
{
private:
    notify();

    ~notify();

    void run(void);

    static notify thread;

public:
    static void start(void);
    static void stop(void);
};

#else

class __LOCAL notify
{
public:
    static void start(void);
    static void stop(void);
};

#endif

END_NAMESPACE

