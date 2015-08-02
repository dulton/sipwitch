// Copyright (C) 2008-2014 David Sugar, Tycho Softworks.
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

#include <sipwitch-config.h>
#include <sipwitch/sipwitch.h>
#include <ucommon/secure.h>
#ifdef _MSWINDOWS_
#include <windows.h>
#include <io.h>
#else
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#endif

#if !defined(_MSWINDOWS_)
#include <sys/un.h>
#endif

using namespace sipwitch;

static string_t statmap = STAT_MAP;
static string_t callmap = CALL_MAP;
static string_t regmap = REGISTRY_MAP;

#ifdef  _MSWINDOWS_
static char *getpass(const char *prompt)
{
    static char buf[128];
    size_t i;

    fputs(prompt, stderr);
    fflush(stderr);
    for (i = 0; i < sizeof(buf) - 1; i++) {
        buf[i] = fgetc(stdin);
        if (buf[i] == '\r' || buf[i] == '\n')
            break;
        fputs("*", stderr);
        fflush(stderr);
    }
    buf[i] = 0;
    fputs("\n", stderr);
    fflush(stderr);
    return buf;
}
#endif

#ifndef _MSWINDOWS_
static void capture(void)
{
    char buffer[512];
    FILE *fp;

    snprintf(buffer, sizeof(buffer), "/tmp/.sipwitch.%ld", (long)getpid());
    fp = fopen(buffer, "r");
    fsys::erase(buffer);
    while(fp && fgets(buffer, sizeof(buffer), fp) != NULL)
        fputs(buffer, stdout);
    if(fp)
        fclose(fp);
}
#endif

static void paddress(struct sockaddr_internet *a1, struct sockaddr_internet *a2)
{
    assert(a1 != NULL);

    char sep = '\n';
    char buf[64];
    unsigned p1 = 0, p2 = 0;

    if(!a1)
        return;

    Socket::query((struct sockaddr *)a1, buf, sizeof(buf));
    switch(a1->address.sa_family) {
    case AF_INET:
        p1 = (unsigned)ntohs(a1->ipv4.sin_port);
        break;
#ifdef  AF_INET6
    case AF_INET6:
        p1 = (unsigned)ntohs(a1->ipv6.sin6_port);
        break;
#endif
    }

    if(a2) {
        switch(a2->address.sa_family) {
        case AF_INET:
            p2 = (unsigned)ntohs(a2->ipv4.sin_port);
            break;
#ifdef  AF_INET6
        case AF_INET6:
            p2 = (unsigned)ntohs(a2->ipv6.sin6_port);
            break;
#endif
        }
    }

    if(a2 && p2)
        sep = ',';

    if(p1)
        printf("%s:%u%c", buf, p1, sep);
    else
        printf("none%c", sep);

    if(!a2 || !p2)
        return;

    Socket::query((struct sockaddr *)a2, buf, sizeof(buf));
    printf("%s:%u\n", buf, p2);
}

static void mapinit(void)
{
#ifndef _MSWINDOWS_
    struct passwd *pwd = getpwuid(getuid());
    const char *userid = NULL;

    fd_t fd = ::open(DEFAULT_VARPATH "/run/sipwitch/control", O_WRONLY | O_NONBLOCK);
    if(fd < 0) {
        if(pwd)
            userid = pwd->pw_name;
        if(!pwd || !userid)
            shell::errexit(4, "*** sipcontrol: maps: invalid login\n");

        statmap = str(STAT_MAP "-") + str(userid);
        callmap = str(CALL_MAP "-") + str(userid);
        regmap = str(REGISTRY_MAP "-") + str(userid);
    }
    else
        ::close(fd);
#endif
}

static void showrealm(void)
{
    fsys_t fs;
    char buffer[256];

    fs.open(DEFAULT_CFGPATH "/siprealm", fsys::RDONLY);
    if(!is(fs))
        fs.open(DEFAULT_VARPATH "/lib/sipwitch/uuid", fsys::RDONLY);

    if(!is(fs))
error:
        shell::errexit(1, "*** sipcontrol: realm: no public realm known\n");

    memset(buffer, 0, sizeof(buffer));
    fs.read(buffer, sizeof(buffer) - 1);
    fs.close();

    char *cp = strchr(buffer, '\n');
    if(cp)
        *cp = 0;

    cp = strchr(buffer, ':');
    if(cp)
        *cp = 0;

    if(!buffer[0])
        goto error;

    printf("%s\n", buffer);
    exit(0);
}

static void compute(char **argv)
{
    char *realm = NULL;
    const char *user, *secret;
    const char *mode = "md5";
    char buffer[128];
    string_t digestbuf;

    user = argv[1];
    if(!user)
        shell::errexit(3, "*** sipcontrol: digest: userid missing\n");

    secret = getpass("Enter new SIP secret: ");
    if(!secret || !*secret) {
        printf("no password supplied\n");
        exit(0);
    }

    realm = argv[2];
    if(realm) {
        if(argv[3])
            mode = argv[3];
    }
    else {
        fsys_t fs;
        fs.open(DEFAULT_CFGPATH "/siprealm", fsys::RDONLY);
        if(!is(fs))
            fs.open(DEFAULT_VARPATH "/lib/sipwitch/uuid", fsys::RDONLY);

        if(!is(fs))
            shell::errexit(4, "*** sipcontrol: digest: no public realm known\n");

        memset(buffer, 0, sizeof(buffer));
        fs.read(buffer, sizeof(buffer) - 1);
        fs.close();

        char *cp = strchr(buffer, '\n');
        if(cp)
            *cp = 0;

        cp = strchr(buffer, ':');
        if(cp)
            *(cp++) = 0;

        if(cp && *cp)
            mode = cp;
        realm = strdup(buffer);
    }

    digest_t digest = mode;
    if(digest.puts((string_t)user + ":" + (string_t)realm + ":" + (string_t)secret))
        digestbuf = *digest;
    else
        shell::errexit(6, "** sipcontrol: digest: unsupported computation");

    printf("%s\n", *digestbuf);
    exit(0);
}

static void realm(char **argv)
{
    char *realm = NULL;
    const char *mode = NULL;
    fsys_t fs;
    char buffer[256];
    char replace[256];
    char *cp = NULL;
    FILE *fp;

#ifdef  _MSWINDOWS_
    const char *control = "\\\\.\\mailslot\\sipwitch_ctrl";
#else
    const char *control = DEFAULT_VARPATH "/run/sipwitch/control";
#endif

    if(!argv[1])
        showrealm();

    mode = argv[2];
    if(!mode)
        mode = "md5";

    fs.open(DEFAULT_CFGPATH "/siprealm", fsys::RDONLY);
    memset(buffer, 0, sizeof(buffer));
    if(is(fs)) {
        fs.read(buffer, sizeof(buffer) - 1);
        fs.close();
        cp = strchr(buffer, ':');
        if(cp)
            *(cp++) = 0;
    }

    realm = argv[1];
    if(!realm)
        realm = buffer;

    if(!cp || !*cp)
        cp = (char *)"md5";

    // make sure we have a valid mode, default is md5...
    if(!mode && cp && *cp)
        mode = cp;

    if(!mode)
        mode = "md5";

    // if unchanged, we leave alone...
    if(eq(buffer, realm) && eq(cp, mode))
        goto exit;

    // create replacement realm string...
    if(eq(mode, "md5"))
        String::set(replace, sizeof(replace), realm);
    else
        snprintf(replace, sizeof(replace), "%s:%s", realm, mode);

    ::remove(DEFAULT_CFGPATH "/siprealm");
    fs.open(DEFAULT_CFGPATH "/siprealm", fsys::GROUP_PUBLIC, fsys::WRONLY);
    if(is(fs)) {
        fs.write(replace, strlen(replace));
        fs.close();
    }
    else
        shell::errexit(3, "*** sipcontrol: realm: root permission required\n");

    // if server is up, also sync server with realm change...
    fp = fopen(control, "w");
    if(fp) {
        fprintf(fp, "realm %s\n", realm);
        fclose(fp);
    }

exit:
    printf("%s\n", realm);
    exit(0);
}

static void status(char **argv)
{
    if(argv[1])
        shell::errexit(1, "*** sipcontrol: status: no arguments used\n");

    mapinit();

    mapped_view<MappedCall> calls(*callmap);
    unsigned count = calls.count();
    unsigned index = 0;
    const volatile MappedCall *map;

    if(!count)
        shell::errexit(10, "*** sipcontrol: status: offline\n");

    while(index < count) {
        map = (const volatile MappedCall *)(calls(index++));
        if(map->state[0])
            fputc(map->state[0], stdout);
        else
            fputc(' ', stdout);
    }
    fputc('\n', stdout);
    fflush(stdout);
    exit(0);
}

static void calls(char **argv)
{
    if(argv[1])
        shell::errexit(1, "*** sipcontrol: calls: no arguments used\n");

    mapinit();

    mapped_view<MappedCall> calls(*callmap);
    unsigned count = calls.count();
    unsigned index = 0;
    const volatile MappedCall *map;
    time_t now;

    if(!count)
        shell::errexit(10, "*** sipcontrol: calls: offline\n");

    time(&now);
    while(index < count) {
        map = (const volatile MappedCall *)(calls(index++));

        if(!map->created || !map->source[0])
            continue;

        if(map->active)
            printf("%08x:%d %s %s \"%s\" -> %s; %ld sec(s)\n", map->sequence, map->cid, map->state + 1, map->source, map->display, map->target, (long)(now - map->active));
        else
            printf("%08x:%d %s %s \"%s\" -> none; %ld secs\n", map->sequence, map->cid, map->state + 1, map->source, map->display, (long)(now - map->created));
    }
    exit(0);
}

static void periodic(char **argv)
{
    char text[80];

    if(argv[1])
        shell::errexit(1, "*** sipcontrol: pstats: no arguments used\n");

    mapinit();

    mapped_view<stats> sta(*statmap);
    unsigned count = sta.count();
    unsigned index = 0;
    const volatile stats *map;

    if(!count)
        shell::errexit(10, "*** sipcontrol: pstats: offline\n");

    while(index < count) {
        map = (const volatile stats *)(sta(index++));

        if(!map->id[0])
            continue;

        if(map->limit)
            snprintf(text, sizeof(text), "%-12s %05hu", map->id, map->limit);
        else
            snprintf(text, sizeof(text), "%-12s -    ", map->id);

        for(unsigned entry = 0; entry < 2; ++entry) {
            size_t len = strlen(text);
            snprintf(text + len, sizeof(text) - len, " %07lu %05hu %05hu",
                map->data[entry].pperiod,
                map->data[entry].pmin,
                map->data[entry].pmax);
        }
        printf("%s\n", text);
    }
    exit(0);
}

static void showevents(char **argv)
{
#ifdef  _MSWINDOWS_
    socket_t ipc = ::socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
#else
    socket_t ipc = ::socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    struct passwd *pwd = getpwuid(getuid());
    const char *userid = NULL;
#endif

    static string_t contact = "-";
    static string_t publish = "-";

    if(argv[1])
        shell::errexit(1, "*** sipcontrol: events: no arguments used\n");

    if(ipc == INVALID_SOCKET)
        shell::errexit(9, "*** sipcontrol: events: cannot create event socket\n");

    memset(&addr, 0, sizeof(addr));

#ifdef  _MSWINDOWS_
    DWORD port = 0;
    DWORD index = 0;
    TCHAR keyname[128];
    TCHAR keyvalue[128];
    DWORD size = sizeof(keyname), vsize = sizeof(keyvalue), vtype;
    DWORD *dp;

    HKEY keys = HKEY_LOCAL_MACHINE, subkey;
    if(RegOpenKeyEx(keys, "SOFTWARE\\sipwitch", 0, KEY_READ, &subkey) != ERROR_SUCCESS)
        shell::errexit(10, "*** sipcontrol: events: no service found\n");
    while((RegEnumValue(subkey, index++, keyname, &size, NULL, &vtype, (BYTE *)keyvalue, &vsize) == ERROR_SUCCESS) && (vtype == REG_DWORD) && (keyname[0] != 0)) {
        dp = (DWORD *)&keyvalue;
        if(eq("port", keyname))
            port = *dp;
//      else if(eq("pid", keyname))
//          pid = *dp;
        vsize = sizeof(keyvalue);
        size = sizeof(keyname);
    }
    RegCloseKey(subkey);
    if(!port)
        shell::errexit(10, "*** sipcontrol: events: server missing\n");
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((unsigned short)port);
    if(::connect(ipc, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        shell::errexit(10, "*** sipcontrol: events: server offline\n");
#else
    addr.sun_family = AF_UNIX;
    String::set(addr.sun_path, sizeof(addr.sun_path), DEFAULT_VARPATH "/run/sipwitch/events");
    if(::connect(ipc, (struct sockaddr *)&addr, SUN_LEN(&addr)) < 0) {
        if(pwd)
            userid = pwd->pw_name;
        if(!pwd || !userid)
            shell::errexit(4, "*** sipcontrol: events: invalid login\n");

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/sipwitch-%s/events", userid);
        if(::connect(ipc, (struct sockaddr *)&addr, SUN_LEN(&addr)) < 0)
            shell::errexit(10, "*** sipcontrol: events: server offline\n");
    }
#endif

    event_t event;
    while(::recv(ipc, (char *)&event, sizeof(event), 0) == sizeof(event)) {
        switch(event.type) {
        case events::FAILURE:
            printf("failure: %s\n", event.msg.reason);
            break;
        case events::WARNING:
            printf("warning: %s\n", event.msg.reason);
            break;
        case events::NOTICE:
            printf("notice:  %s\n", event.msg.reason);
            break;
        case events::CONTACT:
            if(!eq(contact, event.msg.contact)) {
                printf("contact: %s\n", event.msg.contact);
                contact ^= event.msg.contact;
            }
            break;
        case events::PUBLISH:
            if(!eq(publish, event.msg.contact)) {
                printf("publish: %s\n", event.msg.contact);
                publish ^= event.msg.contact;
            }
            break;
        case events::WELCOME:
            printf("server version %s %s\n",
                event.msg.server.version, event.msg.server.state);
            break;
        case events::TERMINATE:
            printf("exiting: %s\n", event.msg.reason);
            exit(0);
        case events::CALL:
            printf("connecting %s to %s on %s\n",
                event.msg.call.caller, event.msg.call.dialed, event.msg.call.network);
            break;
        case events::DROP:
            printf("disconnect %s from %s, reason=%s\n",
                event.msg.call.caller, event.msg.call.dialed, event.msg.call.reason);
            break;
        case events::RELEASE:
            if(event.msg.user.extension)
                printf("releasing %s, extension %d\n",
                    event.msg.user.id, event.msg.user.extension);
            else
                printf("releasing %s\n", event.msg.user.id);
            break;
        case events::ACTIVATE:
            if(event.msg.user.extension)
                printf("activating %s, extension %d\n",
                    event.msg.user.id, event.msg.user.extension);
            else
                printf("activating %s\n", event.msg.user.id);
            break;
        case events::STATE:
            printf("changing state to %s\n", event.msg.server.state);
            break;
        case events::REALM:
            printf("changing realm to %s\n", event.msg.server.realm);
            break;
        case events::SYNC:
            if(event.msg.period)
                printf("housekeeping period %d\n", event.msg.period);
            break;
        }
    }
    shell::errexit(11, "*** sipcontrol: events: connection lost\n");
}

static void dumpstats(char **argv)
{
    char text[80];
    time_t now;

    if(argv[1])
        shell::errexit(1, "*** sipcontrol: stats: no arguments used\n");

    mapinit();

    mapped_view<stats> sta(*statmap);
    unsigned count = sta.count();
    unsigned index = 0;
    stats map;
    unsigned current;

    if(!count)
        shell::errexit(10, "*** sipcontrol: stats: offline\n");

    time(&now);
    while(index < count) {
        sta.copy(index++, map);
        if(!map.id[0])
            continue;

        if(map.limit)
            snprintf(text, sizeof(text), "%-12s %05hu", map.id, map.limit);
        else
            snprintf(text, sizeof(text), "%-12s -    ", map.id);

        for(unsigned entry = 0; entry < 2; ++entry) {
            size_t len = strlen(text);
            snprintf(text + len, sizeof(text) - len, " %09lu %05hu %05hu",
                map.data[entry].total,
                map.data[entry].current,
                map.data[entry].peak);
        }
        current = map.data[0].current + map.data[1].current;
        if(current)
            printf("%s 0s\n", text);
        else if(!map.lastcall)
            printf("%s -\n", text);
        else if(now - map.lastcall > (3600l * 99l))
            printf("%s %ld%c\n", text, (long)((now - map.lastcall) / (3600l * 24l)), 'd');
        else if(now - map.lastcall > (60l * 120l))
            printf("%s %ld%c\n", text, (long)((now - map.lastcall) / 3600l), 'h');
        else if(now - map.lastcall > 120l)
            printf("%s %ld%c\n", text, (long)((now - map.lastcall) / 60l), 'm');
        else
            printf("%s %ld%c\n", text, (long)(now - map.lastcall), 's');
    }
    exit(0);
}

static void registry(char **argv)
{
    mapinit();

    mapped_view<MappedRegistry> reg(*regmap);
    unsigned count = reg.count();
    unsigned found = 0, index = 0;
    MappedRegistry buffer;
    time_t now;
    char ext[8], exp[8], use[8];
    const char *type;

    if(argv[1])
        shell::errexit(1, "*** sipcontrol: registry: too many arguments\n");

    if(!count)
        shell::errexit(10, "*** sipcontrol: registry: offline\n");

    time(&now);
    while(index < count) {
        reg.copy(index++, buffer);
        if(buffer.type == MappedRegistry::EXPIRED)
            continue;
        else if(buffer.type == MappedRegistry::TEMPORARY && !buffer.inuse)
            continue;

        if(!found++)
            printf("%7s %-30s type %-30s  use expires address\n", "ext", "user", "profile");
        ext[0] = 0;
        if(buffer.ext)
            snprintf(ext, sizeof(ext), "%7d", buffer.ext);
        exp[0] = '-';
        exp[1] = 0;
        snprintf(use, sizeof(use), "%u", buffer.inuse);
        if(buffer.expires && buffer.type != MappedRegistry::TEMPORARY)
            snprintf(exp, sizeof(exp), "%ld", (long)(buffer.expires - now));
        switch(buffer.type) {
        case MappedRegistry::REJECT:
            type = "rej";
            break;
        case MappedRegistry::REFER:
            type = "ref";
            break;
        case MappedRegistry::GATEWAY:
            type = "gw";
            break;
        case MappedRegistry::SERVICE:
            type = "svc";
            break;
        case MappedRegistry::TEMPORARY:
            type = "temp";
            break;
        default:
            type = "user";
        };
        printf("%7s %-30s %-4s %-30s %4s %7s ", ext, buffer.userid, type, buffer.profile.id, use, exp);
        paddress(&buffer.contact, NULL);
        fflush(stdout);
    }

    printf("found %d entries active of %d\n", found, count);
    exit(0);
}

static void command(char **argv, unsigned timeout)
{
    char buffer[512];
    size_t len;
    fd_t fd;

#ifdef  _MSWINDOWS_
    snprintf(buffer, sizeof(buffer), "\\\\.\\mailslot\\sipwitch_ctrl");
    fd = CreateFile(buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
    sigset_t sigs;
    int signo;
    struct passwd *pwd = getpwuid(getuid());
    const char *userid = NULL;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGUSR1);
    sigaddset(&sigs, SIGUSR2);
    sigaddset(&sigs, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    fd = ::open(DEFAULT_VARPATH "/run/sipwitch/control", O_WRONLY | O_NONBLOCK);
    if(fd < 0) {
        if(pwd)
            userid = pwd->pw_name;
        if(!pwd || !userid)
            shell::errexit(4, "*** sipcontrol: events: invalid login\n");

        snprintf(buffer, sizeof(buffer), "/tmp/sipwitch-%s/control", userid);
        fd = ::open(buffer, O_WRONLY | O_NONBLOCK);
    }
#endif

    if(fd == INVALID_HANDLE_VALUE)
        shell::errexit(10, "*** sipcontrol: command: offline\n");

#ifndef _MSWINDOWS_
    if(timeout)
        snprintf(buffer, sizeof(buffer), "%ld", (long)getpid());
    else
#endif
        buffer[0] = 0;

    while(*argv) {
        len = strlen(buffer);
        snprintf(buffer + len, sizeof(buffer) - len - 1, " %s", *(argv++));
    }

#ifdef  _MSWINDOWS_
    if(!WriteFile(fd, buffer, (DWORD)strlen(buffer) + 1, NULL, NULL))
        shell::errexit(11, "*** sipcontrol: control failed\n");
#else
    len = strlen(buffer);
    buffer[len++] = '\n';
    buffer[len] = 0;

    if(::write(fd, buffer, len) < (int)len)
        shell::errexit(11, "*** sipcontrol: control failed\n");

    if(!timeout)
        exit(0);

    alarm(timeout);
#ifdef  HAVE_SIGWAIT2
    sigwait(&sigs, &signo);
#else
    signo = sigwait(&sigs);
#endif
    if(signo == SIGUSR1) {
        capture();
        exit(0);
    }
    if(signo == SIGALRM)
        shell::errexit(12, "*** sipcontrol: command: timed out\n");

    shell::errexit(20, "*** sipcontrol: command: request failed\n");
#endif
}

static void version(void)
{
    printf("SIP Witch " VERSION "\n"
        "Copyright (C) 2007,2008,2009 David Sugar, Tycho Softworks\n"
        "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n");
    exit(0);
}

static void usage(void)
{
    printf("usage: sipcontrol command\n"
        "Commands:\n"
        "  abort                    Force daemon abort\n"
        "  activate <ext> <ipaddr>  Assign registration\n"
        "  address <ipaddr>         Set public ip address\n"
        "  calls                    List active calls on server\n"
        "  check                    Server deadlock check\n"
        "  concurrency <level>      Server concurrency level\n"
        "  contact                  Server contact config address\n"
        "  digest id [realm [type]] Compute a digest\n"
        "  disable conf-id...       Disable configurations\n"
        "  down                     Shut down server\n"
        "  drop <user|callid>       Drop an active call\n"
        "  dump                     Dump server configuration\n"
        "  enable conf-id...        Enable configurations\n"
        "  events                   Display server events\n"
        "  grant <group>            Grant dir access to system group\n"
        "  history [bufsize]        Set buffer or dump error log\n"
        "  ifup <iface>             Notify interface came up\n"
        "  ifdown <iface>           Notify interface went down\n"
        "  message <ext> <text>     Send text message to extension\n"
        "  peering                  Print peering (published) address\n"
        "  period <interval>        Collect periodic statistics\n"
        "  pstats                   Dump periodic statistics\n"
        "  realm [text [digest]]    Show or set new server realm\n"
        "  registry                 Dump registry\n"
        "  release <ext>            Release registration\n"
        "  reload                   Reload configuration\n"
        "  restart                  Server restart\n"
        "  siplog                   Dump sip log when tracing\n"
        "  snapshot                 Server snapshot\n"
        "  stats                    Dump server statistics\n"
        "  state <selection>        Change server state\n"
        "  status                   Dump status string\n"
        "  trace <on|off|clear>     Set sip message tracing\n"
        "  usercache                Dump user cache\n"
        "  verbose <level>          Server verbose logging level\n"
    );

    printf("Report bugs to sipwitch-devel@gnu.org\n");
    exit(0);
}

static void single(char **argv, int timeout)
{
    if(argv[1])
        shell::errexit(1, "*** sipcontrol: %s: too many arguments\n", *argv);

    command(argv, timeout);
}

static void level(char **argv, int timeout)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: %s: level missing\n", *argv);

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: %s: too many arguments\n", *argv);

    command(argv, timeout);
}

static void period(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: period: interval missing\n");

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: period: too many arguments\n");

    command(argv, 10);
}

static void address(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: address: ipaddr missing\n");

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: address: too many arguments\n");

    command(argv, 10);
}

static void state(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: state: value missing\n");

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: state: too many arguments\n");

    command(argv, 10);
}

static void iface(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: %s: interface missing\n", *argv);

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: %s: too many arguments\n", *argv);

    command(argv, 20);
}

static void drop(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: drop: user or callid missing\n");

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: drop: too many arguments\n");

    command(argv, 10);
}

static void release(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: release: extension missing\n");

    if(argv[2])
        shell::errexit(1, "*** sipcontrol: release: too many arguments\n");

    command(argv, 10);
}

static void activate(char **argv)
{
    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: activate: extension missing\n");

    if(!argv[2])
        shell::errexit(1, "*** sipcontrol: activate: ipaddr missing\n");

    if(argv[3])
        shell::errexit(1, "*** sipcontrol: activate: too many arguments\n");

    command(argv, 10);
}

static void message(char **argv)
{
    char buffer[500];

    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: message: extension missing\n");

    if(!argv[2])
        shell::errexit(1, "*** sipcontrol: message: \"text\" missing\n");

    if(argv[3])
        shell::errexit(1, "*** sipcontrol: message: too many arguments\n");

    if(argv[2][0] != '{') {
        snprintf(buffer, sizeof(buffer), "{%s}", argv[2]);
        argv[2] = buffer;
    }
    command(argv, 10);
}

#ifdef  HAVE_PWD_H
static void grant(char **argv)
{
    gid_t gid = -1;
    struct group *grp;
    fsys::fileinfo_t ino;

    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: grant: no group specified\n");
    if(argv[2])
        shell::errexit(1, "*** sipcontrol: grant: not more than one group\n");

    grp = getgrnam(argv[1]);
    if(grp)
        gid = grp->gr_gid;
    else if(atol(argv[1]))
        gid = atol(argv[1]);
    else
        shell::errexit(2, "*** sipcontrol: grant: %s: unknown group", argv[1]);

    fsys::info(DEFAULT_VARPATH "/lib/sipwitch", &ino);
    chmod(DEFAULT_VARPATH "/lib/sipwitch", ino.st_mode | 070);
    if(chown(DEFAULT_VARPATH "/lib/sipwitch", ino.st_uid, gid))
        shell::errexit(2, "*** sipcontrol: grant: %s: cannot change owner", argv[1]);

    fsys::info(DEFAULT_VARPATH "/cache/sipwitch", &ino);
    chmod(DEFAULT_VARPATH "/cache/sipwitch", ino.st_mode | 070);
    if(chown(DEFAULT_VARPATH "/cache/sipwitch", ino.st_uid, gid))
        shell::errexit(2, "*** sipcontrol: grant: %s: cannot change owner", argv[1]);

    exit(0);
}
#else
static void grant(char **argv)
{
    shell::errexit(9, "*** sipcontrol: grant: unsupported platform");
}
#endif

#ifdef  _MSWINDOWS_

static void enable(char **argv)
{
    shell::errexit(9, "*** sipcontrol: enable: unsupported platform");
}

static void disable(char **argv)
{
    shell::errexit(9, "*** sipcontrol: disable: unsupported platform");
}

#else

static void enable(char **argv)
{
    char source[128], target[128];

    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: enable: no configs specified\n");

    while(*(++argv)) {
        snprintf(source, sizeof(source), "%s/sipwitch.d/%s.xml", DEFAULT_CFGPATH, *argv);
        snprintf(target, sizeof(target), "%s/lib/sipwitch/%s.xml", DEFAULT_VARPATH, *argv);
        fsys::link(source, target);
    }
    exit(0);
}

static void disable(char **argv)
{
    char target[128];

    if(!argv[1])
        shell::errexit(1, "*** sipcontrol: disable: no configs specified\n");

    while(*(++argv)) {
        snprintf(target, sizeof(target), "%s/lib/sipwitch/%s.xml", DEFAULT_VARPATH, *argv);
        fsys::erase(target);
    }
    exit(0);
}

#endif

PROGRAM_MAIN(argc, argv)
{
    if(argc < 2)
        usage();

    ++argv;
    if(eq(*argv, "version") || eq(*argv, "-version") || eq(*argv, "--version"))
        version();
    else if(eq(*argv, "help") || eq(*argv, "-help") || eq(*argv, "--help"))
        usage();
    else if(eq(*argv, "reload") || eq(*argv, "check") || eq(*argv, "snapshot") || eq(*argv, "dump") || eq(*argv, "siplog") || eq(*argv, "usercache") || eq(*argv, "policy") || eq(*argv, "contact"))
        single(argv, 30);
    else if(eq(*argv, "history")) {
        if(argc == 2)
            single(argv, 30);
        else
            level(argv, 10);
    }
    else if(eq(*argv, "down") || eq(*argv, "restart") || eq(*argv, "abort"))
        single(argv, 0);
    else if(eq(*argv, "verbose") || eq(*argv, "concurrency") || eq(*argv, "trace"))
        level(argv, 10);
    else if(eq(*argv, "message"))
        message(argv);
    else if(eq(*argv, "registry"))
        registry(argv);
    else if(eq(*argv, "stats"))
        dumpstats(argv);
    else if(eq(*argv, "calls"))
        calls(argv);
    else if(eq(*argv, "digest"))
        compute(argv);
    else if(eq(*argv, "pstats"))
        periodic(argv);
    else if(eq(*argv, "address"))
        address(argv);
    else if(eq(*argv, "period"))
        period(argv);
    else if(eq(*argv, "activate"))
        activate(argv);
    else if(eq(*argv, "release"))
        release(argv);
    else if(eq(*argv, "state"))
        state(argv);
    else if(eq(*argv, "status"))
        status(argv);
    else if(eq(*argv, "ifdown") || eq(*argv, "ifup"))
        iface(argv);
    else if(eq(*argv, "realm"))
            realm(argv);
    else if(eq(*argv, "drop"))
        drop(argv);
    else if(eq(*argv, "grant"))
        grant(argv);
    else if(eq(*argv, "enable"))
        enable(argv);
    else if(eq(*argv, "disable"))
        disable(argv);
    else if(eq(*argv, "events"))
        showevents(argv);

    if(!argv[1])
        shell::errexit(1, "use: sipcontrol command [arguments...]\n");
    else
        shell::errexit(1, "*** sipcontrol: %s: unknown command or option\n", argv[0]);
    PROGRAM_EXIT(1);
}

