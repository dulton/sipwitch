// Copyright (C) 2008-2010 David Sugar, Tycho Softworks.
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
#include <eXosip2/eXosip.h>
#include <ucommon/ucommon.h>

static int verbose = 0;
static int port = 0;
static int family = AF_INET;
static int protocol = IPPROTO_UDP;
static const char *server = NULL;
static const char *forwarded = NULL;
static const char *proxy = NULL;
static const char *binding = NULL;
static unsigned timeout = 1000;
static int tls = 0;

#ifdef  EXOSIP_OPT_BASE_OPTION
#define EXOSIP_CONTEXT  context
#define OPTION_CONTEXT  context,
static struct eXosip_t *context = NULL;
#else
#define EXOSIP_CONTEXT
#define OPTION_CONTEXT
#endif


#if defined(_MSWINDOWS_) && defined(__GNUC__)
// binds addrinfo for mingw32 linkage since otherwise mingw32 cannot
// cannot link proper getaddrinfo/freeaddrinfo calls that eXosip uses.
static Socket::address localhost("127.0.0.1");
#endif

using namespace UCOMMON_NAMESPACE;

PROGRAM_MAIN(argc, argv)
{
    int error = 2;
    eXosip_event_t *sevent;
    const char *cp, *user;
    char buffer[256];
    char pbuffer[256];
    char tbuffer[256];
    osip_message_t *msg = NULL;
    int rid;
    osip_contact_t *contact;
    int pos = 0;
    int stop = 0;

    cp = getenv("SIP_PROXY");
    if(cp)
        proxy = cp;

    cp = getenv("SIP_SERVER");
    if(cp)
        server = cp;


    while(NULL != *(++argv)) {
        if(!strcmp(*argv, "--")) {
            ++argv;
            break;
        }

        if(!strncmp(*argv, "--", 2))
            ++*argv;

        if(!strcmp(*argv, "-q") || !strcmp(*argv, "-quiet")) {
            verbose = 0;
            continue;
        }

        if(!strcmp(*argv, "-version")) {
            printf("sipquery 0.1\n"
                "Copyright (C) 2008 David Sugar, Tycho Softworks\n"
                "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
                "This is free software: you are free to change and redistribute it.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n");
            exit(0);
        }

        if(!strcmp(*argv, "-v") || !strcmp(*argv, "-verbose")) {
            verbose = 1;
            continue;
        }


        if(!strcmp(*argv, "-t") || !strcmp(*argv, "-timeout")) {
            if(NULL == *(++argv))
                shell::errexit(3, "*** sipuser: timeout option missing timeout\n");
            timeout = atoi(*argv) * 1000;
            if(!timeout)
                shell::errexit(3, "*** sipuser: timeout option invalid\n");

            continue;
        }

        if(!strncmp(*argv, "-timeout=", 9)) {
            timeout = atoi(*argv + 9) * 1000;
            if(!timeout)
                shell::errexit(3, "*** sipuser: timeout option invalid\n");

            continue;
        }

        if(!strcmp(*argv, "-p") || !strcmp(*argv, "-port")) {
            if(NULL == *(++argv))
                shell::errexit(3, "*** sipuser: port option missing port\n");

            port = atoi(*argv);
            if(!port)
                shell::errexit(3, "*** sipuser: port option invalid number\n");

            continue;
        }

        if(!strncmp(*argv, "-port=", 6)) {
            port = atoi(*argv + 6);
             if(!port)
                shell::errexit(3, "*** sipuser: port option invalid number\n");

            continue;
        }

        if(!strcmp(*argv, "-proxy")) {
            proxy = *(++argv);
            if(!proxy)
                shell::errexit(3, "*** sipuser: proxy option missing proxy\n");
            continue;
        }

        if(!strncmp(*argv, "-proxy=", 7)) {
            proxy = *argv + 7;
            continue;
        }

        if(!strcmp(*argv, "-server")) {
            server = *(++argv);
            if(!server)
                shell::errexit(3, "*** sipuser: server option missing proxy\n");
            continue;
        }

        if(!strncmp(*argv, "-server=", 8)) {
            server = *argv + 8;
            continue;
        }

        if(!strcmp(*argv, "-forward")) {
            forwarded = *(++argv);
            if(!forwarded)
                shell::errexit(3, "*** sipuser: forwarding option missing interface\n");
            continue;
        }

        if(!strncmp(*argv, "-forward=", 9)) {
            forwarded = *argv + 8;
            continue;
        }

        if(!strcmp(*argv, "-?") || !strcmp(*argv, "-h") || !strcmp(*argv, "-help")) {
            fprintf(stderr, "usage: sipuser [options] userid\n"
                "[options]\n"
                "  -proxy    sip:proxyhost[:port]\n"
                "  -server   sip:server[:port]\n"
                "  -forward  ip-address\n"
                "  -port     port-numer\n"
                "  -timeout  seconds\n"
                "  -verbsose\n"
                "Report bugs to sipwitch-devel@gnu.org\n");
            exit(3);
        }

        if(**argv == '-')
            shell::errexit(3, "*** sipuser: %s: unknown option\n", *argv);

        break;
    }

    if(!*argv) {
usage:
        shell::errexit(3, "use: sipuser [options] userid\n");
    }

    user = *(argv++);
    if(*argv)
        goto usage;

#if defined(WIN32) || defined(_WIn32)
    if(!port)
        port = 5060;
#else
    if(!port)
        port = 5060 + getuid();
#endif

#ifdef  EXOSIP_OPT_BASE_OPTION
    context = eXosip_malloc();
#endif

    if(eXosip_init(EXOSIP_CONTEXT))
        shell::errexit(3, "*** sipuser: failed exosip init\n");

#ifdef  AF_INET6
    if(family == AF_INET6) {
        eXosip_enable_ipv6(1);
        if(binding == NULL)
            binding = "::0";
    }
#endif

    if(eXosip_listen_addr(OPTION_CONTEXT protocol, binding, port, family, tls)) {
#ifdef  AF_INET6
        if(!binding && family == AF_INET6)
            binding = "::0";
#endif
        if(!binding)
            binding = "*";
        shell::errexit(3, "*** sipuser: failed to listen %s:%d\n", binding, port);
    }

    if(forwarded)
        eXosip_masquerade_contact(OPTION_CONTEXT forwarded, port);

    eXosip_set_user_agent(OPTION_CONTEXT "SIPW/sipquery");

    if(!strncmp(user, "sip:", 4)) {
        tls = 0;
        user += 4;
    }
    else if(!strncmp(user, "sips:", 5)) {
        tls = 1;
        user += 5;
    }

    if(!server && strchr(user, '@')) {
        server = strchr(user, '@');
        ++server;
    }

    if(server && !strncmp(server, "sip:", 4))
        server += 4;
    else if(server && !strncmp(server, "sips:", 5))
        server += 5;

#ifdef  AF_INET6
    if(family == AF_INET6 && server == NULL)
        server = "::1";
#endif
    if(server == NULL)
        server = "127.0.0.1";

    if(!proxy)
        proxy = server;

    if(strncmp(proxy, "sip:", 4) && strncmp(proxy, "sips:", 5)) {
        if(tls)
            snprintf(pbuffer, sizeof(pbuffer), "sips:%s", proxy);
        else
            snprintf(pbuffer, sizeof(pbuffer), "sip:%s", proxy);
        proxy = pbuffer;
    }

    if(tls && !strchr(user, '@'))
        snprintf(buffer, sizeof(buffer), "sips:%s@%s", user, server);
    else if(!strchr(user, '@'))
        snprintf(buffer, sizeof(buffer), "sip:%s@%s", user, server);
    else if(tls)
        snprintf(buffer, sizeof(buffer), "sips:%s", user);
    else
        snprintf(buffer, sizeof(buffer), "sip:%s", user);


    eXosip_lock(EXOSIP_CONTEXT);
    rid = eXosip_register_build_initial_register(OPTION_CONTEXT buffer, proxy, NULL, 60, &msg);
    if(!msg) {
        eXosip_unlock(EXOSIP_CONTEXT);
        shell::errexit(3, "*** sipuser: cannot create query for %s\n", user);
    }
    snprintf(tbuffer, sizeof(tbuffer), "<%s>", buffer);
    osip_message_set_to(msg, tbuffer);
    osip_list_ofchar_free(&msg->contacts);
    eXosip_register_send_register(OPTION_CONTEXT rid, msg);
    eXosip_unlock(EXOSIP_CONTEXT);

    while(!stop) {
        sevent = eXosip_event_wait(OPTION_CONTEXT 0, timeout);
        if(!sevent)
            shell::errexit(2, "*** sipuser: timed out\n");

        if(sevent->type == EXOSIP_REGISTRATION_FAILURE) {
            error = 1;
            ++stop;
        }

        if(sevent->type == EXOSIP_REGISTRATION_SUCCESS) {
            pos = 0;
            while(verbose && sevent->response && !osip_list_eol(OSIP2_LIST_PTR sevent->response->contacts, pos)) {
                contact = (osip_contact_t *)osip_list_get(OSIP2_LIST_PTR sevent->response->contacts, pos++);
                if(contact && contact->url)
                    printf("%s:%s@%s:%s\n",
                        contact->url->scheme, contact->url->username,
                        contact->url->host, contact->url->port);
            }
            error = 0;
            ++stop;
        }

        eXosip_event_free(sevent);
    }
    eXosip_register_remove(OPTION_CONTEXT rid);
    eXosip_quit(EXOSIP_CONTEXT);
    PROGRAM_EXIT(error);
}

