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

#ifndef _MSWINDOWS_

#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <errno.h>

#endif

using namespace SIPWITCH_NAMESPACE;
using namespace UCOMMON_NAMESPACE;

static shell::flagopt helpflag('h',"--help",    _TEXT("display this list"));
static shell::flagopt althelp('?', NULL, NULL);
static shell::flagopt backflag('b', "--background", _TEXT("run in background"));
static shell::numericopt concurrency('c', "--concurrency", _TEXT("process concurrency"), "level");
static shell::flagopt desktop(0, "--desktop", _TEXT("enable desktop access"));
static shell::flagopt foreflag('f', "--foreground", _TEXT("run in foreground"));
#ifdef  HAVE_PWD_H
static shell::stringopt group('g', "--group", _TEXT("use specified group permissions"), "groupid", "nobody");
#endif
static shell::numericopt histbuf('h', "--history", _TEXT("set history buffer"), "count", 0);
static shell::stringopt loglevel('L', "--logging", _TEXT("set log level"), "level", "err");
static shell::stringopt loading('l', "--plugins", _TEXT("specify modules to load"), "names", "none");
static shell::counteropt priority('p', "--priority", _TEXT("set priority level"), "level");
static shell::flagopt restart('r', "--restartable", _TEXT("set to restartable process"));
static shell::flagopt trace('t', "--trace", _TEXT("trace sip messages"));
#ifdef HAVE_PWD_H
static shell::stringopt user('u', "--user", _TEXT("user to run as"), "userid", "nobody");
#endif
static shell::flagopt verbose('v', NULL, _TEXT("set verbosity, can be used multiple times"), false);
static shell::flagopt version(0, "--version", _TEXT("show version information"));
static shell::numericopt debuglevel('x', "--debug", _TEXT("set debug level directly"), "level", 0);

#if defined(HAVE_SETRLIMIT) && defined(DEBUG)
#include <sys/time.h>
#include <sys/resource.h>

static void corefiles(void)
{
    struct rlimit core;

    assert(getrlimit(RLIMIT_CORE, &core) == 0);
#ifdef  MAX_CORE_SOFT
    core.rlim_cur = MAX_CORE_SOFT;
#else
    core.rlim_cur = RLIM_INFINITY;
#endif
#ifdef  MAX_CORE_HARD
    core.rlim_max = MAX_CORE_HARD;
#else
    core.rlim_max = RLIM_INFINITY;
#endif
    assert(setrlimit(RLIMIT_CORE, &core) == 0);
}
#else
static void corefiles(void)
{
}
#endif

static void usage(void)
{
#if defined(DEBUG)
    printf("%s\n", _TEXT("Usage: sipw [debug] [options]"));
#else
    printf("%s\n", _TEXT("Usage: sipw [options]"));
#endif
    printf("%s\n\n", _TEXT("Start sipwitch service"));
    printf("%s\n", _TEXT("Options:"));
    shell::help();
    #if defined(DEBUG)
    printf("%s", _TEXT(
        "\nDebug Options:\n"
        "  --dbg            execute command in debugger\n"
        "  --memcheck       execute with valgrind memory check\n"
        "  --memleak        execute with valgrind leak detection\n"
        "\n"
    ));
#endif

    printf("\n%s\n", _TEXT("Report bugs to sipwitch-devel@gnu.org"));
    exit(0);
}

static void versioninfo(void)
{
    printf("SIP Witch " VERSION "\n%s", _TEXT(
        "Copyright (C) 2007,2008,2009 David Sugar, Tycho Softworks\n"
        "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
        "This is free software: you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law.\n"));
    exit(0);
}

static bool errlog(shell::loglevel_t level, const char *text)
{
    switch(level) {
    case shell::WARN:
        events::warning(text);
        break;
    case shell::FAIL:
        events::terminate(text);
        break;
    case shell::ERR:
        events::failure(text);
    default:
        break;
    }
    modules::errlog(level, text);
    history::add(level, text);
    return false;
}

namespace SIPWITCH_NAMESPACE {

    static void up(void)
    {
        server::reload();
        server::startup();

        if(is(trace))
            stack::enableDumping();

        signals::start();
        events::start();
        server::run();

        events::terminate("server shutdown");
        signals::stop();
        service::shutdown();
        control::release();
    }
}

static void init(int argc, char **argv, bool detached, shell::mainproc_t svc = NULL)
{

    bool daemon = true;
    const char *cp;
    const char *prefix;
    const char *rundir;
    const char *plugins = argv[0];
    shell args;

    shell::bind("sipwitch");
    corefiles();

#if defined(DEBUG)
    if(eq(argv[1], "-gdb") || eq(argv[1], "--gdb") || eq(argv[1], "-dbg") || eq(argv[1], "--dbg")) {
        char *dbg[] = {(char *)"gdb", (char *)"--args", NULL};
        const char *cp = args.getenv("DEBUGGER");
        if(cp && *cp)
            dbg[0] = (char *)cp;
        args.restart(argv[0], &argv[2], dbg);
    }

    if(eq(argv[1], "-memcheck") || eq(argv[1], "--memcheck")) {
        char *mem[] = {(char *)"valgrind", (char *)"--tool=memcheck", NULL};
        args.restart(argv[0], &argv[2], mem);
    }

    if(eq(argv[1], "-memleak") || eq(argv[1], "--memleak")) {
        char *mem[] = {(char *)"valgrind",
            (char *)"--tool=memcheck", (char *)"--leak-check=yes", NULL};
        args.restart(argv[0], &argv[2], mem);
    }
#endif

    // cheat out shell parser...
    argv[0] = (char *)"sipwitch";

    args.setsym("statmap", STAT_MAP);
    args.setsym("callmap", CALL_MAP);
    args.setsym("regmap", REGISTRY_MAP);

#ifdef _MSWINDOWS_
    rundir = strdup(str(args.getenv("APPDATA")) + "/sipwitch");
    prefix = "C:\\Program Files\\sipwitch";
    plugins = "C:\\Program Files\\sipwitch\\plugins";
    args.setsym("config", _STR(str(prefix) + "/sipwitch.ini"));
    args.setsym("controls", rundir);
    args.setsym("control", "\\\\.\\mailslot\\sipwitch_ctrl");
    args.setsym("logfiles", _STR(str(prefix) + "/logs"));
    args.setsym("siplogs", _STR(str(prefix) + "/logs/siptrace.log"));
    args.setsym("logfile", _STR(str(prefix) + "/logs/sipwitch.log"));
    args.setsym("calls", _STR(str(prefix) + "/logs/sipwitch.calls"));
    args.setsym("stats", _STR(str(prefix) + "/logs/sipwitch.stats"));
    args.setsym("prefix", rundir);
    args.setsym("shell", "cmd.exe");
    prefix = rundir;
#else
    prefix = DEFAULT_VARPATH "/lib/sipwitch";
    rundir = DEFAULT_VARPATH "/run/sipwitch";
    args.setsym("reply", "/tmp/.sipwitch.");
    args.setsym("config", DEFAULT_CFGPATH "/sipwitch.conf");
    args.setsym("controls", DEFAULT_VARPATH "/run/sipwitch");
    args.setsym("control", DEFAULT_VARPATH "/run/sipwitch/control");
    args.setsym("events", DEFAULT_VARPATH "/run/sipwitch/events");
    args.setsym("config", DEFAULT_CFGPATH "/sipwitch.conf");
    args.setsym("logfiles", DEFAULT_VARPATH "/log");
    args.setsym("siplogs", DEFAULT_VARPATH "/log/siptrace.log");
    args.setsym("logfile", DEFAULT_VARPATH "/log/sipwitch.log");
    args.setsym("calls", DEFAULT_VARPATH "/log/sipwitch.calls");
    args.setsym("stats", DEFAULT_VARPATH "/log/sipwitch.stats");
    args.setsym("prefix", DEFAULT_VARPATH "/lib/sipwitch");
    args.setsym("shell", "/bin/sh");
#endif

#ifdef  HAVE_PWD_H
    struct passwd *pwd = getpwuid(getuid());
    umask(007);

    if(getuid() && pwd && pwd->pw_dir && *pwd->pw_dir == '/') {
        args.setsym("prefix", pwd->pw_dir);
        if(!eq(pwd->pw_shell, "/bin/false") && !eq(pwd->pw_dir, "/var/", 5) && !eq(pwd->pw_dir, "/srv/", 5)) {
            umask(077);
            daemon = false;
        };
    }

    if(!getuid())
        plugins = DEFAULT_LIBPATH "/sipwitch";

    if(!daemon && pwd) {
        rundir = strdup(str("/tmp/sipwitch-") + str(pwd->pw_name));
        prefix = strdup(str(pwd->pw_dir) + "/.sipwitch");

        args.setsym("statmap", _STR(str(STAT_MAP "-") + str(pwd->pw_name)));
        args.setsym("callmap", _STR(str(CALL_MAP "-") + str(pwd->pw_name)));
        args.setsym("regmap", _STR(str(REGISTRY_MAP "-") + str(pwd->pw_name)));

        args.setsym("config", _STR(str(pwd->pw_dir) + "/.sipwitchrc"));
        args.setsym("controls", rundir);
        args.setsym("control", _STR(str(rundir) + "/control"));
        args.setsym("events", _STR(str(rundir) + "/events"));
        args.setsym("logfiles", rundir);
        args.setsym("siplogs", _STR(str(rundir) + "/siplogs"));
        args.setsym("logfile", _STR(str(rundir) + "/logfile"));
        args.setsym("calls", _STR(str(rundir) + "/calls"));
        args.setsym("stats", _STR(str(rundir) + "/stats"));
        args.setsym("prefix", prefix);
        args.setsym("shell", pwd->pw_shell);
    }

#else
    if(argv[1])
        daemon = false;
#endif

#ifdef  HAVE_PWD_H
    cp = args.getenv("GROUP");
    if(cp && *cp)
        group.set(cp);

    cp = args.getenv("USER");
    if(cp && *cp)
        user.set(cp);

    // root gets these from default to act as user daemon...

    if(!getuid()) {
        cp = getenv("FIRSTUID");
        if(!cp)
            cp = getenv("UID");

        if(cp && *cp)
            server::uid = atoi(cp);

        cp = getenv("SIPUSERS");
        if(cp && *cp)
            server::sipusers = strdup(cp);

        cp = getenv("SIPADMIN");
        if(cp && *cp)
            server::sipadmin = strdup(cp);
    }

#endif

    cp = args.getenv("CONCURRENCY");
    if(cp && *cp)
        concurrency.set(atol(cp));

    cp = args.getenv("PRIORITY");
    if(cp && *cp)
        priority.set(atol(cp));

    cp = args.getenv("VERBOSE");
    if(cp && *cp)
        loglevel.set(strdup(cp));

    cp = args.getenv("LOGGING");
    if(cp && *cp)
        loglevel.set(strdup(cp));

    cp = args.getenv("LOGGING");
    if(cp && *cp)
        histbuf.set(atoi(cp));

    cp = args.getenv("PLUGINS");
    if(cp && *cp)
        loading.set(strdup(cp));

    // parse and check for help
    args.parse(argc, argv);
    if(is(helpflag) || is(althelp) || args.argc() > 0)
        usage();

    if(is(version))
        versioninfo();

    // check validity of some options...

    if(*concurrency < 0)
        shell::errexit(1, "sipwitch: concurrency: %ld: %s\n",
            *concurrency, _TEXT("negative levels invalid"));

    if(*histbuf < 0)
        shell::errexit(1, "sipwitch: history: %ld: %s\n",
            *histbuf, _TEXT("negative buffer limit invalid"));

    // set threading properties...

    if(*concurrency > 0)
        Thread::concurrency(*concurrency);

    shell::priority(*priority);

#ifdef  SCHED_RR
    if(*priority > 0)
        Thread::policy(SCHED_RR);
#endif

    // fore and background...

    if(is(backflag))
        daemon = true;

    if(is(foreflag))
        daemon = false;


   // lets play with verbose level and logging options

    if(is(verbose))
        verbose.set(*verbose + (unsigned)shell::INFO);
    else {
        if(atoi(*loglevel) > 0)
            verbose.set(atoi(*loglevel));
        else if(eq(*loglevel, "0") || eq(*loglevel, "no", 2) || eq(*loglevel, "fail", 4))
            verbose.set((unsigned)shell::FAIL);
        else if(eq(*loglevel, "err", 3))
            verbose.set((unsigned)shell::ERR);
        else if(eq(*loglevel, "warn", 4))
            verbose.set((unsigned)shell::WARN);
        else if(eq(*loglevel, "noti", 4))
            verbose.set((unsigned)shell::NOTIFY);
        else if(eq(*loglevel, "info"))
            verbose.set((unsigned)shell::INFO);
        else if(eq(*loglevel, "debug", 5))
            verbose.set((unsigned)shell::DEBUG0 + atoi(*loglevel + 5));
    }

    if(is(debuglevel))
        verbose.set((unsigned)shell::DEBUG0 + *debuglevel);

#ifdef  HAVE_PWD_H
    pwd = NULL;
    struct group *grp = NULL;

    // if root user, then see if we change permissions...

    if(!getuid()) {
        if(is(user)) {
            if(atoi(*user))
                pwd = getpwuid(atoi(*user));
            else
                pwd = getpwnam(*user);
            if(!pwd)
                shell::errexit(2, "*** sipw: %s: %s\n", *user,
                    _TEXT("unknown or invalid user id"));
        }
    }

    if(is(group)) {
        if(atoi(*group))
            grp = getgrgid(atoi(*group));
        else
            grp = getgrnam(*group);
        if(!grp)
            shell::errexit(2, "*** sipw: %s: %s\n", *group,
                _TEXT("unknown or invalid group id"));
    }

    if(grp) {
        umask(007);
        setgid(grp->gr_gid);
    }

    int uid = 0;

    if(pwd) {
        umask(007);
        if(!grp)
            setgid(pwd->pw_gid);
        uid = pwd->pw_uid;
    }

    endgrent();
    endpwent();

    if(is(desktop))
        umask(002);
#endif

    fsys::createDir(rundir, 0775);
    fsys::createDir(prefix, 0770);
    if(fsys::changeDir(prefix))
        shell::errexit(3, "*** sipwitch: %s: %s\n",
            prefix, _TEXT("data directory unavailable"));

    shell::loglevel_t level = (shell::loglevel_t)*verbose;
    history::set(*histbuf);
    server::plugins(plugins, *loading);

    // daemonify process....
    if(daemon) {
        if(!detached)
            args.detach(svc);
        server::logmode = shell::CONSOLE_LOG;
    }
    else
        shell::log("sipwitch", level, server::logmode, &errlog);

    signals::setup();

    const char *home = getenv("HOME");

#ifdef  _MSWINDOWS_
    if(!home)
        home = getenv("USERPROFILE");
#endif

    if(!home)
        home = args.getenv("prefix");

    args.setsym("HOME", home);

    if(!control::attach(&args))
        shell::errexit(1, "*** sipwitch: %s\n",
            _TEXT("no control file; exiting"));

    // drop root privilege
#ifdef  HAVE_PWD_H
    if(uid)
        setuid(uid);
#endif

    if(is(restart))
        args.restart();

    up();
}

// stub code for windows service daemon...

static SERVICE_MAIN(main, argc, argv)
{
    signals::service("sipwitch");
    init(argc, argv, true);
}

PROGRAM_MAIN(argc, argv)
{
    init(argc, argv, false, &service_main);
    PROGRAM_EXIT(0);
}
