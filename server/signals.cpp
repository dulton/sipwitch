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

#ifdef HAVE_SIGWAIT

signals signals::thread;

signals::signals() :
JoinableThread()
{
	shutdown = started = false;
}

signals::~signals()
{
	if(!shutdown)
		cancel();
}

void signals::cancel(void)
{
	if(started) {
        shutdown = true;
#ifdef  __FreeBSD__
        raise(SIGINT);
#endif
        pthread_kill(tid, SIGALRM);
        join();
    }
}

void signals::run(void)
{
	int signo;
	unsigned period = 900;

	started = true;
	shell::log(DEBUG1, "starting signal handler");

	for(;;) {
		alarm(period);
#ifdef	HAVE_SIGWAIT2
		sigwait(&sigs, &signo);
#else
		signo = sigwait(&sigs);
#endif
		alarm(0);
		if(shutdown)
			return;

		shell::log(DEBUG1, "received signal %d", signo);

		switch(signo) {
		case SIGALRM:
            shell::log(shell::INFO, "system housekeeping");
            registry::cleanup(period);
            break;
		case SIGINT:
		case SIGTERM:
			process::control("down");
			break;
		case SIGUSR1:
            process::control("snapshot");
			break;
		case SIGHUP:
            process::control("reload");
			break;
		default:
			break;
		}
	}
	shell::log(DEBUG1, "stopping signal handler");
}

void signals::setup(void)
{
    sigemptyset(&thread.sigs);
    sigaddset(&thread.sigs, SIGALRM);
    sigaddset(&thread.sigs, SIGHUP);
    sigaddset(&thread.sigs, SIGINT);
    sigaddset(&thread.sigs, SIGTERM);
    sigaddset(&thread.sigs, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &thread.sigs, NULL);

    signal(SIGPIPE, SIG_IGN);
}

void signals::start(void)
{
    thread.background();
}

void signals::stop(void)
{
    thread.cancel();
}

#else

void signals::setup(void)
{
}

void signals::start(void)
{
}

void signals::stop(void)
{
}

#endif

END_NAMESPACE

