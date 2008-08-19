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

#ifdef	_MSWINDOWS_
#include <signal.h>

#define	SERVICE_CONTROL_RELOAD	128

NAMESPACE_SIPWITCH
using namespace UCOMMON_NAMESPACE;

static SERVICE_STATUS_HANDLE hStatus;
static SERVICE_STATUS status;
static const char *user = "telephony";
static const char *cfgfile = "C:\\WINDOWS\\SIPWITCH.INI";
static unsigned verbose = 0;

static void dispatch()
{
	char buf[256];
	size_t len;	

	process::setVerbose((errlevel_t)(verbose));

	if(!process::attach(user)) {
		fprintf(stderr, "*** sipw: no control file; exiting\n");
		exit(-1);
	}

	if(!cfgfile || !*cfgfile) 
		SetEnvironmentVariable("CFG", "");
	else if(*cfgfile == '/')
		SetEnvironmentVariable("CFG", cfgfile);
	else {			
		fsys::getPrefix(buf, sizeof(buf));
		String::add(buf, sizeof(buf), "/");
		String::add(buf, sizeof(buf), cfgfile);
		SetEnvironmentVariable("CFG", buf);
	}

	GetEnvironmentVariable("APPDATA", buf, 192);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\sipwitch"); 
	fsys::createDir(buf, 0770);
	fsys::changeDir(buf);
	SetEnvironmentVariable("PWD", buf);
	SetEnvironmentVariable("IDENT", "sipwitch");

	GetEnvironmentVariable("USERPROFILE", buf, 192);
	len = strlen(buf);
	snprintf(buf + len, sizeof(buf) - len, "\\gnutelephony");
	fsys::createDir(buf, 0770);
	SetEnvironmentVariable("HOME", buf);
	GetEnvironmentVariable("ComSpec", buf, sizeof(buf));
	SetEnvironmentVariable("SHELL", buf);

	server::reload(user);
	server::startup();

	server::run(user);
	service::shutdown();
	process::release();
	exit(0);
}

static void WINAPI control(DWORD control)
{
	switch(control)
	{
	case SERVICE_CONTROL_RELOAD:
		process::control(user, "reload");
		return;
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		status.dwCurrentState = SERVICE_STOP_PENDING;
		status.dwWin32ExitCode = 0;
		status.dwCheckPoint = 0;
		status.dwWaitHint = 0;
		server::stop();
		break;
	default:
		break;
	}
	::SetServiceStatus(hStatus, &status);
}

static void WINAPI start(DWORD argc, LPSTR *argv)
{
	memset(&status, 0, sizeof(SERVICE_STATUS));
	status.dwServiceType = SERVICE_WIN32;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;

	hStatus = ::RegisterServiceCtrlHandler("sipwitch", &control);
	::SetServiceStatus(hStatus, &status);

	// ?? parse argments....

	status.dwCurrentState = SERVICE_RUNNING;
	::SetServiceStatus(hStatus, &status);
	dispatch();
}

extern "C" int main(int argc, char **argv)
{
	static bool dumping = false;
	static bool daemon = false;
	static bool warned = false;
	static unsigned priority = 0;
	static int exit_code = 0;

	static SERVICE_TABLE_ENTRY serviceTable[] = {
		{"sipwitch", (LPSERVICE_MAIN_FUNCTION)start},
		{NULL, NULL}};		

	SC_HANDLE service, scm;
	BOOL success;
	char *cp, *tokens;
	char *args[65];

	// for deaemon env usually loaded from /etc/defaults or /etc/sysconfig

	cp = getenv("PRIORITY");
	if(cp)
		priority = atoi(cp);

	cp = getenv("VERBOSE");
	if(cp) {
		warned = true;
		verbose = atoi(cp);
	}

	cp = getenv("CFGFILE");
	if(cp)
		cfgfile = strdup(cp);

	while(NULL != *(++argv)) {
		if(!strncmp(*argv, "--", 2))
			++*argv;

		if(!strcmp(*argv, "-f") || !stricmp(*argv, "-foreground")) {
			daemon = false;
			continue;
		}

		if(!strcmp(*argv, "-d") || !stricmp(*argv, "-background")) {
			daemon = true;
			continue;
		}

		if(!strcmp(*argv, "-t") || !stricmp(*argv, "-trace")) {
			dumping = true;
			continue;
		}

		if(!strcmp(*argv, "-p")) {
			priority = 1;
			continue;
		}

		if(!strnicmp(*argv, "-priority=", 10)) {
			priority = atoi(*argv + 10);
			continue;
		} 

		if(!stricmp(*argv, "-c") || !stricmp(*argv, "-config")) {
			cfgfile = *(++argv);
			if(!cfgfile) {
				fprintf(stderr, "*** sipw: cfgfile option missing\n");
				exit(-1);
			}
			continue;
		}

		if(!strnicmp(*argv, "-config=", 8)) {
			cfgfile = *argv + 8;
			continue;
		} 

		if(!stricmp(*argv, "-version"))
			server::version();

		if(!strcmp(*argv, "-u") || !stricmp(*argv, "-user")) {
			user = *(++argv);
			if(!user) {
				fprintf(stderr, "*** sipw: user option missing\n");
				exit(-1);
			}
			continue;
		}

		if(!strnicmp(*argv, "-user=", 6)) {
			user = *argv + 6;
			continue;
		} 

		if(!stricmp(*argv, "-help") || !stricmp(*argv, "-?")) 
			server::usage();

		if(!strnicmp(*argv, "-x", 2)) {
			if(*argv + 2)
				cp = *argv + 2;
			else
				cp = *(++argv);
			if(!cp) {
				fprintf(stderr, "*** sipw: debug level missing\n");
				exit(-1);
			}
			verbose = atoi(cp) + INFO;
			continue;
		}

		cp = *argv;
		while(**argv == '-' && *(++cp)) {
			switch(*cp) {
			case 'v':
				warned = true;
				if(!verbose)
					verbose = INFO;
				else
					++verbose;
				break;
			case 'f':
				daemon = false;
				break;
			case 'd':
				daemon = true;
				break;
			case 'p':
				priority = 1;
				break;
			default:
				fprintf(stderr, "*** sipw: -%c: unknown option\n", *cp);
				exit(-1);
			}	
		}
		if(!*cp)
			continue;

		if(*argv && !argv[1]) {
			scm = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
			if(!scm) {
				fprintf(stderr, "*** sipw: cannot access service control\n");
				exit(-1);
			}
			if(!stricmp(*argv, "stop")) {
				service = OpenService(scm, "sipwitch", SERVICE_ALL_ACCESS);
				if(!service) {
					fprintf(stderr, "*** sipw: cannot access service for stop\n");
					exit(-1);
				}
				ControlService(service, SERVICE_CONTROL_STOP, &status);
				goto exitcontrol;
			}

			if(!stricmp(*argv, "reload")) {
				service = OpenService(scm, "sipwitch", SERVICE_ALL_ACCESS);
				if(!service) {
					fprintf(stderr, "*** sipw: cannot access service for stop\n");
					exit(-1);
				}
				ControlService(service, SERVICE_CONTROL_RELOAD, &status);
				goto exitcontrol;
			}

			if(!stricmp(*argv, "register")) {
				service = CreateService(scm,
					"sipwitch", "sipwitch",
					GENERIC_READ | GENERIC_EXECUTE,
					SERVICE_WIN32_OWN_PROCESS,
					SERVICE_AUTO_START,
					SERVICE_ERROR_IGNORE,
					argv[0],
					NULL, NULL, NULL, NULL, NULL);
				if(service)
					printf("service removed\n");
				else
					fprintf(stderr, "*** sipw: cannot remove service\n");
				goto exitcontrol;
			}

			if(!stricmp(*argv, "release")) {
				service = OpenService(scm, "sipwitch", SERVICE_ALL_ACCESS | DELETE);
				if(!service) {
					fprintf(stderr, "*** sipw: cannot access service for delete\n");
					exit(-1);
				}
				success = QueryServiceStatus(service, &status);
				if(!success) {
					fprintf(stderr, "*** sipw: cannot access service\n");
					exit(-1);
				}
				if(status.dwCurrentState != SERVICE_STOPPED) {
					success = ControlService(service, SERVICE_CONTROL_STOP, &status);
					Sleep(1000);
				}
				success = DeleteService(service);
				if(success)
					printf("service removed\n");
				else
					fprintf(stderr, "*** sipw: cannot remove service\n");
exitcontrol:
				CloseServiceHandle(service);
				CloseServiceHandle(scm);
				exit(0);
			}
		}
		fprintf(stderr, "*** sipw: %s: unknown option\n", *argv);
		exit(-1);
	}

	if(!warned && !verbose)
		verbose = 2;

	if(daemon || argc < 2) {
		success = ::StartServiceCtrlDispatcher(serviceTable);
		if(!success) {
			if(argc < 2)
				fprintf(stderr, "*** sipw: options required for non-service startup\n"); 
			exit(-1);
		}
		return 0;
	}

	if(dumping)
		stack::enableDumping();

	dispatch();
	exit(exit_code);
}
	
END_NAMESPACE

#endif
