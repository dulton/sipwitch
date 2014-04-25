/* Copyright (C) 2011 David Sugar, Tycho Softworks

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
   implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#define PACKAGE "${PROJECT_NAME}"
#define STDC_HEADERS 1
#define VERSION "${VERSION}"

#define DEFAULT_LIBPATH "${DEFAULT_LIBPATH}"
#define DEFAULT_LIBEXEC "${DEFAULT_LIBEXEC}"
#define DEFAULT_VARPATH "${DEFAULT_VARPATH}"
#define DEFAULT_CFGPATH "${DEFAULT_CFGPATH}"
#define MODULE_EXT  "${MODULE_EXT}"
#define TRANSLATIONS "${DEFAULT_TRANSLATIONS}"

#cmakedefine HAVE_GETHOSTNAME 1
#cmakedefine HAVE_ATEXIT 1
#cmakedefine HAVE_GETUID 1
#cmakedefine HAVE_IOCTL_H 1
#cmakedefine HAVE_MKFIFO 1
#cmakedefine HAVE_NET_IF_H 1
#cmakedefine HAVE_PWD_H 1
#cmakedefine HAVE_SETPGRP 1
#cmakedefine HAVE_SETGROUPS 1
#cmakedefine HAVE_SETRLIMIT 1
#cmakedefine HAVE_SIGWAIT 1
#cmakedefine HAVE_SIGWAIT2 1
#cmakedefine HAVE_SYMLINK 1
#cmakedefine HAVE_SYSLOG_H 1
#cmakedefine HAVE_SYS_RESOURCE_H 1
#cmakedefine HAVE_SYS_INOTIFY_H 1
#cmakedefine HAVE_SYS_SOCKIO_H 1
#cmakedefine HAVE_SYS_STAT_H 1
#cmakedefine HAVE_RESOLV_H 1
#cmakedefine HAVE_SYSTEMD 1
#cmakedefine HAVE_OPENSSL 1

#cmakedefine ZEROCONF_AVAHI 1

#define OSIP2_LIST_PTR  &
