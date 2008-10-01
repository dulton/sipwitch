# Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

MAINTAINERCLEANFILES = Makefile.in Makefile
AM_CXXFLAGS = -I$(top_srcdir)/inc @SIPAPPS_FLAGS@
LDADD = ../common/libsipwitch.la @SIPWITCH_EXOSIP2@ @SIPAPPS_LIBS@ @DAEMON_LIBS@
EXTRA_DIST = *.xml *.conf *.log *.def *.init
EXTRA_LTLIBRARIES =

sbin_PROGRAMS = sipapps
pkgstatedir=$(localstatedir)/lib/sipapps
pkglibdir=$(libdir)/sipapps
logrotatedir=$(sysconfdir)/logrotate.d
noinst_HEADERS = server.h

sipapps_SOURCES = posix.cpp mswindows.cpp server.cpp
sipapps_LDADD = $(LDADD)

sysconf_DATA = sipapps.conf

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(logrotatedir)
	$(INSTALL_DATA) sipapps.log $(DESTDIR)/$(logrotatedir)/sipapps
	if test -d /etc/sysconfig ; then \
		$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/sysconfig ; \
		$(INSTALL_DATA) sipapps.def $(DESTDIR)/$(sysconfdir)/sysconfig/sipapps ; \
	else \
		$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/default ; \
		$(INSTALL_DATA) sipapps.def $(DESTDIR)/$(sysconfdir)/default/sipapps ; \
	fi
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/init.d
	$(INSTALL) -m 0755 sipapps.init $(DESTDIR)/$(sysconfdir)/init.d/sipapps

