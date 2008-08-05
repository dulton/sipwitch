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
AM_CXXFLAGS = -I$(top_srcdir)/inc @SIPWITCH_FLAGS@
LDADD = ../common/libsipwitch.la @SIPWITCH_EXOSIP2@ @SIPWITCH_LIBS@ @DAEMON_LIBS@
EXTRA_DIST = *.xml *.conf *.log *.def *.init
EXTRA_LTLIBRARIES =

sbin_PROGRAMS = sipw
pkgstatedir=$(localstatedir)/lib/sipwitch
pkglibdir=$(libdir)/sipwitch
logrotatedir=$(sysconfdir)/logrotate.d
noinst_HEADERS = server.h
pkglib_LTLIBRARIES = scripting.la

if ZEROCONF
pkglib_LTLIBRARIES += zeroconf.la
else
EXTRA_LTLIBRARIES += zeroconf.la
endif

sipw_SOURCES = server.cpp config.cpp registry.cpp stack.cpp thread.cpp \
	call.cpp messages.cpp posix.cpp mswindows.cpp
sipw_LDADD = $(LDADD) $(DLOPEN)

sysconf_DATA = sipwitch.conf

pkgstate_DATA = *.xml 

scripting_la_SOURCES = scripting.cpp 
scripting_la_LDFLAGS = -module $(MODFLAGS) $(LDADD)

zeroconf_la_SOURCES = zeroconf.cpp 
zeroconf_la_LDFLAGS = -module $(MODFLAGS) @ZEROCONF_LIBS@ $(LDADD)

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(logrotatedir)
	$(INSTALL_DATA) sipwitch.log $(DESTDIR)/$(logrotatedir)/sipwitch
	if test -d /etc/sysconfig ; then \
		$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/sysconfig ; \
		$(INSTALL_DATA) sipwitch.def $(DESTDIR)/$(sysconfdir)/sysconfig/sipwitch ; \
	else \
		$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/default ; \
		$(INSTALL_DATA) sipwitch.def $(DESTDIR)/$(sysconfdir)/default/sipwitch ; \
	fi
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/init.d
	$(INSTALL) -m 0755 sipwitch.init $(DESTDIR)/$(sysconfdir)/init.d/sipwitch

