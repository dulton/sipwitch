# Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
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
EXTRA_DIST = *.xml *.conf *.log *.defaults *.init *.cron GNUTelephony-MIB.txt
EXTRA_LTLIBRARIES =

sbin_PROGRAMS = sipw
pkgxmldir=$(sysconfdir)/sipwitch.d
pkglibdir=$(libdir)/sipwitch
logrotatedir=$(sysconfdir)/logrotate.d
noinst_HEADERS = server.h
pkglib_LTLIBRARIES = forward.la scripting.la subscriber.la

if ZEROCONF
pkglib_LTLIBRARIES += zeroconf.la
else
EXTRA_LTLIBRARIES += zeroconf.la
endif

sipw_SOURCES = server.cpp registry.cpp stack.cpp thread.cpp \
	call.cpp messages.cpp posix.cpp mswindows.cpp 
sipw_LDADD = $(LDADD) $(DLOPEN)

sysconf_DATA = sipwitch.conf

pkgxml_DATA = lab.xml tests.xml 

forward_la_SOURCES = forward.cpp 
forward_la_LDFLAGS = -module $(MODFLAGS) $(LDADD)

scripting_la_SOURCES = scripting.cpp 
scripting_la_LDFLAGS = -module $(MODFLAGS) $(LDADD)

subscriber_la_SOURCES = subscriber.cpp 
subscriber_la_LDFLAGS = -module $(MODFLAGS) $(LDADD)

zeroconf_la_SOURCES = zeroconf.cpp 
zeroconf_la_LDFLAGS = -module $(MODFLAGS) @ZEROCONF_LIBS@ $(LDADD)

mibsdatadir = $(datadir)/snmp/mibs

mibsdata_DATA = GNUTelephony-MIB.txt

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)/$(logrotatedir)
	$(INSTALL_DATA) sipwitch.log $(DESTDIR)/$(logrotatedir)/sipwitch
	if test -d /etc/sysconfig ; then \
		$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/sysconfig ; \
		$(INSTALL_DATA) sipwitch.defaults $(DESTDIR)/$(sysconfdir)/sysconfig/sipwitch ; \
	else \
		$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/default ; \
		$(INSTALL_DATA) sipwitch.defaults $(DESTDIR)/$(sysconfdir)/default/sipwitch ; \
	fi
	if test "@INITRDDIR@" != "none" ; then $(mkinstalldirs) $(DESTDIR)/@INITRDDIR@ ; fi
	if test "@INITRDDIR@" != "none" ; then $(INSTALL) -m 0755 sipwitch.init $(DESTDIR)/@INITRDDIR@/sipwitch ; fi
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/cron.hourly 
	$(INSTALL) -m 0755 sipwitch.cron $(DESTDIR)/$(sysconfdir)/cron.hourly/sipwitch 


