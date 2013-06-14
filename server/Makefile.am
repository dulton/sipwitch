# Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
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
LDADD = ../common/libsipwitch.la @SIPWITCH_LIBS@
PLUGINS_ADD = ../common/libsipwitch.la @UCOMMON_LINK@
EXTRA_DIST = *.xml *-example *.conf *.log *.defaults *.init *.cron *.8 \
	sipwitch.ifup sipwitch.ifdown sipwitch.reload CMakeLists.txt \
	sipwitch.service
EXTRA_LTLIBRARIES =

man_MANS = sipw.8
sbin_PROGRAMS = sipw
pkgxmldir=$(sysconfdir)/sipwitch.d
pkglibdir=$(libdir)/sipwitch
systemddir=$(libdir)/systemd/system
logrotatedir=$(sysconfdir)/logrotate.d
noinst_HEADERS = server.h voip.h
pkglib_LTLIBRARIES = forward.la scripting.la subscriber.la

if ZEROCONF
pkglib_LTLIBRARIES += zeroconf.la
else
EXTRA_LTLIBRARIES += zeroconf.la
endif

sipw_SOURCES = server.cpp registry.cpp stack.cpp thread.cpp protocols.cpp \
	call.cpp messages.cpp media.cpp system.cpp signals.cpp history.cpp \
	voip.cpp
sipw_LDADD = $(LDADD) @SIPWITCH_EXOSIP2@ @DAEMON_LIBS@ $(DLOPEN)
sipw_LDFLAGS = @LDFLAGS@

sysconf_DATA = sipwitch.conf

pkgxml_DATA = lab.xml-example tests.xml 

forward_la_SOURCES = forward.cpp 
forward_la_LDFLAGS = -module $(MODFLAGS) $(PLUGINS_ADD)

scripting_la_SOURCES = scripting.cpp 
scripting_la_LDFLAGS = -module $(MODFLAGS) $(PLUGINS_ADD)

subscriber_la_SOURCES = subscriber.cpp 
subscriber_la_LDFLAGS = -module $(MODFLAGS) $(PLUGINS_ADD)

zeroconf_la_SOURCES = zeroconf.cpp 
zeroconf_la_LDFLAGS = -module $(MODFLAGS) @ZEROCONF_LIBS@ $(PLUGINS_ADD)

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
	if test "@NETWORK_UP@" != "none" ; then $(mkinstalldirs) $(DESTDIR)/@NETWORK_UP@ ; fi
	if test "@NETWORK_UP@" != "none" ; then $(INSTALL) -m 0755 sipwitch.ifup $(DESTDIR)/@NETWORK_UP@/sipwitch ; fi
	if test "@NETWORK_DOWN@" != "none" ; then $(mkinstalldirs) $(DESTDIR)/@NETWORK_DOWN@ ; fi
	if test "@NETWORK_DOWN@" != "none" ; then $(INSTALL) -m 0755 sipwitch.ifdown $(DESTDIR)/@NETWORK_DOWN@/sipwitch ; fi
	if test "@NETWORK_RELOAD@" != "none" ; then $(mkinstalldirs) $(DESTDIR)/@NETWORK_RELOAD@ ; fi
	if test "@NETWORK_RELOAD@" != "none" ; then $(INSTALL) -m 0755 sipwitch.reload $(DESTDIR)/@NETWORK_RELOAD@/90sipwitch ; fi
	if test "@INITRDDIR@" != "none" ; then $(mkinstalldirs) $(DESTDIR)/@INITRDDIR@ ; fi
	if test "@INITRDDIR@" != "none" ; then $(INSTALL) -m 0755 sipwitch.init $(DESTDIR)/@INITRDDIR@/sipwitch ; fi
	if test "@INITRDDIR@" = "none" ; then $(mkinstalldirs) $(DESTDIR)/$(systemddir) ; fi
	if test "@INITRDDIR@" = "none" ; then $(INSTALL) -m 0644 sipwitch.service $(DESTDIR)/$(systemddir)/sipwitch.service ; fi
	$(mkinstalldirs) $(DESTDIR)/$(sysconfdir)/cron.hourly 
	$(INSTALL) -m 0755 sipwitch.cron $(DESTDIR)/$(sysconfdir)/cron.hourly/sipwitch 


