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
LDADD = ../common/libgnusipwitch.la @SIPWITCH_EXOSIP2@ @SIPWITCH_LIBS@ @DAEMON_LIBS@
EXTRA_DIST = *.xml *.conf

sbin_PROGRAMS = sipw
pkglibdir=$(libdir)/sipwitch
noinst_HEADERS = server.h
pkglib_LTLIBRARIES = scripting.la zeroconf.la

sipw_SOURCES = server.cpp config.cpp registry.cpp stack.cpp thread.cpp \
	call.cpp messages.cpp posix.cpp mswindows.cpp

sysconf_DATA = sipwitch.conf

localstate_DATA = *.xml 

scripting_la_SOURCES = scripting.cpp 
scripting_la_LDFLAGS = -module -avoid-version

zeroconf_la_SOURCES = zeroconf.cpp 
zeroconf_la_LDFLAGS = -module -avoid-version @ZEROCONF_LIBS@
