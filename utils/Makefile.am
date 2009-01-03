# Copyright (C) 2008 David Sugar, Tycho Softworks.
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
EXTRA_DIST = sipwitch.8

man8_MANS = sipwitch.8
man_MANS = sipwitch.8

bin_PROGRAMS = sipquery sipwitch
sbin_PROGRAMS = sipwitch.cgi

sipwitch_SOURCES = sipwitch.cpp
sipwitch_LDADD = @SIPWITCH_LIBS@

sipquery_SOURCES = sipquery.cpp
sipquery_LDADD = @SIPWITCH_EXOSIP2@ @SIPWITCH_LIBS@

sipwitch_cgi_SOURCES = cgiserver.cpp
sipwitch_cgi_LDADD = @SIPWITCH_LIBS@


