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
RELEASE = -version-info $(LT_VERSION)
AM_CXXFLAGS = -I$(top_srcdir)/inc @SIPWITCH_FLAGS@

lib_LTLIBRARIES = libsipwitch.la 

libsipwitch_la_LDFLAGS = @LDFLAGS@ $(RELEASE) @SIPWITCH_EXOSIP2@ @USECURE_LINK@
libsipwitch_la_SOURCES = service.cpp control.cpp cache.cpp \
	events.cpp uri.cpp stats.cpp modules.cpp cdr.cpp voip.cpp


