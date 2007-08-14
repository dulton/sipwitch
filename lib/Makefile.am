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
RELEASE = -version-info $(LT_VERSION) -release $(LT_RELEASE)
MODEL=@UCOMMON_MODEL@
AM_CXXFLAGS = -I$(top_srcdir)/inc @GNUTELEPHONY_FLAGS@
CXXLINK = $(LIBTOOL) --tag=$(MODEL) --mode=link $(CXX) $(AM_CFLAGS) $(CFLAGS) \
    $(AM_LDFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES = libgnutelephony.la 

libgnutelephony_la_LDFLAGS = @GNUTELEPHONY_LIBS@ $(RELEASE) 
libgnutelephony_la_SOURCES = mapped.cpp service.cpp digest.cpp process.cpp


