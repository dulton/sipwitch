MAINTAINERCLEANFILES = Makefile.in Makefile
AM_CXXFLAGS = -I$(top_srcdir)/inc @TRESTLE_FLAGS@
MODEL=@UCOMMON_MODEL@
CXXLINK = $(LIBTOOL) --tag=$(MODEL) --mode=link $(CXX) $(AM_CXXFLAGS) $(CFLAGS) \
    $(AM_LDFLAGS) $(LDFLAGS) -o $@
LDADD = ../lib/libtrestle.la -leXosip2 @TRESTLE_LIBS@

sbin_PROGRAMS = sipw
pkglibdir=$(libdir)/sipw
noinst_HEADERS = server.h

sipw_SOURCES = server.cpp config.cpp registry.cpp stack.cpp thread.cpp

