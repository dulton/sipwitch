MAINTAINERCLEANFILES = Makefile.in Makefile
RELEASE = -version-info $(LT_VERSION) -release $(LT_RELEASE)
MODEL=@UCOMMON_MODEL@
AM_CXXFLAGS = -I$(top_srcdir)/inc @TRESTLE_FLAGS@
CXXLINK = $(LIBTOOL) --tag=$(MODEL) --mode=link $(CXX) $(AM_CFLAGS) $(CFLAGS) \
    $(AM_LDFLAGS) $(LDFLAGS) -o $@

lib_LTLIBRARIES = libtrestle.la 

libtrestle_la_LDFLAGS = @TRESTLE_LIBS@ $(RELEASE) @UCOMMON_SHARED@
libtrestle_la_SOURCES = mapped.cpp service.cpp digest.cpp


