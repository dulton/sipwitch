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
EXTRA_DIST = README swig.i swig.h swig.cpp setup.py

# official swig builds, note: does not strip...

python-swig: swig-clean
	swig -c++ -python @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i	
	LDFLAGS="@LDFLAGS@ @UCOMMON_CLINK@" CFLAGS="@SIPWITCH_FLAGS@ -I$(abs_top_srcdir)/inc -I$(abs_top_srcdir)" python setup.py build_ext --inplace --swig-opts=-c++ -lucommon
	$(mkinstalldirs) $(DESTDIR)$(shell  python -c 'import sys; path = sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages" ; print path')
	$(STRIP) _sipwitch.so
	$(INSTALL) sipwitch.py _sipwitch.so $(DESTDIR)$(shell  python -c 'import sys; path = sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages" ; print path')

# my internal use testing targets...

python-test: swig-clean
	swig -c++ -python @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	LDFLAGS="@LDFLAGS@ @UCOMMON_CLINK@" CFLAGS="@SIPWITCH_FLAGS@ -I$(abs_top_srcdir)/inc -I$(abs_top_srcdir)" python setup.py build_ext --inplace --swig-opts=-c++ -L../../ucommon/src/.libs -lucommon

path-test:
	echo $(DESTDIR)/$(shell  python -c 'import sys; path = sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages" ; print path')


# general cleanup

swig-clean:
	-rm -rf *.so *.o *.lo wrapper.cpp sipwitch.py	build

