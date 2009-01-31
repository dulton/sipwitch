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
PKGNAME = "org.gnutelephony.sipwitch"
PKGPATH = "org/gnutelephony/sipwitch"

# official swig builds

java-swig: swig-clean
	rm -rf org/gnutelephony/sipwitch
	rm -rf *.jar
	mkdir -p $(PKGPATH)
	swig -c++ -java -module Server -package $(PKGNAME) @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -outdir $(PKGPATH) -o wrapper.cpp swig.i 
	$(CXX) -shared @SIPWITCH_FLAGS@ -fPIC -fpic -I$(top_srcdir)/inc -I$(top_srcdir) -I$(libdir)/jvm/default-java/include -o wrapper.o -c wrapper.cpp  
	$(CXX) -shared -o libsipwitch.so wrapper.o -lucommon @UCOMMON_CLINK@
	(cd org/gnutelephony/sipwitch ; javac *.java)
	jar cf sipwitch.jar $(PKGPATH)/*.class
	$(STRIP) libsipwitch.so
	$(INSTALL) sipwitch.jar $(DESTDIR)$(libdir)/java
	$(INSTALL) libsipwitch.so $(DESTDIR)$(libdir)/jni

python-swig: swig-clean
	swig -c++ -python @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i	
	LDFLAGS="@LDFLAGS@ @UCOMMON_CLINK@" CFLAGS="@SIPWITCH_FLAGS@ -I$(abs_top_srcdir)/inc -I$(abs_top_srcdir)" python setup.py build_ext --inplace --swig-opts=-c++ -lucommon
	$(mkinstalldirs) $(DESTDIR)`python -c 'import sys; path = sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages" ; print path'`
	$(STRIP) _sipwitch.so
	$(INSTALL) sipwitch.py _sipwitch.so $(DESTDIR)`python -c 'import sys; path = sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages" ; print path'`

php5-swig: swig-clean
	swig -c++ -php5 @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	$(CXX) -shared `php-config --includes` -Wno-format -fpic @SIPWITCH_FLAGS@ -o wrapper.o -c wrapper.cpp -I$(top_srcdir)/inc -I$(top_srcdir) 
	$(CXX) -shared -module $(MODFLAGS) -o sipwitch.so wrapper.o -lucommon @UCOMMON_CLINK@
	$(mkinstalldirs) $(DESTDIR)`php-config --extension-dir`
	$(STRIP) sipwitch.so
	$(INSTALL) sipwitch.so $(DESTDIR)`php-config --extension-dir`

# my internal use testing targets...

php5-test: swig-clean
	swig -c++ -php5 @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	$(CXX) `php-config --includes` -Wno-format -fpic @SIPWITCH_FLAGS@ -o wrapper.o -c wrapper.cpp -I$(top_srcdir)/inc -I$(top_srcdir) 
	$(CXX) -shared -module $(MODFLAGS) -o sipwitch.so wrapper.o -L../../ucommon/src/.libs -lucommon @UCOMMON_CLINK@

python-test: swig-clean
	swig -c++ -python @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	LDFLAGS="@LDFLAGS@ @UCOMMON_CLINK@" CFLAGS="@SIPWITCH_FLAGS@ -I$(abs_top_srcdir)/inc -I$(abs_top_srcdir)" python setup.py build_ext --inplace --swig-opts=-c++ -L../../ucommon/src/.libs -lucommon

# general cleanup

swig-clean:
	-rm -rf *.so *.o *.lo wrapper.cpp sipwitch.py build

