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
EXTRA_DIST = README swig.i swig.h swig.cpp setup.py setup.pl
PKGNAME = "org.gnutelephony.sipwitch"
PKGPATH = "org/gnutelephony/sipwitch"

# official swig builds

csharp-swig: swig-clean
	mkdir build
	swig -c++ -csharp -dllimport csharp-sipwitch -outdir build -module Server -namespace $(PKGNAME) @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	mcs -out:sipwitch.dll -t:library build/*.cs
	$(CXX) -shared @SIPWITCH_FLAGS@ -fPIC -fpic -I$(top_srcdir)/inc -I$(top_srcdir) -I$(prefix)/include/mono -o wrapper.o -c wrapper.cpp  
	$(CXX) -shared -o libcsharp-sipwitch.so wrapper.o -lucommon @UCOMMON_CLINK@
	$(mkinstalldirs) $(DESTDIR)$(libdir)/mono/gnutelephony
	$(INSTALL) sipwitch.dll $(DESTDIR)$(libdir)/mono/gnutelephony
	$(INSTALL) libcsharp-sipwitch.so $(DESTDIR)$(libdir)

java-swig: swig-clean
	rm -rf org/gnutelephony/sipwitch
	rm -rf *.jar
	mkdir -p $(PKGPATH)
	swig -c++ -java -module Server -package $(PKGNAME) @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -outdir $(PKGPATH) -o wrapper.cpp swig.i 
	$(CXX) -shared @SIPWITCH_FLAGS@ -fPIC -fpic -I$(top_srcdir)/inc -I$(top_srcdir) -I$(libdir)/jvm/default-java/include -o wrapper.o -c wrapper.cpp  
	$(CXX) -shared -o libjava-sipwitch.so wrapper.o -lucommon @UCOMMON_CLINK@
	(cd $(PKGPATH) ; javac *.java)
	jar cf sipwitch.jar $(PKGPATH)/*.class
	$(mkinstalldirs) $(DESTDIR)$(libdir)/java
	$(INSTALL) sipwitch.jar $(DESTDIR)$(libdir)/java
	$(INSTALL) libjava-sipwitch.so $(DESTDIR)$(libdir)

perl5-swig: swig-clean
	swig -c++ -perl5 @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	$(CXX) -shared -fpic @SIPWITCH_FLAGS@  -o wrapper.o -c wrapper.cpp -I$(top_srcdir)/inc -I$(top_srcdir) `perl setup.pl --flags`
	$(CXX) -shared -module $(MODFLAGS) -o sipwitch.so wrapper.o -lucommon @UCOMMON_CLINK@
	$(mkinstalldirs) $(DESTDIR)$(libdir)/perl5/auto/sipwitch
	touch $(DESTDIR)$(libdir)/perl5/auto/sipwitch/sipwitch.bs
	$(INSTALL) sipwitch.so $(DESTDIR)$(libdir)/perl5/auto/sipwitch
	$(INSTALL) sipwitch.pm $(DESTDIR)$(libdir)/perl5

python-swig: swig-clean
	swig -c++ -python @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i	
	LDFLAGS="@LDFLAGS@ @UCOMMON_CLINK@" CFLAGS="@SIPWITCH_FLAGS@ -I$(abs_top_srcdir)/inc -I$(abs_top_srcdir)" python setup.py build_ext --inplace --swig-opts=-c++ -lucommon
	$(mkinstalldirs) $(DESTDIR)/$(PYTHON_SITELIB)
	$(mkinstalldirs) $(DESTDIR)/$(PYTHON_SITEARCH)
	$(INSTALL_DATA) sipwitch.py $(DESTDIR)/$(PYTHON_SITELIB)
	$(INSTALL) _sipwitch.so $(DESTDIR)/$(PYTHON_SITEARCH)

php5-swig: swig-clean
	swig -c++ -php5 @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	$(CXX) -shared `$(PHP_CONFIG) --includes` -Wno-format -fpic @SIPWITCH_FLAGS@ -o wrapper.o -c wrapper.cpp -I$(top_srcdir)/inc -I$(top_srcdir) 
	$(CXX) -shared -module $(MODFLAGS) -o sipwitch.so wrapper.o -lucommon @UCOMMON_CLINK@
	$(mkinstalldirs) $(DESTDIR)/$(PHP_EXTDIR)
	$(INSTALL) sipwitch.so $(DESTDIR)/$(PHP_EXTDIR)

# my internal use testing targets...

php5-test: swig-clean
	swig -c++ -php5 @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	$(CXX) `$(PHP_CONFIG) --includes` -Wno-format -fpic @SIPWITCH_FLAGS@ -o wrapper.o -c wrapper.cpp -I$(top_srcdir)/inc -I$(top_srcdir) 
	$(CXX) -shared -module $(MODFLAGS) -o sipwitch.so wrapper.o -L../../ucommon/src/.libs -lucommon @UCOMMON_CLINK@

python-test: swig-clean
	swig -c++ -python @INCLUDE_FLAGS@ -I$(top_srcdir)/inc -o wrapper.cpp swig.i
	LDFLAGS="@LDFLAGS@ @UCOMMON_CLINK@" CFLAGS="@SIPWITCH_FLAGS@ -I$(abs_top_srcdir)/inc -I$(abs_top_srcdir)" python setup.py build_ext --inplace --swig-opts=-c++ -L../../ucommon/src/.libs -lucommon

# general cleanup

swig-clean:
	-rm -rf *.so *.o *.lo wrapper.cpp sipwitch.py sipwitch.php build

