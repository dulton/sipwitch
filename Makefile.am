# Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies dist-shar dist-zip
EXTRA_DIST = autogen.sh README *.pc.in FEATURES  TODO Doxyfile \
	SUPPORT NOTES MODULES cmodel.sh sipwitch.spec.in sipwitch.spec
#  *.pc.in *.spec.in *.spec

SUBDIRS = common server utils inc test
DIST_SUBDIRS = common server utils inc test swig

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsipwitch.pc

swig-python:
	(cd swig ; make python-swig)

swig-php5:
	(cd swig ; make php5-swig)


