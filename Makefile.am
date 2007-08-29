# Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies dist-shar dist-zip
EXTRA_DIST = autogen.sh README *.pc.in TODO
#  *.pc.in *.spec.in *.spec

SUBDIRS = @BUILD_SUBDIRS@ inc test
DIST_SUBDIRS = lib server inc test

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgnutelephony.pc


