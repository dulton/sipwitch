# Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies dist-zip
EXTRA_DIST = autogen.sh README *.pc.in FEATURES  TODO Doxyfile BUILDS \
	SUPPORT NOTES MODULES cmodel.sh sipwitch.spec.in sipwitch.spec \
	sipwitch-config.in sipwitch-config.1 sipwitch-config.h.cmake \
	CMakeLists.txt
#  *.pc.in *.spec.in *.spec

SUBDIRS = common server @QTAPPS@ utils inc test
DIST_SUBDIRS = common server switchview utils inc test 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsipwitch.pc

scriptdir = $(bindir)
script_SCRIPTS = sipwitch-config

man_MANS = sipwitch-config.1

dist-hook:  cleandist

cleandist:
	@rm -f ${PACKAGE}-[0-9]*.tar.gz
	@rm -f ${PACKAGE}-[0-9]*.tar.bz2
	@rm -f ${PACKAGE}-[0-9]*.shar.gz
	@rm -f ${PACKAGE}-[0-9]*.zip
	@rm -f ${PACKAGE}-*.rpm
	@rm -f lib${PACKAGE}*[-_]*.deb
	@rm -f ${PACKAGE}[-_]*.deb
	@rm -f ${PACKAGE}_*.gz
	@rm -f ${PACKAGE}_*.dsc
	@rm -f *.changes


