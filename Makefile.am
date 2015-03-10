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
	SUPPORT NOTES MODULES sipwitch.spec.in sipwitch.spec PKGBUILD.in \
	sipwitch-config.h.cmake CMakeLists.txt directive.in cmake-abi.sh \
	sipwitch-rpmlintrc

#  *.pc.in *.spec.in *.spec

SUBDIRS = common server utils inc test
DIST_SUBDIRS = common server utils inc test 

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsipwitch.pc

srpm:	dist
	rm -f *.rpm
	rpmbuild  -bs --nodeps --define "_sourcedir ." --define "_srcrpmdir ." --sign sipwitch.spec

deb:	dist
	rm -f *.deb *.debian.tar.gz *.dsc *.changes
	cape-source --sign sipwitch-${VERSION}.tar.gz .

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


