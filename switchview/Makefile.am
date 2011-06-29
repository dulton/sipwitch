# Copyright (C) 2008-2010 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

MAINTAINERCLEANFILES = Makefile.in Makefile
AM_CXXFLAGS = -I$(top_srcdir)/inc @SIPWITCH_FLAGS@ @QT_CFLAGS@
LDADD = @SIPWITCH_LIBS@ @QT_LIBS@
BUILT_SOURCES = ui_options.h ui_mapped.h
EXTRA_DIST = CMakeLists.txt switchview.png switchview.desktop switchview-autostart.desktop

noinst_HEADERS = switchview.h options.ui mapped.ui switchview.qrc \
	error.png info.png switchview_down.png switchview_live.png warning.png

bin_PROGRAMS = switchview

autostartdir = ${sysconfdir}/xdg/autostart
applicationsdir = ${datadir}/applications
pixmapsdir = ${datadir}/pixmaps

pixmaps_DATA = switchview.png
autostart_DATA = switchview-autostart.desktop
applications_DATA = switchview.desktop

nodist_switchview_SOURCES = moc_switchview.cpp qrc_switchview.cpp
switchview_SOURCES = switchview.cpp events.cpp mapped.cpp options.cpp \
	startup.cpp
#moc_xxx.cpp qrc_xxx.cpp
#nodist_app_HEADERS = ui_xxx.h

ui_options.h:	options.ui
	@UIC@ -o $@ $<

ui_mapped.h:	mapped.ui
	@UIC@ -o $@ $<

moc_switchview.cpp:	switchview.h
	@MOC@ -o $@ $<

qrc_switchview.cpp:	switchview.qrc
	@RCC@ -o $@ $<

