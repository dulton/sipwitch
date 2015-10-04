# Copyright (C) 2011-2014 David Sugar, Tycho Softworks.
# Copyright (C) 2015 Cherokees of Idaho.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
#

cmake_minimum_required(VERSION 2.6)
PROJECT(sipwitch)
set (VERSION 1.9.10)
set (USES_UCOMMON_REQUIRED 6.6.1)

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(FindPkgConfig)
INCLUDE(GNUInstallDirs)

set(MODULE_EXT "${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(INSTALL_PLUGINS "${CMAKE_INSTALL_FULL_LIBDIR}/sipwitch")
if(NOT CMAKE_INSTALL_CGIBINDIR)
    set(CMAKE_INSTALL_CGIBINDIR "/srv/www/cgi-bin")
endif()

if(WIN32)
    set(MODULE_EXT ".dll")
else()
    set(MODULE_EXT ".so")
endif()

if (WIN32)
    # too broken to build dll's with const static members...
    option(BUILD_STATIC "Set to OFF to build shared libraries" ON)
    set(HAVE_SIGWAIT false)
    set(HAVE_SIGWAIT2 off CACHE BOOL "disable sigwait on windows" FORCE)
    MARK_AS_ADVANCED(FORCE HAVE_SIGWAIT2)
else()
    option(BUILD_STATIC "Set to ON to build static libraries" OFF)
    option(HAVE_SIGWAIT2 "Set to OFF to build with single argument" ON)
    MARK_AS_ADVANCED(HAVE_SIGWAIT2)

    set(HAVE_SIGWAIT true)
endif()

MESSAGE( STATUS "Configuring GNU sipwitch ${VERSION}...")

find_package(PkgConfig)
if (USES_UCOMMON_INCLUDE_DIRS)
    message(STATUS "  Using local ucommon dependency")
else()
    pkg_check_modules(USES_UCOMMON REQUIRED ucommon>=@USES_UCOMMON_REQUIRED@)
endif()

pkg_check_modules(USES_ZEROCONF avahi-client>=0.3.0)

if(USES_ZEROCONF_FOUND)
    set(ZEROCONF_AVAHI true)
endif()

pkg_check_modules(USES_SYSTEMD libsystemd-daemon>=44)
if(USES_SYSTEMD_FOUND)
    set(HAVE_SYSTEMD true)
endif()

include_directories(${USES_UCOMMON_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/inc ${WITH_INCLUDES})
link_directories(${USES_UCOMMON_LIBRARY_DIRS} ${WITH_LIBS})
add_definitions(${USES_UCOMMON_CFLAGS} ${WITH_CFLAGS})

if(USES_UCOMMON_CMAKE_MACROS)
	set(CMAKE_MODULE_PATH "${USES_UCOMMON_CMAKE_MACROS}")
elseif(EXISTS "${USES_UCOMMON_PREFIX}/share/ucommon/cmake")
	set(CMAKE_MODULE_PATH "${USES_UCOMMON_PREFIX}/share/ucommon/cmake")
else()
	set(CMAKE_MODULE_PATH "${CMAKE_INSTALL_FULL_DATADIR}/ucommon/cmake")
endif()

include(CapeConfig)
include(CapeMakeTargets)

# by default we build static libs for windows, shared libs for unix.
# we may also set this from a top level cmake or -DWITH_XX_LIBS

if(BUILD_STATIC)
    set(BUILD_LIBRARY_TYPE STATIC)
else()
    set(BUILD_LIBRARY_TYPE SHARED)
endif()

if(NOT BUILD_RUNTIME_TYPE)
    set(BUILD_RUNTIME_TYPE ${BUILD_LIBRARY_TYPE})
endif()

check_include_files(sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_files(sys/inotify.h HAVE_SYS_INOTIFY_H)
check_include_files(syslog.h HAVE_SYSLOG_H)
check_include_files(net/if.h HAVE_NET_IF_H)
check_include_files(sys/sockio.h HAVE_SYS_SOCKIO_H)
check_include_files(ioctl.h HAVE_IOCTL_H)
check_include_files(pwd.h HAVE_PWD_H)
check_include_files(eXosip2/eXosip.h HAVE_EXOSIP2)

if(HAVE_EXOSIP2)
    check_include_files(openssl/ssl.h HAVE_OPENSSL)
else()
    message(ERROR "libeXosip2 required to build")
endif()

if(HAVE_OPENSSL)
    if(WIN32 AND NOT CYGWIN AND NOT MINGW)
        set (EXOSIP2_LIBS eXosip2 osip2 osipparser2 ssleay32 libeay32 gdi32)
    else()
        set (EXOSIP2_LIBS eXosip2 osip2 osipparser2 ssl crypto z)
    endif()
else()
    set(EXOSIP2_LIBS eXosip2 osip2 osipparser2)
endif()

check_include_files(resolv.h HAVE_RESOLV_H)
if(HAVE_RESOLV_H)
    set(EXOSIP2_LIBS ${EXOSIP2_LIBS} resolv)
endif()

if(WIN32 AND NOT CYGWIN)
    set(EXOSIP2_LIBS ${EXOSIP2_LIBS} iphlpapi dnsapi ws2_32 crypt32)
endif()

if(APPLE)
    find_library(CORE_FOUNDATION CoreFoundation)
    find_library(CORE_SERVICES CoreServices)
    find_library(APPLE_SECURITY Security)
    set(EXOSIP2_LIBS ${EXOSIP2_LIBS} ${APPLE_SECURITY} ${CORE_SERVICES} ${CORE_FOUNDATION})
endif()

check_function_exists(setrlimit HAVE_SETRLIMIT)
check_function_exists(setgroups HAVE_SETGROUPS)
check_function_exists(setpgrp HAVE_SETPGRP)
check_function_exists(getuid HAVE_GETUID)
check_function_exists(mkfifo HAVE_MKFIFO)
check_function_exists(symlink HAVE_SYMLINK)
check_function_exists(atexit HAVE_ATEXIT)

file(GLOB runtime_src common/*.cpp)
file(GLOB runtime_inc inc/sipwitch/*.h)
file(GLOB sipwitch_man1 utils/*.1)
file(GLOB sipwitch_man8 utils/*.8 server/*.8)
file(GLOB sipwitch_conf server/*.conf)
file(GLOB sipwitch_xml server/*.xml*)

STRING(COMPARE EQUAL "${BUILD_RUNTIME_TYPE}" "SHARED" HAVE_PLUGINS)

pc_flags(PKG_SIPWITCH_FLAGS ${EXOSIP2_FLAGS})
pc_libs(PKG_SIPWITCH_LIBS ${EXOSIP2_LIBS})

create_headers()
create_specfile()
create_scripts(noinst_scr PKGBUILD)
create_pcfiles(pc_files libsipwitch)

add_library(sipwitch ${BUILD_RUNTIME_TYPE} ${runtime_src} ${runtime_inc})
set_library_version(sipwitch)
set_source_dependencies(sipwitch ucommon)
target_link_libraries(sipwitch ${USES_UCOMMON_LIBRARIES} ${EXOSIP2_LIBS})
set_target_properties(sipwitch PROPERTIES OUTPUT_NAME sipwitch)

add_subdirectory(server)

add_executable(sipwitch-query utils/sipquery.cpp)
set_source_dependencies(sipwitch-query usecure ucommon eXosip2)
target_link_libraries(sipwitch-query usecure ucommon ${EXOSIP2_LIBS} ${USES_UCOMMON_LIBRARIES})
set_target_properties(sipwitch-query PROPERTIES OUTPUT_NAME sipquery)

install(TARGETS sipwitch-query DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(sipwitch-cgi utils/cgiserver.cpp)
set_source_dependencies(sipwitch-cgi ucommon)
target_link_libraries(sipwitch-cgi ucommon ${USES_UCOMMON_LIBRARIES})
if(UNIX)
    set_target_properties(sipwitch-cgi PROPERTIES OUTPUT_NAME sipwitch.cgi)
endif()

add_executable(sipwitch-passwd utils/sippasswd.cpp)
set_source_dependencies(sipwitch-passwd usecure ucommon)
target_link_libraries(sipwitch-passwd usecure ucommon ${USES_UCOMMON_LIBRARIES})
set_target_properties(sipwitch-passwd PROPERTIES OUTPUT_NAME sippasswd)
if(UNIX)
    target_setuid_properties(sipwitch-passwd)
endif()

add_executable(sipwitch-control utils/sipcontrol.cpp)
set_source_dependencies(sipwitch-control usecure ucommon)
target_link_libraries(sipwitch-control usecure ucommon ${USES_UCOMMON_LIBRARIES})
set_target_properties(sipwitch-control PROPERTIES OUTPUT_NAME sipcontrol)

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
    # in DEBIAN we would set this off, in opensuse/rpm based, on...
    option(SYSTEM_CONFIG "Set to ON to write system config" OFF)
    if(SYSTEM_CONFIG)
        if(NOT CMAKE_INSTALL_UNITDIR)
            set(CMAKE_INSTALL_UNITDIR lib/systemd/system)
        endif()
        file(GLOB sipwitch_log server/*.log)
        file(GLOB sipwitch_cron server/*.cron)
        file(GLOB sipwitch_def server/*.defaults)
        file(GLOB sipwitch_init server/*.service)
        install(FILES   ${sipwitch_log} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/logrotate.d RENAME sipwitch)
        install(FILES   ${sipwitch_cron} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/cron.hourly RENAME sipwitch)
        install(FILES   ${sipwitch_def} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/default RENAME sipwitch)
        install(FILES   ${sipwitch_init} DESTINATION ${CMAKE_INSTALL_UNITDIR})
    endif()
endif()

install(FILES ${pc_files} DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

install(FILES   ${sipwitch_conf} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
install(FILES   ${sipwitch_xml} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/sipwitch.d)
install(FILES   ${sipwitch_man1} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES   ${sipwitch_man8} DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
install(FILES   ${runtime_inc}  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sipwitch)
install(TARGETS sipwitch DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS sipwitch-control DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS sipwitch-cgi DESTINATION ${CMAKE_INSTALL_CGIBINDIR})

if(SYSTEM_SETUID)
    install(TARGETS sipwitch-passwd DESTINATION ${CMAKE_INSTALL_BINDIR} PERMISSIONS SETUID)
else()
    install(TARGETS sipwitch-passwd DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

add_make_lint_target()
add_make_uninstall_target()


