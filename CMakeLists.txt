# Copyright (C) 2011 David Sugar, Tycho Softworks.
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
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckFunctionExists)
INCLUDE(FindPkgConfig)
set (VERSION 1.9.0)

set(RC_VERSION ${VERSION})
STRING(REGEX REPLACE "[.]" "," RC_VERSION ${RC_VERSION})
set(RC_VERSION "${RC_VERSION},0")

set(SOVERSION ${VERSION})
STRING(REGEX REPLACE "[.].*$" "" SOVERSION ${SOVERSION})

if(NOT INSTALL_INCLUDEDIR)
    set(INSTALL_INCLUDEDIR "include")
endif()

if(NOT INSTALL_BINDIR)
    set(INSTALL_BINDIR "bin")
endif()

if(NOT INSTALL_SBINDIR)
    set(INSTALL_SBINDIR "sbin")
endif()

if(NOT INSTALL_LIBEXEC)
    set(INSTALL_LIBEXEC "libexec")
endif()

if(WIN32)
    set(MODULE_EXT ".mll")
    set(INSTALL_MANDIR "man")
    set(INSTALL_DOCDIR doc/${PROJECT_NAME})
    set(INSTALL_LOCALE locale)
    set(INSTALL_LIBDIR bin)
    set(INSTALL_INFODIR info)
    set(INSTALL_PLUGINS bin)
    set(SYSCONFDIR "etc" CACHE PATH "config directory")
    set(STATEDIR "var" CACHE PATH "state directory")
    set(TRANSLATIONS translations)
else()
    set(MODULE_EXT .so)
    if (NOT LIB_SUFFIX)
        if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
            set(LIB_SUFFIX 64)
        endif()
    endif()
    if(NOT INSTALL_MANDIR)
        set(INSTALL_MANDIR share/man)
    endif()

    if(NOT INSTALL_LOCALE)
        set(INSTALL_LOCALE share/locale)
    endif()

    if(NOT INSTALL_DOCTDIR)
        set(INSTALL_DOCDIR share/doc/${PROJECT_NAME})
    endif()

    if(NOT INSTALL_INFODIR)
        set(INSTALL_INFODIR share/info)
    endif()

    if(NOT INSTALL_LIBDIR)
        set(INSTALL_LIBDIR lib${LIB_SUFFIX})
    endif()

    if(NOT INSTALL_PLUGINS)
        set(INSTALL_PLUGINS ${INSTALL_LIBDIR}/sipwitch)
    endif()

    if(NOT INSTALL_PIXMAPS)
        set(INSTALL_PIXMAPS share/pixmaps)
    endif()

    if(NOT INSTALL_APPLICATIONS)
        set(INSTALL_APPLICATIONS share/applications)
    endif()

    set(TRANSLATIONS share/${PROJECT_NAME}/translations)
    set(SYSCONFDIR "/etc" CACHE PATH "config directory")
    set(STATEDIR "/var" CACHE PATH "state directory")
endif()

if(WIN32)
    set(DEFAULT_CFGPATH "${CMAKE_INSTALL_PREFIX}/${SYSCONFDIR}")
    set(DEFAULT_VARPATH "${CMAKE_INSTALL_PREFIX}/${STATEDIR}")
else()
    set(DEFAULT_CFGPATH ${SYSCONFDIR})
    set(DEFAULT_VARPATH ${STATEDIR})
endif()

set(INSTALL_EXTPATH lib)
set(DEFAULT_LIBPATH ${CMAKE_INSTALL_PREFIX}/${INSTALL_EXTPATH})
set(DEFAULT_LIBEXEC ${CMAKE_INSTALL_PREFIX}/${INSTALL_LIBEXEC})
set(DEFAULT_TRANSLATIONS ${CMAKE_INSTALL_PREFIX}/${TRANSLATIONS})

if (WIN32)
    # too broken to build dll's with const static members...
    if(MSVC60)
        set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
        MARK_AS_ADVANCED(FORCE BUILD_STATIC)
    else()
        option(BUILD_STATIC "Set to OFF to build shared libraries" ON)
    endif()
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

# set to true for debug and trace during CMakeLists development
set(CMAKE_VERBOSE_MAKEFILE FALSE)

# Set defaults and pass common options.  Common build options can be passed
# to cmake using cmake -DWITH_CFLAGS="...", WITH_LIBS, and WITH_INCLUDES
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/inc ${WITH_INCLUDES})
add_definitions(${WITH_CFLAGS})
link_libraries(${WITH_LIBS})
find_package(PkgConfig)

if (USES_UCOMMON_INCLUDE_DIRS)
    message(STATUS "  Using local ucommon dependency")
else()
    pkg_check_modules(USES_UCOMMON REQUIRED ucommon>=6.0.0)
endif()

pkg_check_modules(USES_ZEROCONF avahi-client>=0.3.0)

if(USES_ZEROCONF_FOUND)
    set(ZEROCONF_AVAHI true)
endif()

pkg_check_modules(USES_SYSTEMD libsystemd-daemon>=44)
if(USES_SYSTEMD_FOUND)
    set(HAVE_SYSTEMD true)
endif()

include_directories(${USES_UCOMMON_INCLUDE_DIRS})
link_directories(${USES_UCOMMON_LIBRARY_DIRS})
add_definitions(${USES_UCOMMON_CFLAGS})

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
    set(EXOSIP2_LIBS ${EXOSIP2_LIBS} iphlpapi dnsapi)
endif()

check_function_exists(setrlimit HAVE_SETRLIMIT)
check_function_exists(setgroups HAVE_SETGROUPS)
check_function_exists(setpgrp HAVE_SETPGRP)
check_function_exists(getuid HAVE_GETUID)
check_function_exists(mkfifo HAVE_MKFIFO)
check_function_exists(symlink HAVE_SYMLINK)
check_function_exists(atexit HAVE_ATEXIT)

configure_file(sipwitch-config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/sipwitch-config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

file(GLOB runtime_src common/*.cpp)
file(GLOB runtime_inc inc/sipwitch/*.h)
file(GLOB sipwitch_man utils/*.[1|8])
file(GLOB sipwitch_conf server/*.conf)

STRING(COMPARE EQUAL "${BUILD_RUNTIME_TYPE}" "SHARED" HAVE_PLUGINS)

add_library(sipwitch-runtime ${BUILD_RUNTIME_TYPE} ${runtime_src} ${runtime_inc})
set_target_properties(sipwitch-runtime PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
add_dependencies(sipwitch-runtime ucommon)
target_link_libraries(sipwitch-runtime ${USES_UCOMMON_LIBRARIES} ${EXOSIP2_LIBS})
set_target_properties(sipwitch-runtime PROPERTIES OUTPUT_NAME sipwitch)

add_subdirectory(server)

add_executable(sipwitch-query utils/sipquery.cpp)
add_dependencies(sipwitch-query usecure ucommon eXosip2)
target_link_libraries(sipwitch-query usecure ucommon ${EXOSIP2_LIBS} ${SECURE_LIBS} ${UCOMMON_LIBS})
set_target_properties(sipwitch-query PROPERTIES OUTPUT_NAME sipquery)

install(TARGETS sipwitch-query DESTINATION ${INSTALL_BINDIR})

add_executable(sipwitch-cgi utils/cgiserver.cpp)
add_dependencies(sipwitch-cgi ucommon)
target_link_libraries(sipwitch-cgi ucommon ${UCOMMON_LIBS})

add_executable(sipwitch-passwd utils/sippasswd.cpp)
add_dependencies(sipwitch-passwd usecure ucommon)
target_link_libraries(sipwitch-passwd usecure ucommon ${SECURE_LIBS} ${UCOMMON_LIBS})
set_target_properties(sipwitch-passwd PROPERTIES OUTPUT_NAME sippasswd)

add_executable(sipwitch-control utils/sipwitch.cpp)
add_dependencies(sipwitch-control usecure ucommon)
target_link_libraries(sipwitch-control usecure ucommon ${SECURE_LIBS} ${UCOMMON_LIBS})
set_target_properties(sipwitch-control PROPERTIES OUTPUT_NAME sipwitch)

install(FILES   ${sipwitch_conf} DESTINATION ${SYSCONFDIR})
install(FILES   ${sipwitch_man} DESTINATION ${INSTALL_MANDIR})
install(FILES   ${runtime_inc}  DESTINATION ${INSTALL_INCLUDEDIR}/sipwitch)
install(TARGETS sipwitch-runtime DESTINATION ${INSTALL_LIBDIR})
install(TARGETS sipwitch-control sipwitch-cgi DESTINATION ${INSTALL_BINDIR})
install(TARGETS sipwitch-passwd DESTINATION ${INSTALL_BINDIR} PERMISSIONS SETUID)


