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
set (VERSION 0.10.2)
set (SOVERSION 0)

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
    option(EXOSIP2_TLS "Set to ON to check eXosip2 TLS support" OFF)
else()
    option(BUILD_STATIC "Set to ON to build static libraries" OFF)
    option(HAVE_SIGWAIT2 "Set to OFF to build with single argument" ON)
    set(HAVE_SIGWAIT true)
    option(EXOSIP2_TLS "Set to OFF to disable eXosip2 TLS support check" ON)
endif()
option(BUILD_PACKAGE "Set to OFF to disable packaging and install" ON)

MESSAGE( STATUS "Configuring GNU sipwitch ${VERSION}...")

# set to true for debug and trace during CMakeLists development
set(CMAKE_VERBOSE_MAKEFILE FALSE)

configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# Set defaults and pass common options.  Common build options can be passed
# to cmake using cmake -DWITH_CFLAGS="...", WITH_LIBS, and WITH_INCLUDES
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/inc ${WITH_INCLUDES})
add_definitions(${WITH_CFLAGS})
link_libraries(${WITH_LIBS})
find_package(PkgConfig)

if (USES_UCOMMON_INCLUDE_DIRS)
    message(STATUS "  Using local ucommon dependency")
else()
    pkg_check_modules(USES_UCOMMON REQUIRED ucommon>=4.1.0)
endif()

pkg_check_modules(USES_ZEROCONF avahi-client>0.3)

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

# app specific paths, -DWITH_LIBDIR

if(WITH_BINDIR)
    set(INSTALL_BINDIR ${WITH_BINDIR})
else()
    set(INSTALL_BINDIR bin)
endif()

if(WITH_SBINDIR)
    set(INSTALL_SBINDIR ${WITH_SBINDIR})
else()
    set(INSTALL_SBINDIR sbin)
endif()

if(WITH_LIBDIR)
    set(DEFAULT_LIBPATH ${WITH_LIBDIR})
    set(INSTALL_LIBDIR ${WITH_LIBDIR})
else()
    set(DEFAULT_LIBPATH ${CMAKE_INSTALL_PREFIX}/lib${WITH_LIBSUFFIX})
    set(INSTALL_LIBDIR lib${WITH_LIBSUFFIX})
endif()

if(WITH_VARPATH)
    set(DEFAULT_VARPATH ${WITH_VARPATH}/sipwitch)
else()
    set(DEFAULT_VARPATH ${CMAKE_INSTALL_PREFIX}/var/sipwitch)
endif()

if (WITH_CONFIGDIR)
    set(DEFAULT_CFGPATH ${WITH_CONFIGDIR})
    set(INSTALL_ETCDIR ${WITH_CONFIGDIR})
elseif(WIN32)
    set(DEFAULT_CFGPATH ${CMAKE_INSTALL_PREFIX}/etc)
    set(INSTALL_ETCDIR etc)
else()
    set(DEFAULT_CFGPATH /etc)
    set(INSTALL_ETCDIR /etc)
endif()

check_include_files(sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_files(syslog.h HAVE_SYSLOG_H)
check_include_files(net/if.h HAVE_NET_IF_H)
check_include_files(sys/sockio.h HAVE_SYS_SOCKIO_H)
check_include_files(ioctl.h HAVE_IOCTL_H)
check_include_files(pwd.h HAVE_PWD_H)
check_include_files(eXosip2/eXosip.h HAVE_EXOSIP2)

if(NOT HAVE_EXOSIP2)
    set(EXOSIP2_TLS OFF CACHE BOOL "no tls if no exosip2" FORCE)
    MARK_AS_ADVANCED(EXOSIP2_TLS)
endif()

if(EXOSIP2_TLS AND HAVE_EXOSIP2)
    check_include_files(openssl/openssl.h HAVE_TLS)
endif()

if(HAVE_TLS)
    if(WIN32 AND NOT CYGWIN AND NOT MINGW)
        set (EXOSIP2_LIBS eXosip2 osip2 osipparser2 ssleay32 libeay32 gdi32)
    else()
        set (EXOSIP2_LIBS eXosip2 osip2 osipparser2 ssl crypto z )
    endif()
elseif(HAVE_EXOSIP2)
    set(EXOSIP2_LIBS eXosip2 osip2 osipparser2)
endif()

if(HAVE_EXOSIP2 AND WIN32 AND NOT CYGWIN)
    set(EXOSIP2_LIBS ${EXOSIP2_LIBS} Iphlpapi dnsapi)
endif()

check_function_exists(setrlimit HAVE_SETRLIMIT)
check_function_exists(setpgrp HAVE_SETPGRP)
check_function_exists(getuid HAVE_GETUID)
check_function_exists(mkfifo HAVE_MKFIFO)
check_function_exists(symlink HAVE_SYMLINK)
check_function_exists(atexit HAVE_ATEXIT)

file(GLOB runtime_src common/*.cpp)
file(GLOB runtime_inc inc/sipwitch/*.h)
set(server_src server/server.cpp server/registry.cpp server/stack.cpp server/thread.cpp server/call.cpp server/messages.cpp server/media.cpp server/system.cpp server/signals.cpp server/history.cpp)
set(server_inc server/server.h)

if(BUILD_STATIC)
    set(server_src ${server_src} server/forward.cpp server/scripting.cpp)
endif()

add_library(sipwitch-runtime ${BUILD_LIBRARY_TYPE} ${runtime_src} ${runtime_inc})
set_target_properties(sipwitch-runtime PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
add_dependencies(sipwitch-runtime ucommon)
target_link_libraries(sipwitch-runtime ${USES_UCOMMON_LIBRARIES})
set_target_properties(sipwitch-runtime PROPERTIES OUTPUT_NAME sipwitch)

if(HAVE_EXOSIP2)
    add_executable(sipwitch ${server_src} ${server_inc})
    add_dependencies(sipwitch sipwitch-runtime usecure ucommon)
    target_link_libraries(sipwitch sipwitch-runtime usecure ucommon ${EXOSIP2_LIBS} ${SECURE_LIBS} ${UCOMMON_LIBS})
    set_target_properties(sipwitch PROPERTIES OUTPUT_NAME sipw)

    add_executable(sipwitch-query utils/sipquery.cpp)
    add_dependencies(sipwitch-query usecure ucommon)
    target_link_libraries(sipwitch-query usecure ucommon ${EXOSIP2_LIBS} ${SECURE_LIBS} ${UCOMMON_LIBS})
    set_target_properties(sipwitch-query PROPERTIES OUTPUT_NAME sipquery)
endif()

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

if(NOT BUILD_STATIC AND HAVE_EXOSIP2)
    add_library(sipwitch-forward MODULE server/forward.cpp)
    add_dependencies(sipwitch-forward sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-forward sipwitch-runtime ${EXOSIP2_LIBS} ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-forward PROPERTIES OUTPUT_NAME forward)

    add_library(sipwitch-scripting MODULE server/scripting.cpp)
    add_dependencies(sipwitch-scripting sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-scripting sipwitch-runtime ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-scripting PROPERTIES OUTPUT_NAME scripting)

    add_library(sipwitch-subscriber MODULE server/subscriber.cpp)
    add_dependencies(sipwitch-subscriber sipwitch-runtime usecure ucommon)
    target_link_libraries(sipwitch-subscriber sipwitch-runtime usecure ucommon ${EXOSIP2_LIBS} ${SECURE_LIBS} ${UCOMMON_LIBS})
    set_target_properties(sipwitch-subscriber PROPERTIES OUTPUT_NAME subscriber)
endif()

if(NOT BUILD_STATIC AND USES_ZEROCONF AND HAVE_EXOSIP2)
    add_library(sipwitch-zeroconf MODULE server/scripting.cpp)
    add_dependencies(sipwitch-zeroconf sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-zeroconf sipwitch-runtime ${USES_ZEROCONF_LIBRARIES} ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-zeroconf PROPERTIES OUTPUT_NAME zeroconf)
endif()

if(BUILD_PACKAGE)
    install(FILES   ${runtime_inc}  DESTINATION include/ucommon  COMPONENT headers)
    install(TARGETS sipwitch-runtime DESTINATION ${INSTALL_LIBDIR})
    install(TARGETS sipwitch-control sipwitch-cgi DESTINATION ${INSTALL_BINDIR})
    install(TARGETS sipwitch-passwd DESTINATION ${INSTALL_BINDIR} PERMISSIONS SETUID)

    if(HAVE_EXOSIP2)
        install(TARGETS sipwitch DESTINATION ${INSTALL_SBINDIR})
        install(TARGETS sipwitch-query DESTINATION ${INSTALL_BINDIR})
        if(NOT BUILD_STATIC)
            install(TARGETS sipwitch-forward sipwitch-scripting sipwitch-subscriber DESTINATION ${INSTALL_LIBDIR}/sipwitch)
        endif()
        if(NOT BUILD_STATIC AND USES_ZEROCONF)
            install(TARGETS sipwitch-zeroconf DESTINATION ${INSTALL_LIBDIR}/sipwitch)
        endif()
    endif()
endif()


