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
set (VERSION 1.2.4)
set (SOVERSION 1)

set(INSTALL_INCLUDEDIR include)
set(INSTALL_BINDIR bin)
set(INSTALL_SBINDIR sbin)
set(INSTALL_LIBEXEC libexec)

if(WIN32)
    set(MODULE_EXT .mll)
    set(INSTALL_MANDIR man)
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
    set(INSTALL_MANDIR share/man)
    set(INSTALL_LOCALE share/locale)
    set(INSTALL_DOCDIR share/doc/${PROJECT_NAME})
    set(INSTALL_INFODIR share/info)
    set(INSTALL_LIBDIR lib${LIB_SUFFIX})
    set(INSTALL_PLUGINS ${INSTALL_LIBDIR}/sipwitch)
    set(INSTALL_PIXMAPS share/pixmaps)
    set(INSTALL_APPLICATIONS share/applications)
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

if(MSVC60)
    set(BUILD_QT false)
else()
    find_package(Qt4)
    if(QT4_FOUND)
        include(${QT_USE_FILE})
        ADD_DEFINITIONS(-DQT_GUI_LIBS -DQT_CORE_LIB)
        set(BUILD_QT true)
        message(STATUS "Building with QT Support")
    else()
        set(BUILD_QT false)
        message(STATUS "Building without QT")
    endif()
endif()

if (WIN32)
    # too broken to build dll's with const static members...
    if(MSVC60)
        set(BUILD_STATIC ON CACHE BOOL "static linking only" FORCE)
        MARK_AS_ADVANCED(FORCE BUILD_STATIC BUILD_QT)
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
    pkg_check_modules(USES_UCOMMON REQUIRED ucommon>=4.3.0)
endif()

pkg_check_modules(USES_ZEROCONF avahi-client>0.3)

pkg_check_modules(USES_LIBNOTIFY libnotify>=0.4.0)
if(USES_LIBNOTIFY_FOUND)
    add_definitions(-DUSES_LIBNOTIFY)
endif()

include_directories(${USES_UCOMMON_INCLUDE_DIRS})
link_directories(${USES_UCOMMON_LIBRARY_DIRS} ${USES_LIBNOTIFY_LIBRARY_DIRS})
add_definitions(${USES_UCOMMON_CFLAGS} ${USES_LIBNOTIFY_CFLAGS})

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

if(NOT HAVE_EXOSIP2)
    set(EXOSIP2_TLS OFF CACHE BOOL "no tls if no exosip2" FORCE)
    MARK_AS_ADVANCED(EXOSIP2_TLS)
endif()

if(EXOSIP2_TLS AND HAVE_EXOSIP2)
    check_include_files(openssl/ssl.h HAVE_TLS)
endif()

if(HAVE_TLS)
    if(WIN32 AND NOT CYGWIN AND NOT MINGW)
        set (EXOSIP2_LIBS eXosip2 osip2 osipparser2 ssleay32 libeay32 gdi32)
    else()
        set (EXOSIP2_LIBS eXosip2 osip2 osipparser2 ssl crypto z)
    endif()
elseif(HAVE_EXOSIP2)
    set(EXOSIP2_LIBS eXosip2 osip2 osipparser2)
endif()

check_include_files(resolv.h HAVE_RESOLV)
if(HAVE_RESOLV)
    set(EXOSIP2_LIBS ${EXOSIP2_LIBS} resolv)
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

configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

file(GLOB runtime_src common/*.cpp)
file(GLOB runtime_inc inc/sipwitch/*.h)

STRING(COMPARE EQUAL "${BUILD_RUNTIME_TYPE}" "SHARED" HAVE_PLUGINS)

add_library(sipwitch-runtime ${BUILD_RUNTIME_TYPE} ${runtime_src} ${runtime_inc})
set_target_properties(sipwitch-runtime PROPERTIES VERSION ${VERSION} SOVERSION ${SOVERSION})
add_dependencies(sipwitch-runtime ucommon)
target_link_libraries(sipwitch-runtime ${USES_UCOMMON_LIBRARIES})
set_target_properties(sipwitch-runtime PROPERTIES OUTPUT_NAME sipwitch)

if(HAVE_EXOSIP2)
    add_subdirectory(server)

    add_executable(sipwitch-query utils/sipquery.cpp)
    add_dependencies(sipwitch-query usecure ucommon eXosip2)
    target_link_libraries(sipwitch-query usecure ucommon ${EXOSIP2_LIBS} ${SECURE_LIBS} ${UCOMMON_LIBS})
    set_target_properties(sipwitch-query PROPERTIES OUTPUT_NAME sipquery)

    install(TARGETS sipwitch-query DESTINATION ${INSTALL_BINDIR})
endif()

if(BUILD_QT)
    add_subdirectory(switchview)
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


install(FILES   ${runtime_inc}  DESTINATION ${INSTALL_INCLUDEDIR}/sipwitch  COMPONENT headers)
install(TARGETS sipwitch-runtime DESTINATION ${INSTALL_LIBDIR})
install(TARGETS sipwitch-control sipwitch-cgi DESTINATION ${INSTALL_BINDIR})
install(TARGETS sipwitch-passwd DESTINATION ${INSTALL_BINDIR} PERMISSIONS SETUID)



