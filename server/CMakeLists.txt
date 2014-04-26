# Copyright (C) 2011 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
#

set(server_src server.cpp registry.cpp stack.cpp thread.cpp call.cpp messages.cpp media.cpp system.cpp signals.cpp history.cpp digests.cpp)
set(server_inc server.h)

if(NOT HAVE_PLUGINS)
    set(server_src ${server_src} forward.cpp scripting.cpp)
endif()

add_executable(sipwitch ${server_src} ${server_inc})
add_dependencies(sipwitch sipwitch-runtime usecure ucommon eXosip2)
target_link_libraries(sipwitch sipwitch-runtime usecure ucommon ${EXOSIP2_LIBS} ${USES_UCOMMON_LIBRARIES} ${USES_SYSTEMD_LIBRARIES})
set_target_properties(sipwitch PROPERTIES OUTPUT_NAME sipw)
install(TARGETS sipwitch DESTINATION ${INSTALL_SBINDIR})

if(HAVE_PLUGINS)
    add_library(sipwitch-forward MODULE forward.cpp)
    add_dependencies(sipwitch-forward sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-forward sipwitch-runtime ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-forward PROPERTIES OUTPUT_NAME forward SUFFIX ${MODULE_EXT} PREFIX "")

    add_library(sipwitch-scripting MODULE scripting.cpp)
    add_dependencies(sipwitch-scripting sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-scripting sipwitch-runtime ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-scripting PROPERTIES OUTPUT_NAME scripting SUFFIX ${MODULE_EXT} PREFIX "")

    add_library(sipwitch-subscriber MODULE subscriber.cpp)
    add_dependencies(sipwitch-subscriber sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-subscriber sipwitch-runtime usecure ucommon ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-subscriber PROPERTIES OUTPUT_NAME subscriber SUFFIX ${MODULE_EXT} PREFIX "")

    install(TARGETS sipwitch-forward sipwitch-scripting sipwitch-subscriber DESTINATION ${INSTALL_PLUGINS})
endif()

if(HAVE_PLUGINS AND USES_ZEROCONF_FOUND)
    add_library(sipwitch-zeroconf MODULE zeroconf.cpp)
    add_dependencies(sipwitch-zeroconf sipwitch-runtime ucommon)
    target_link_libraries(sipwitch-zeroconf sipwitch-runtime ${USES_ZEROCONF_LIBRARIES} ${USES_UCOMMON_LIBRARIES})
    set_target_properties(sipwitch-zeroconf PROPERTIES OUTPUT_NAME zeroconf SUFFIX ${MODULE_EXT} PREFIX "")

    install(TARGETS sipwitch-zeroconf DESTINATION ${INSTALL_PLUGINS})
endif()


