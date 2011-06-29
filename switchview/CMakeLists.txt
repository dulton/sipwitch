# Copyright (C) 2011 David Sugar, Haakon Eriksen, GNU Free Call Foundation
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
file(GLOB qt_src *.cpp)
file(GLOB qt_inc *.h)
file(GLOB ui_src *.ui)

QT4_ADD_RESOURCES(qt_qrc switchview.qrc)
QT4_WRAP_CPP(qt_moc switchview.h)
QT4_WRAP_UI(qt_ui ${ui_src})

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(switchview ${qt_src} ${qt_inc} ${qt_moc} ${qt_qrc} ${qt_ui})
add_dependencies(switchview ucommon)
target_link_libraries(switchview ${QT_LIBRARIES} ${QT_QTSQL_LIBRARIES} ${USES_UCOMMON_LIBRARIES} ${USES_LIBNOTIFY_LIBRARIES})
install(TARGETS switchview DESTINATION ${INSTALL_BINDIR})

if(NOT WIN32)
    file(GLOB autostart switchview-autostart.desktop)
    file(GLOB appmenus menu/switchview.desktop)
    file(GLOB pixmaps pixmaps/switchview.png)

    install(FILES ${autostart} DESTINATION ${SYSCONFDIR}/xdg/autostart)
    install(FILES ${appmenus} DESTINATION ${INSTALL_APPLICATIONS})
    install(FILES ${pixmaps} DESTINATION ${INSTALL_PIXMAPS})
endif()

