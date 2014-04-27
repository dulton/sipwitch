prefix=${CMAKE_INSTALL_PREFIX}
libdir=${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}
includedir=${CMAKE_INSTALL_PREFIX}/include

Name: libsipwitch
Description: Sip Witch supporting library for plugins
Version: ${VERSION}
Requires: ucommon >= 6.0.0
Libs:  -lsipwitch ${PACKAGE_LIBS}
Cflags: ${PACKAGE_FLAGS}
 
