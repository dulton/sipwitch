# Copyright (C) 2006-2010 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_INIT(autogen.sh)

VERSION="1.3.1"
LT_VERSION="1:6:0"
UCOMMON_REQUIRES="5.2.0"

AC_CONFIG_AUX_DIR(autoconf)
AC_CANONICAL_SYSTEM
AC_PROG_CPP
AC_PROG_CC
AC_PROG_CXXCPP
AC_PROG_CXX
AC_PROG_LN_S
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_DLOPEN
AM_PROG_LIBTOOL
AM_INIT_AUTOMAKE(sipwitch, [$VERSION])
AM_CONFIG_HEADER(sipwitch-config.h)

AC_C_RESTRICT
AC_C_VOLATILE
AC_C_INLINE

if test -z "$PKG_CONFIG_PATH" ; then
    case "$prefix" in
    NONE|/usr/local|/usr)
        PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
        ;;
    *)
        PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
        ;;
    esac
else
    case "$prefix" in
    NONE|/usr/local|/usr)
        PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
        ;;
    *)
        PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$prefix/lib/pkgconfig"
        ;;
    esac
fi

export PKG_CONFIG_PATH

INCLUDE_FLAGS=""
EXPORT_LIBS=""
EXPORT_FLAGS=""
SIPWITCH_LIBS=""
SIPWITCH_FLAGS=""
SERVER_FLAGS=""
SERVER_LIBS=""

AC_ARG_ENABLE(qt,
    [  --disable-qt        disable support for qt],
    enable_qt=$enableval,enable_qt="yes")

if test "x${enable_qt}" = "xyes" ; then
    PKG_CHECK_MODULES(QT, QtGui >= 4.0.1,,enable_qt="no") ; fi

AC_CHECK_PROG(PKG_CONFIG, [pkg-config], [pkg-config])

if test "x${enable_qt}" = "xyes" ; then
    dnl Check needed because in some cases the QtGui includedir
    dnl doesn't contain the subsystem dir.

    QT_INCLUDE_DIR=$($PKG_CONFIG --variable=includedir QtGui)
    EXTRA_QT_INCLUDE_DIR="$QT_INCLUDE_DIR/Qt"
    AC_CHECK_FILE([$QT_INCLUDE_DIR/QWidget],
                  AC_MSG_NOTICE([No extra QT_INCLUDE_DIR needed]),

                  AC_CHECK_FILE([$EXTRA_QT_INCLUDE_DIR/QWidget],
                        QT_CFLAGS="$QT_CFLAGS -I$EXTRA_QT_INCLUDE_DIR",
                        AC_MSG_WARN([QWidget not found])))
    AC_MSG_NOTICE([Set QT_CFLAGS... $QT_CFLAGS])
    AC_CHECK_PROGS(MOC, [moc moc-qt4], [no])
    AC_CHECK_PROGS(RCC, [rcc], [no])
    AC_CHECK_PROGS(UIC, [uic uic-qt4], [no])

    QTAPPS="switchview"

    AC_SUBST(QT_CFLAGS)
    AC_SUBST(QT_LIBS)
fi

AC_SUBST(QTAPPS)

AC_ARG_ENABLE(openssl,
    [  --enable-openssl        enable support for openssl],
    enable_openssl=$enableval,enable_openssl="auto")

if test "$enable_openssl" = "yes" ; then
    AC_DEFINE(HAVE_TLS, [1], [have exosip tls support in sipwitch])
fi

if test "$enable_openssl" = "auto" ; then
    AC_CHECK_HEADER(openssl/openssl.h, [
        AC_DEFINE(HAVE_TLS, [1], [have exosip tls support in sipwitch])
    ])
fi

test -z "$ac_with_malloc" && ac_with_malloc=""
test -z "$plugindir" && plugindir='${libdir}'
test -z "$translatedir" && translatedir='${datadir}/sipwitch/translations'

AC_DEFUN([AC_SUBST_DIR], [
    ifelse($2,,,$1="[$]$2")
    result="***"
    prior="A"
    while test "$prior" != "$result" ; do
        prior=`(echo "[$]$1")`
        $1=`(
        test "x$prefix" = xNONE && prefix="$ac_default_prefix"
        test "x$exec_prefix" = xNONE && exec_prefix="${prefix}"
        eval echo \""[$]$1"\"
        )`
        result=`(echo "[$]$1")`
    done
    AC_SUBST($1)
])

# lets check init path
AC_ARG_WITH(initrddir,
    AC_HELP_STRING([--with-initrddir=path], [specify /etc/init.d path]),[
        INITRDDIR="$with_initrddir"
])

# define network script paths
AC_ARG_WITH(netscripting,
    AC_HELP_STRING([--with-netscripting=type], [specify scripting type]),[
        case "$with_netscripting" in
        debian)
            NETWORK_UP="/etc/network/if-up.d"
            NETWORK_DOWN="/etc/network/if-down.d"
            ;;
        nm|NetworkManager|nmanager)
            NETWORK_RELOAD="/etc/NetworkManager/dispatcher.d"
            ;;
        esac
])


# and cgi bin path
AC_ARG_WITH(cgibindir,
    AC_HELP_STRING([--with-cgibindir=path], [specific cgi-bin path]), [
        cgibindir="$with_initrddir"
])

if test -z "$cgibindir" ; then
    cgibindir='${libdir}/cgi-bin' ; fi

# make list that is parsed...

AC_ARG_ENABLE(debug,
    AC_HELP_STRING([--enable-debug],[compile for debugging]))
if test -z "$enable_debug" ; then
    enable_debug="no"
elif test $enable_debug = "yes" ; then
    CXXFLAGS="${CXXFLAGS} -g -DDEBUG"
fi

AC_ARG_WITH(pkg-config,
    AC_HELP_STRING([--with-pkg-config],[enable support for pkg-config]),[
    PKG_CHECK_MODULES(UCOMMON, ucommon >= $UCOMMON_REQUIRES)
    UCOMMON_CLINK=`pkg-config --variable=clink ucommon`
    UCOMMON_MODEL=`pkg-config --variable=model ucommon`
],[
    AC_PATH_PROG([UCOMMON],[ucommon-config],[none])
    if test $UCOMMON = "none" ; then
        AC_ERROR("required ucommon library missing")
    fi
    UCOMMON_CLINK=`$UCOMMON --clink`
    UCOMMON_MODEL=`$UCOMMON --model`
    UCOMMON_CFLAGS=`$UCOMMON --cflags`
    UCOMMON_LIBS=`$UCOMMON --libs`
])

AC_ARG_WITH(malloc,
    AC_HELP_STRING([--with-malloc=xxx],[specify malloc library]),[
    with_malloc=`echo $with_malloc | sed -e "s/,/ /g"`
    for malloc in $with_malloc ; do
        AC_CHECK_LIB($malloc, malloc,
            [ac_with_malloc="-l$malloc"])
        if test ! -z "$ac_with_malloc" ; then
            break ; fi
    done
])

AC_ARG_ENABLE(commands,
    AC_HELP_STRING([--disable-commands],[disable command options]))
if test -z "$enable_commands" ; then
    enable_commands="yes" ; fi

PKG_CHECK_MODULES(EXOSIP2, eXosip2 >= 3.0.0, [
        AC_DEFINE(EXOSIP2_OPTION_SEND_101, 1, [new option 6])
        AC_DEFINE(EXOSIP2_OPTION_RPORT, 1, [new option 7])
    ],[
    AC_ARG_WITH(libeXosip2,
        AC_HELP_STRING([--with-libeXosip2=xxx],[specify eXosip2 library]),
            [EXOSIP2_LIBS="$with_libeXosip2"],[EXOSIP2_LIBS="-leXosip2"])

    AC_CHECK_HEADER(resolv.h,[
        EXOSIP2_LIBS="$EXOSIP2_LIBS -lresolv"
    ],[])

    AC_CHECK_HEADER(eXosip2/eXosip.h,,[
        AC_ERROR("libeXosip2 must be installed or build --disable-sipwitch-server")
    ])
    AC_EGREP_HEADER(EXOSIP_OPT_DONT_SEND_101, eXosip2/eX_setup.h,[
        AC_DEFINE(EXOSIP2_OPTION_SEND_101, 1, [new option 6])
    ])
    AC_EGREP_HEADER(EXOSIP_OPT_USE_RPORT, eXosip2/eX_setup.h,[
        AC_DEFINE(EXOSIP2_OPTION_RPORT, 1, [new option 7])
    ])
])

PKG_CHECK_MODULES(LIBOSIP2, libosip2 >= 3.0.0)
AC_DEFINE(OSIP2_LIST_PTR, [&], [define pointer mode])
SIPWITCH_EXOSIP2="$EXOSIP2_LIBS $LIBOSIP2_LIBS"

case "$target" in
*mingw*)
    SIPWITCH_EXOSIP2="$SIPWITCH_EXOSIP2 -liphlpapi -ldnsapi"
    ;;
esac

AC_TYPE_SIGNAL
AC_CACHE_CHECK(whether sigwait has 2 arguments,
    ac_cv_libc_sigwait2,
    AC_TRY_COMPILE([
        #define _POSIX_PTHREAD_SEMANTICS
        #define _GNU_SOURCE
        #include <stdio.h>
        #include <signal.h>],
        [sigset_t sigs; int signo; sigwait(&sigs, &signo);],
        ac_cv_libc_sigwait2=yes,
        ac_cv_libc_sigwait2=no
    )
)
if test "$ac_cv_libc_sigwait2" = "yes" ; then
    AC_DEFINE(HAVE_SIGWAIT2, [1], [2 argument form])
    AC_DEFINE(HAVE_SIGWAIT, [1], [have sigwait])
else
    AC_CACHE_CHECK(whether has any sigwait support,
        ac_cv_libc_sigwait,
        AC_TRY_COMPILE([
            #define _POSIX_PTHREAD_SEMANTICS
            #define _GNU_SOURCE
            #include <stdio.h>
            #include <signal.h>],
            [sigset_t sigs; int signo = sigwait(&sigs);],
            ac_cv_libc_sigwait2=yes,
            ac_cv_libc_sigwait2=no
        )
    )

    if test "$ac_cv_libc_sigwait" = "yes" ; then
        AC_DEFINE(HAVE_SIGWAIT, [1], [have sigwait])
    else
        AC_CHECK_FUNCS(sigwait)
    fi
fi

if test "$UCOMMON_MODEL" = "CC" ; then
    LIBTOOL='$(SHELL) $(top_srcdir)/cmodel.sh'" ${LIBTOOL}" ; fi

AC_CHECK_HEADERS(sys/resource.h syslog.h net/if.h sys/sockio.h ioctl.h pwd.h sys/inotify.h)
AC_CHECK_FUNCS(setrlimit setpgrp setrlimit getuid mkfifo gethostname symlink)

AC_LANG_CPLUSPLUS
COMPILER_FLAGS=""

for flag in $CXXFLAGS ; do
    case "$flag" in
    -f*exceptions|-f*rtti|-f*check-new|-f*enforce-eh-specs|-finline|-f*except)
        if test "$UCOMMON_MODEL" = "CXX" ; then
            COMPILER_FLAGS="$COMPILER_FLAGS $flag" ; fi
        ;;
    -fvisibility=*)
        ;;
    -I*)
        idir=`echo $flag | sed -e "s/^-I//"`
        COMPILER_FLAGS="$COMPILER_FLAGS $flag"
        INCLUDE_FLAGS="$INCLUDE_FLAGS $flag"
        ;;
    *)
        COMPILER_FLAGS="$COMPILER_FLAGS $flag"
        ;;
    esac
done
export CXXFLAGS="$COMPILER_FLAGS"

SIPWITCH_FLAGS="$EXPORT_FLAGS $EXOSIP2_CFLAGS $LIBOSIP2_CFLAGS $UCOMMON_CFLAGS"
SIPWITCH_LIBS="$EXPORT_LIBS $UCOMMON_LIBS $ac_with_malloc"
ulibs=""
slibs=""
for lib in $UCOMMON_LIBS ; do
    case "$lib" in
    -L*|-lucommon|*ucommon.a|*ucommon.so|*ucommon.la)
        ulibs="$ulibs $lib"
        ;;
    -lusecure|*usecure.a|*usecure.so|*usecure.la)
        slibs="$slibs $lib"
        ;;
    esac
done
USECURE_LINK="$slibs $ulibs"
UCOMMON_LINK="$ulibs"
if test "$UCOMMON_MODEL" = "CC" ; then
    SIPWITCH_LIBS="$SIPWITCH_LIBS $UCOMMON_CLINK" ; fi

if test "$localstatedir" = '${prefix}/var' ; then
    localstatedir="/var" ; fi

if test "$sysconfdir" = '${prefix}/etc' ; then
    sysconfdir="/etc"
fi

AC_SUBST_DIR(default_cfgpath, sysconfdir)
AC_SUBST_DIR(default_varpath, localstatedir)
AC_SUBST_DIR(default_libpath, plugindir)
AC_SUBST_DIR(default_incpath, includedir)
AC_SUBST_DIR(default_libexec, libexecdir)
AC_SUBST_DIR(prefix_libdir, libdir)
AC_SUBST_DIR(translations, translatedir)

if test -z "$NETWORK_UP" ; then
    NETWORK_UP="none" ; fi

if test -z "$NETWORK_DOWN" ; then
    NETWORK_DOWN="none" ; fi

if test -z "$NETWORK_RELOAD" ; then
    NETWORK_RELOAD="none" ; fi

if test -z "$INITRDDIR" ; then
    INITRDDIR="$default_cfgpath/init.d" ; fi

case "$SIPWITCH_FLAGS -I/usr/include" in
*-I${default_incpath}*)
    ;;
*)
    EXPORT_FLAGS="$EXPORT_FLAGS -I$default_incpath"
    ;;
esac

case "-L/usr/lib $EXPORT_LIBS" in
*-L${default_libpath}*)
    ;;
*)
    EXPORT_LIBS="-L$default_libpath $EXPORT_LIBS"
    ;;
esac

AC_DEFINE_UNQUOTED(TRANSLATIONS, "$translations", [translation path])
AC_DEFINE_UNQUOTED(DEFAULT_CFGPATH, "$default_cfgpath", [config path])
AC_DEFINE_UNQUOTED(DEFAULT_VARPATH, "$default_varpath", [run path])
AC_DEFINE_UNQUOTED(DEFAULT_LIBPATH, "$default_libpath", [lib path])
AC_DEFINE_UNQUOTED(DEFAULT_LIBEXEC, "$default_libexec", [script path])

zeroconf=""
ZEROCONF_LIBS=""
if test -z "$zeroconf" ; then
    PKG_CHECK_MODULES(ZEROCONF, avahi-client > 0.3, [
        AC_DEFINE(ZEROCONF_AVAHI, 1, [zeroconf avahi client])
        zeroconf="avahi"
    ],[zeroconf="$zeroconf"])
fi

AH_BOTTOM([
#ifndef HAVE_LOCALTIME_R
#define localtime_r(x, y)   localtime(x)
#endif

#ifdef  _MSC_VER
#define MODULE_EXT ".dll"
#else
#define MODULE_EXT ".so"
#endif

])

DAEMON_LIBS=""
AC_CHECK_LIB(msvcrt, fopen, [
    DAEMON_LIBS="-ladvapi32"
])

AM_CONDITIONAL(STATIC_MODULES, test "$enable_shared" = "no")
if test "$enable_shared" = "no" ; then
    MODFLAGS="-static"
    DLOPEN="-dlopen scripting.la"
    if test ! -z "$zeroconf" ; then
        DLOPEN="$DLOPEN -dlopen zeroconf.la" ; fi
else
    MODFLAGS="-shared -avoid-version"
    DLOPEN=""
fi

AM_CONDITIONAL(ZEROCONF, test ! -z "$zeroconf")

AC_SUBST(cgibindir)
AC_SUBST(plugindir)
AC_SUBST(translatedir)
AC_SUBST(LT_VERSION)
AC_SUBST(INITRDDIR)
AC_SUBST(NETWORK_UP)
AC_SUBST(NETWORK_DOWN)
AC_SUBST(NETWORK_RELOAD)
AC_SUBST(UCOMMON_REQUIRES)
AC_SUBST(UCOMMON_MODEL)
AC_SUBST(UCOMMON_CLINK)
AC_SUBST(DAEMON_LIBS)
AC_SUBST(EXPORT_FLAGS)
AC_SUBST(EXPORT_LIBS)
AC_SUBST(INCLUDE_FLAGS)
AC_SUBST(UCOMMON_LINK)
AC_SUBST(USECURE_LINK)
AC_SUBST(SIPWITCH_FLAGS)
AC_SUBST(SIPWITCH_LIBS)
AC_SUBST(SIPWITCH_EXOSIP2)
AC_SUBST(ZEROCONF_LIBS)
AC_SUBST(CXXFLAGS)
AC_SUBST(MODFLAGS)
AC_SUBST(DLOPEN)
AC_OUTPUT(Makefile common/Makefile inc/Makefile inc/sipwitch/Makefile
server/Makefile switchview/Makefile utils/Makefile test/Makefile
libsipwitch.pc sipwitch.spec sipwitch-config)

