# Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_INIT(autogen.sh)

VERSION="0.5.13"
LT_VERSION="0:30:0"
UCOMMON_REQUIRES="2.0.0"

AC_CONFIG_AUX_DIR(autoconf)
AC_CANONICAL_SYSTEM
AC_PROG_CPP
AC_PROG_CC
AC_PROG_CXXCPP
AC_PROG_CXX
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_DLOPEN
AM_PROG_LIBTOOL
AM_INIT_AUTOMAKE(sipwitch, [$VERSION])
AM_CONFIG_HEADER(config.h)

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

test -z "$ac_with_malloc" && ac_with_malloc=""
test -z "$ac_with_crypto" && ac_with_crypto="auto"
test -z "$plugindir" && plugindir='${libdir}' 

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

# make list that is parsed...

AC_ARG_WITH(crypto, 
	AC_HELP_STRING([--with-crypto=lib],[specify crypto library]),[
	case "$with_crypto" in
	libcrypto|crypto)
		ac_with_crypto="openssl"
		;;
	gnutls|libgcrypt)
		ac_with_crypto="gcrypt"
		;;
	none|openssl|gcrypt|crypto|sasl)
		ac_with_crypto="$with_crypto"
		;;
	*)
		AC_ERROR("unrecognized crypto library $with_crypto specified")
		;;
	esac
])	

if test "$ac_with_crypto" = "auto" ; then
	AC_CHECK_HEADER(gcrypt/gcrypt.h, [ac_with_crypto="gcrypt"])
	AC_DEFINE(HAVE_GRYCPT_GRYPT_H, [1], [alternate header])
fi

if test "$ac_with_crypto" = "auto" ; then
	AC_CHECK_HEADER(gcrypt.h, [ac_with_crypto="gcrypt"])
	AC_DEFINE(HAVE_GRYCPT_H, [1], [standard header])
fi

if test "$ac_with_crypto" = "auto" ; then
	AC_CHECK_HEADER(openssl/md5.h, [ac_with_crypto="openssl"])
fi

if test "$ac_with_crypto" = "auto" ; then
	AC_CHECK_HEADER(sasl/md5global.h, [ac_with_crypto="sasl"])
fi

if test "$ac_with_crypto" = "auto" ; then
	ac_with_crypto="none" ; fi

case "$ac_with_crypto" in
gcrypt)
	AC_CHECK_LIB(gcrypt, gcry_control, [
		AC_DEFINE(HAVE_GCRYPT_CRYPTO, [1], [gcrypt crypto used])
		EXPORT_LIBS="$EXPORT_LIBS -lgcrypt"
	],[
		ac_with_crypto="none"
	])
	;;
openssl|crypto)
	AC_CHECK_LIB(crypto, MD5_Init, [
		AC_DEFINE(HAVE_OPENSSL_CRYPTO, [1], [openssl crypto used])
		EXPORT_LIBS="$EXPORT_LIBS -lcrypto"
	],[
		ac_with_crypto="none"
	])
	;;
sasl)
	AC_CHECK_LIB(sasl2, _sasl_MD5Init, [
		AC_DEFINE(HAVE_SASL_CRYPTO, [1], [sasl crypto used])
		EXPORT_LIBS="$EXPORT_LIBS -lsasl2"
	],[
		ac_with_crypto="none"
	])
	;;
esac	

if test "$ac_with_crypto" = "none" ; then
	AC_DEFINE(HAVE_NO_CRYPTO, [1], [use local])
fi
	
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

AC_ARG_WITH(libeXosip2,
	AC_HELP_STRING([--with-libeXosip2=xxx],[specify eXosip2 library]),
		[SIPWITCH_EXOSIP2="$with_libeXosip2"],[SIPWITCH_EXOSIP2="-leXosip2"])

AC_ARG_ENABLE(commands, 
	AC_HELP_STRING([--disable-commands],[disable command options]))
if test -z "$enable_commands" ; then
	enable_commands="yes" ; fi

AC_CHECK_HEADER(eXosip2/eXosip.h,,[
	AC_ERROR("libeXosip2 must be installed or build --disable-sipwitch-server")
])
AC_EGREP_HEADER(EXOSIP_OPT_DONT_SEND_101, eXosip2/eX_setup.h,[
	AC_DEFINE(EXOSIP2_OPTION_SEND_101, 1, [new option])
])
PKG_CHECK_MODULES(LIBOSIP2, libosip2 >= 3.0.0)
AC_DEFINE(OSIP2_LIST_PTR, [&], [define pointer mode])
SIPWITCH_EXOSIP2="$SIPWITCH_EXOSIP2 $LIBOSIP2_LIBS"

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
		#define	_GNU_SOURCE
		#include <stdio.h>
		#include <signal.h>],
		[sigset_t sigs; int signo; sigwait(&sigs, &signo);],
		ac_cv_libc_sigwait2=yes,
		ac_cv_libc_sigwait2=no
	)	
)
if test "$ac_cv_libc_sigwait2" = "yes" ; then
	AC_DEFINE(HAVE_SIGWAIT2, [1], [2 argument form])
fi

if test "$UCOMMON_MODEL" = "CC" ; then
	LIBTOOL='$(SHELL) $(top_srcdir)/cmodel.sh'" ${LIBTOOL}" ; fi

for lib in $UCOMMON_CLINK ; do
	case "$lib" in
	*,-lc)
		lib="-lc"
		;;
	esac
	case "$lib" in
	-l*)
		libc=`echo $lib | sed -e "s/^-l//"`
		AC_CHECK_LIB($libc, localtime_r, [
			AC_DEFINE(HAVE_LOCALTIME_R, [1], [have localtime_r])
		])
		AC_CHECK_LIB($libc, mkfifo, [
			AC_DEFINE(HAVE_MKFIFO, [1], [fifo control port])
		])
		AC_CHECK_LIB($libc, setpgrp, [
			AC_DEFINE(HAVE_SETPGR, [1], [process set group])
		])
		AC_CHECK_LIB($libc, symlink, [
			AC_DEFINE(HAVE_SYMLINK, [1], [support symlinks])
		])
		;;
	*)
		;;
	esac
done

AC_CHECK_HEADERS(sys/resource.h syslog.h net/if.h ioctl.h)
AC_CHECK_FUNCS(setrlimit)

AC_LANG_CPLUSPLUS
COMPILER_FLAGS=""

flags="-Wno-variadic-macros"
for flag in $flags ; do
    AC_MSG_CHECKING([whether ${CXX} supports $flag])
    echo 'void f(){}' >conftest.cpp
    if test -z "`${CXX} $flag -c conftest.cpp 2>&1`"; then
        EXPORT_FLAGS="$EXPORT_FLAGS $flag"
        AC_MSG_RESULT(yes)
    else
        AC_MSG_RESULT(no)
    fi
    rm -f conftest*
done

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

SIPWITCH_FLAGS="$EXPORT_FLAGS $UCOMMON_CFLAGS"
SIPWITCH_LIBS="$EXPORT_LIBS $UCOMMON_LIBS $ac_with_malloc $UCOMMON_CLINK"

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
#ifndef	HAVE_LOCALTIME_R
#define	localtime_r(x, y)	localtime(x)
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

AC_SUBST(LT_VERSION)
AC_SUBST(INITRDDIR)
AC_SUBST(plugindir)
AC_SUBST(UCOMMON_REQUIRES)
AC_SUBST(UCOMMON_MODEL)
AC_SUBST(UCOMMON_CLINK)
AC_SUBST(DAEMON_LIBS)
AC_SUBST(EXPORT_FLAGS)
AC_SUBST(EXPORT_LIBS)
AC_SUBST(INCLUDE_FLAGS)
AC_SUBST(SIPWITCH_FLAGS)
AC_SUBST(SIPWITCH_LIBS)
AC_SUBST(SIPWITCH_EXOSIP2)
AC_SUBST(ZEROCONF_LIBS)
AC_SUBST(CXXFLAGS)
AC_SUBST(MODFLAGS)
AC_SUBST(DLOPEN)
AC_OUTPUT(Makefile common/Makefile inc/Makefile inc/sipwitch/Makefile 
server/Makefile utils/Makefile test/Makefile 
libsipwitch.pc sipwitch.spec sipwitch-config)

