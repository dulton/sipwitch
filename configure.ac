# Copyright (C) 2006-2007 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AC_INIT(autogen.sh)

VERSION="0.2.0"
LT_RELEASE="0.2"
LT_VERSION="0:0"

AC_CONFIG_AUX_DIR(autoconf)
AC_CANONICAL_SYSTEM
AC_PROG_CPP
AC_PROG_CC
AC_PROG_CXXCPP
AC_PROG_CXX
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AM_INIT_AUTOMAKE(sipwitch, [$VERSION])
AM_CONFIG_HEADER(config.h)

LT_MAJOR="`echo $LT_VERSION | sed s/:.*$//`"
LT_MINOR="`echo $LT_VERSION | sed s/.*://`"
LT_SUBVER="$LT_MAJOR.$LT_MINOR"
AC_SUBST(LT_RELEASE)
AC_SUBST(LT_VERSION)
AC_SUBST(LT_SUBVER)
AC_SUBST(LT_MAJOR)
AC_SUBST(LT_MINOR)

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

EXPORT_LIBS=""
EXPORT_FLAGS=""
GNUTELEPHONY_LIBS=""
GNUTELEPHONY_FLAGS=""
SERVER_FLAGS=""
SERVER_LIBS=""
BUILD_SUBDIRS="lib"

ac_with_malloc=""
ac_with_crypto="auto"

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

# make list that is parsed...

AC_ARG_ENABLE(server,  [  --disable-server          compile library only])
if test -z "$enable_server" ; then
	enable_server="yes" ; fi

AC_ARG_WITH(crypto, [  --with-crypto=xxx      specify crypto library],[
	case "$with_crypto" in
	none|openssl|gcrypt|sasl)
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
openssl)
	AC_CHECK_LIB(openssl, MD5_Init, [
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
	
if test "$enable_server" = "yes" ; then
	BUILD_SUBDIRS="$BUILD_SUBDIRS server"
	AC_ARG_WITH(malloc,
		[  --with-malloc=xxx      specify malloc library],[
		with_malloc=`echo $with_malloc | sed -e "s/,/ /g"`
		for malloc in $with_malloc ; do
			AC_CHECK_LIB($malloc, malloc, [
				ac_with_malloc="-l$malloc"])
			if test ! -z "$ac_with_malloc" ; then
				break ; fi
		done
	])

	AC_ARG_ENABLE(commands, [  --disable-commands        disable command options])
	if test -z "$enable_commands" ; then
		enable_commands="yes" ; fi
	if test "$enable_commands" = "yes" ; then
		AC_DEFINE(USES_COMMANDS, [1], [command options])
	fi

	AC_ARG_ENABLE(signals, [  --disable-signals         disable signal handling thread])
	if test -z "$enable_signals" ; then
		enable_signals="yes" ; fi
	if test "$enable_signals" = "yes" ; then
		AC_DEFINE(USES_SIGNALS, [1], [has signal handler])
	fi
fi

AC_ARG_ENABLE(debug, [  --enable-debug          compile for debugging])
if test -z "$enable_debug" ; then
	enable_debug="no"
elif test $enable_debug = "yes" ; then
	CXXFLAGS="${CXXFLAGS} -g -DDEBUG"
fi

if test "$enable_server" = "yes" ; then
	AC_CHECK_HEADER(eXosip2/eXosip.h,,[
		AC_ERROR("libeXosip2 must be installed or build --without-server")
	])
	AC_EGREP_HEADER(EXOSIP_OPT_DONT_SEND_101, eXosip2/eX_setup.h,[
		AC_DEFINE(EXOSIP2_OPTION_SEND_101, 1, [new option])
	])
	PKG_CHECK_MODULES(libosip2, libosip2 >= 3.0.0, [
		AC_DEFINE(OSIP2_LIST_PTR, [&], [define pointer mode])],[
		echo "<3.0.0"
		AC_DEFINE(OSIP2_LIST_PTR, [])
	])

	AC_CACHE_CHECK(whether sigwait has 2 arguments,
		ac_cv_libc_sigwait2,
		AC_TRY_COMPILE([
			#define _POSIX_PTHREAD_SEMANTICS
			#include <stdio.h>
			#include <signal.h>],
			[sigwait(NULL, NULL);],
			ac_cv_libc_sigwait2=yes,
			ac_cv_libc_sigwait2=no
		)	
	)
	if test "$ac_cv_libc_sigwait2" = "yes" ; then
		AC_DEFINE(HAVE_SIGWAIT2, [1], [2 argument form])
	fi
fi

PKG_CHECK_MODULES(UCOMMON, ucommon >= 0.5.1)
UCOMMON_CLINK=`pkg-config --variable=clink ucommon`
UCOMMON_SHARED=`pkg-config --variable=shared ucommon`
UCOMMON_MODULE=`pkg-config --variable=module ucommon`
UCOMMON_MODEL=`pkg-config --variable=model ucommon`

for lib in $UCOMMON_CLINK ; do
	case "$lib" in
	-l*)
		libc=`echo $lib | sed -e "s/^-l//"`
		AC_CHECK_LIB($libc, mkfifo, [
			AC_DEFINE(HAVE_MKFIFO, [1], [fifo control port])
		])
		AC_CHECK_LIB($libc, ftok, [
			AC_DEFINE(HAVE_FTOK, [1], [ftok ipc support])
		])
		AC_CHECK_LIB($libc, setpgrp, [
			AC_DEFINE(HAVE_SETPGR, [1], [process set group])
		])
		;;
	*)
		;;
	esac
done

ac_have_shm_open="no"
for lib in $UCOMMON_LIBS $UCOMMON_CLINK ; do
	case "$lib" in
	-lucommon)
		;;
	-l*)
		libcheck=`echo $lib | sed -e "s/^-l//"`
		if test "$ac_have_shm_open" = "no" ; then
			AC_CHECK_LIB($libcheck, shm_open, [
				AC_DEFINE(HAVE_SHM_OPEN, [1], [shared memory open])
				ac_have_shm_open="yes"
			])
		fi
		;;
	*)
		;;
	esac
done

AC_CHECK_HEADERS(sys/resource.h sys/mman.h syslog.h)

AC_LANG_CPLUSPLUS
COMPILER_FLAGS=""
for flag in $CXXFLAGS ; do
	case $flag in
		-fvisibility=*|-f*exceptions|-f*rtti|-f*check-new|-f*enforce-eh-specs|-finline|-f*except)
		;;
	*)
		COMPILER_FLAGS="$COMPILER_FLAGS $flag"
		;;
	esac
done
export CXXFLAGS="$COMPILER_FLAGS"

GNUTELEPHONY_FLAGS="$EXPORT_FLAGS $UCOMMON_CFLAGS"
GNUTELEPHONY_LIBS="$EXPORT_LIBS $UCOMMON_LIBS $ac_with_malloc $UCOMMON_CLINK"

if test "$localstatedir" == '${prefix}/var' ; then
	localstatedir="/var" ; fi

if test "$sysconfdir" == '${prefix}/etc' ; then
	sysconfdir="/etc/gnutelephony" 
elif test "$sysconfdir" == '/etc' ; then
	sysconfdir="/etc/gnutelephony"
fi

AC_SUBST_DIR(default_cfgpath, sysconfdir)
AC_SUBST_DIR(default_varpath, localstatedir)
AC_SUBST_DIR(default_libpath, libdir)
AC_SUBST_DIR(default_incpath, includedir)

case "$GNUTELEPHONY_FLAGS -I/usr/include" in
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

AH_BOTTOM([
#include <ucommon/ucommon.h>
#include <ucommon/export.h>

#ifdef	_MSWINDOWS_
#undef	USES_SIGNALS
#endif
])

AC_SUBST(UCOMMON_MODEL)
AC_SUBST(UCOMMON_SHARED)
AC_SUBST(EXPORT_FLAGS)
AC_SUBST(EXPORT_LIBS)
AC_SUBST(GNUTELEPHONY_FLAGS)
AC_SUBST(GNUTELEPHONY_LIBS)
AC_SUBST(BUILD_SUBDIRS)
AC_SUBST(CXXFLAGS)
AC_OUTPUT(Makefile lib/Makefile inc/Makefile inc/gnutelephony/Makefile 
server/Makefile test/Makefile libgnutelephony.pc)

