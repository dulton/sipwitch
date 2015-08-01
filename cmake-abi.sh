#!/bin/sh
# Copyright (C) 2013-2014 David Sugar, Tycho Softworks.
# Copyright (C) 2015 Cherokees of Idaho.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

ltver=`grep LT_VERSION= configure.ac | sed -e "s/^.*=//" | sed -e "s/\"//g"`
release=`echo $ltver | sed -e "s/:.*//"`
compat=`echo $ltver | sed -e "s/.*://"`
abi=`echo $ltver | sed -e "s/^$release://" -e "s/:.*$//"`
echo="echo"
if test -x "/bin/echo" ; then
	echo="/bin/echo"
elif test -x "/usr/bin/echo" ; then
	echo="/usr/bin/echo"
fi	
$echo $release.$compat.$abi
