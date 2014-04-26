#!/bin/sh
ltver=`grep LT_VERSION= configure.ac | sed -e "s/^.*=//" | sed -e "s/\"//g"`
release=`echo $ltver | sed -e "s/:.*//"`
compat=`echo $ltver | sed -e "s/.*://"`
abi=`echo $ltver | sed -e "s/^$release://" -e "s/:.*$//"`
echo -n $release.$compat.$abi
