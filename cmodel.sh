#!/bin/sh
args=""
tag="no"
shell=$1
shift
cmd=$1
shift
for arg in $* ; do
	case "$arg" in
	--tag=*)
		tag="no"
		;;
	--tag)
		tag="yes"
		;;
	*)
		if test "$tag" = "no" ; then
			args="$args $arg"
		fi
		tag="no"
		;;
	esac
done

tag="--tag=CC"
version=`libtool --version | sed -e s/^[^0-9]*//`
if test -z "$version" ; then
	version="1.5.x" ; fi

case "$version" in
1.4.*|1.3.*|1.2.*)
	tag=""
	;;
esac
exec $shell $cmd $tag $args



