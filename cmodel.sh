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

# Replace for old libtool??

version=`${cmd} --version 2>/dev/null | sed -e 's/([^)]*//g;s/^[^0-9]*//;s/[- ].*//g;q'` 
if test -z "$version" ; then
	version="1.5.x" ; fi
case "$version" in
1.3.*|1.4.*)
	tag=""
	;;
*)
	tag="--tag=CC"
	;;
esac
exec $shell $cmd $tag $args



