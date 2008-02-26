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

exec $shell $cmd --tag=CC $args



