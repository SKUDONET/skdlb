#!/bin/bash


load_global_conf() {
	local TMP_CONF="/tmp/global.conf.tmp"
	local GLOBALCONF="/usr/local/zevenet/config/global.conf"

	# remove the characters '$'
	# remove spaces between variable and value in the assignments
	sed 's/^\$//;s/\s*=\s*/=/' $GLOBALCONF > $TMP_CONF

	source $TMP_CONF
	rm $TMP_CONF
}
