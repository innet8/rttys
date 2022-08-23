package config

const CheckStartContent = string(`#!/bin/sh
. /lib/functions/gl_util.sh

check_dnsmasq() {
	dnsmasq --version &> /dev/null
	if [ $? -ne  0 ]; then
		echo "未安装 dnsmasq"
		exit 1
	fi
}

check_iptables() {
	iptables --version &> /dev/null
	if [ $? -ne  0 ]; then
		echo "未安装 iptables"
		exit 1
	fi
	ipset version &> /dev/null
	if [ $? -ne  0 ]; then
		echo "未安装 ipset"
		exit 1
	fi
}

check_dnsmasq
check_iptables
`)
