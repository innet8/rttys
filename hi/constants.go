package hi

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"text/template"
)

// 网络下载
const ReadDBAWK = string(`
#!/usr/bin/awk

function inInterfaces(host) {
	return(interfaces ~ "(^| )" host "($| )")
}

function newRule(arp_ip, ipt_cmd) {
	# checking for existing rules shouldn't be necessary if newRule is
	# always called after db is read, arp table is read, and existing
	# iptables rules are read.
	ipt_cmd=iptKey " -t mangle -j RETURN -s " arp_ip
	system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
	ipt_cmd=iptKey " -t mangle -j RETURN -d " arp_ip
	system(ipt_cmd " -C RRDIPT_FORWARD 2>/dev/null || " ipt_cmd " -A RRDIPT_FORWARD")
}

function delRule(arp_ip, ipt_cmd) {
	ipt_cmd=iptKey " -t mangle -D RRDIPT_FORWARD -j RETURN "
	system(ipt_cmd "-s " arp_ip " 2>/dev/null")
	system(ipt_cmd "-d " arp_ip " 2>/dev/null")
}

function total(i) {
	return(bw[i "/in"] + bw[i "/out"])
}

BEGIN {
	if (ipv6) {
		iptNF	= 8
		iptKey	= "ip6tables"
	} else {
		iptNF	= 9
		iptKey	= "iptables"
	}
}

/^#/ { # get DB filename
	FS	= ","
	dbFile	= FILENAME
	next
}

# data from database; first file
ARGIND==1 { #!@todo this doesn't help if the DB file is empty.
	lb=$1

	if (lb !~ "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$") next

	if (!(lb in mac)) {
		mac[lb]		= $1
		ip[lb]		= $2
		inter[lb]	= $3
		speed[lb "/in"]	= 0
		speed[lb "/out"]= 0
		bw[lb "/in"]	= $6
		bw[lb "/out"]	= $7
		firstDate[lb]	= $9
		lastDate[lb]	= $10
		ignore[lb]	= 1
	} else {
		if ($9 < firstDate[lb])
			firstDate[lb]	= $9
		if ($10 > lastDate[lb]) {
			ip[lb]		= $2
			inter[lb]	= $3
			lastDate[lb]	= $10
		}
		bw[lb "/in"]	+= $6
		bw[lb "/out"]	+= $7
		ignore[lb]	= 0
	}
	next
}

# not triggered on the first file
FNR==1 {
	FS=" "
	if(ARGIND == 2) next
}

# arp: ip hw flags hw_addr mask device
ARGIND==2 {
	#!@todo regex match IPs and MACs for sanity
	if (ipv6) {
		statFlag= ($4 != "FAILED" && $4 != "INCOMPLETE")
		macAddr	= $5
		hwIF	= $3
	} else {
		statFlag= ($3 != "0x0")
		macAddr	= $4
		hwIF	= $6
	}

	lb=$1
	if (hwIF != wanIF && statFlag && macAddr ~ "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$") {
		hosts[lb]		= 1
		arp_mac[lb]		= macAddr
		arp_ip[lb]		= $1
		arp_inter[lb]		= hwIF
		arp_bw[lb "/in"]	= 0
		arp_bw[lb "/out"]	= 0
		arp_firstDate[lb]	= systime()
		arp_lastDate[lb]	= arp_firstDate[lb]
		arp_ignore[lb]		= 1
	}
	next
}

#!@todo could use mangle chain totals or tailing "unnact" rules to
# account for data for new hosts from their first presence on the
# network to rule creation. The "unnact" rules would have to be
# maintained at the end of the list, and new rules would be inserted
# at the top.
ARGIND==3 && NF==iptNF && $1!="pkts" { # iptables input
	if (ipv6) {
		lfn = 5
		tag = "::/0"
	} else {
		lfn = 6
		tag = "0.0.0.0/0"
	}

	if ($(lfn) != "*") {
		m = $(lfn)
		n = m "/in"
	} else if ($(++lfn) != "*") {
		m = $(lfn)
		n = m "/out"
	} else if ($(++lfn) != tag) {
		m = $(lfn)
		n = m "/out"
	} else { # $(++lfn) != tag
		m = $(++lfn)
		n = m "/in"
	}

	if (mode == "diff" || mode == "noUpdate") print n, $2
	if (mode != "noUpdate") {
		if (inInterfaces(m)) { # if label is an interface
			if (!(m in arp_mac)) {
				cmd = "cat /sys/class/net/" m "/address"
				cmd | getline arp_mac[m]
				close(cmd)

				if (length(arp_mac[m]) == 0) arp_mac[m] = "00:00:00:00:00:00"

				arp_ip[m]		= "NA"
				arp_inter[m] 		= m
				arp_bw[m "/in"]		= 0
				arp_bw[m "/out"]	= 0
				arp_firstDate[m]	= systime()
				arp_lastDate[m]		= arp_firstDate[m]
				arp_ignore[lb]		= 1
			}
		} else {
			if (!(m in arp_mac)) hosts[m] = 0
			else delete hosts[m]
		}

		if ($2 > 0) {
			arp_bw[n]	= $2
			arp_lastDate[m]	= systime()
			arp_ignore[m]	= 0
		}
	}
}

END {
	if (mode == "noUpdate") exit

	for (i in arp_ip) {
		lb = arp_mac[i]
		if (!arp_ignore[i] || !(lb in mac)) {
			ignore[lb]	= 0

			if (lb in mac) {
				bw[lb "/in"]	+= arp_bw[i "/in"]
				bw[lb "/out"]	+= arp_bw[i "/out"]
				lastDate[lb]	= arp_lastDate[i]
			} else {
				bw[lb "/in"]	= arp_bw[i "/in"]
				bw[lb "/out"]	= arp_bw[i "/out"]
				firstDate[lb]	= arp_firstDate[i]
				lastDate[lb]	= arp_lastDate[i]
			}
			mac[lb]		= arp_mac[i]
			ip[lb]		= arp_ip[i]
			inter[lb]	= arp_inter[i]

			if (interval != 0) {
				speed[lb "/in"]	= int(arp_bw[i "/in"] / interval)
				speed[lb "/out"]= int(arp_bw[i "/out"] / interval)
			}
		}
	}

	close(dbFile)
	for (i in mac) {
		if (!ignore[i]) {
			print "#mac,ip,iface,speed_in,speed_out,in,out,total,first_date,last_date" > dbFile
			OFS=","
			for (i in mac)
				print mac[i], ip[i], inter[i], speed[i "/in"], speed[i "/out"], bw[i "/in"], bw[i "/out"], total(i), firstDate[i], lastDate[i] > dbFile
			close(dbFile)
			break
		}
	}

	# for hosts without rules
	for (i in hosts)
		if (hosts[i]) newRule(i)
		else delRule(i)
}
`)

// 网络下载
const WrtbwmonScript = string(`
#!/bin/sh
#

# Default input parameters for wrtbwmon.
runMode=0
Monitor46=4

# Some parameters for monitor process.
for46=
updatePID=
logFile=/var/log/wrtbwmon.log
lockFile=/var/lock/wrtbwmon.lock
pidFile=/var/run/wrtbwmon.pid
tmpDir=/var/tmp/wrtbwmon
interval4=0
interval6=0

# Debug parameters for readDB.awk.
mode=
DEBUG=

# Constant parameter for wrtbwmon.
binDir=/usr/sbin
dataDir=/usr/share/wrtbwmon

networkFuncs=/lib/functions/network.sh
uci=$(which uci 2>/dev/null)
nslookup=$(which nslookup 2>/dev/null)
nvram=$(which nvram 2>/dev/null)

chains='INPUT OUTPUT FORWARD'
interfaces='eth0 tun0 br-lan' # in addition to detected WAN

# DNS server for reverse lookups provided in "DNS".
# don't perform reverse DNS lookups by default
DO_RDNS=${DNS-}

header="#mac,ip,iface,speed_in,speed_out,in,out,total,first_date,last_date"

createDbIfMissing() {
	[ ! -f "$DB" ] && echo $header > "$DB"
	[ ! -f "$DB6" ] && echo $header > "$DB6"
}

checkDbArg() {
	[ -z "$DB" ] && echo "ERROR: Missing argument 2 (database file)" && exit 1
}

checkDB() {
	[ ! -f "$DB" ] && echo "ERROR: $DB does not exist" && exit 1
	[ ! -w "$DB" ] && echo "ERROR: $DB is not writable" && exit 1
	[ ! -f "$DB6" ] && echo "ERROR: $DB6 does not exist" && exit 1
	[ ! -w "$DB6" ] && echo "ERROR: $DB6 is not writable" && exit 1
}

checkWAN() {
	[ -z "$1" ] && echo "Warning: failed to detect WAN interface."
}

lookup() {
	local MAC=$1
	local IP=$2
	local userDB=$3
	local USERSFILE=
	local USER=
	for USERSFILE in $userDB /tmp/dhcp.leases /tmp/dnsmasq.conf /etc/dnsmasq.conf /etc/hosts; do
		[ -e "$USERSFILE" ] || continue

		case $USERSFILE in
			/tmp/dhcp.leases )
			USER=$(grep -i "$MAC" $USERSFILE | cut -f4 -s -d' ')
			;;
			/etc/hosts )
			USER=$(grep "^$IP " $USERSFILE | cut -f2 -s -d' ')
			;;
			* )
			USER=$(grep -i "$MAC" "$USERSFILE" | cut -f2 -s -d,)
			;;
		esac

		[ "$USER" = "*" ] && USER=
		[ -n "$USER" ] && break

	done

	if [ -n "$DO_RDNS" -a -z "$USER" -a "$IP" != "NA" -a -n "$nslookup" ]; then
		USER=$($nslookup $IP $DNS | awk '!/server can/{if($4){print $4; exit}}' | sed -re 's/[.]$//')
	fi

	[ -z "$USER" ] && USER=${MAC}
	echo $USER
}

detectIF() {
	local IF=
	if [ -f "$networkFuncs" ]; then
		IF=$(. $networkFuncs; network_get_device netdev $1; echo $netdev)
		[ -n "$IF" ] && echo $IF && return
	fi

	if [ -n "$uci" -a -x "$uci" ]; then
		IF=$($uci get network.${1}.ifname 2>/dev/null)
		[ $? -eq 0 -a -n "$IF" ] && echo $IF && return
	fi

	if [ -n "$nvram" -a -x "$nvram" ]; then
		IF=$($nvram get ${1}_ifname 2>/dev/null)
		[ $? -eq 0 -a -n "$IF" ] && echo $IF && return
	fi
}

detectLAN() {
	[ -e /sys/class/net/br-lan ] && echo br-lan && return
	local lan=$(detectIF lan)
	[ -n "$lan" ] && echo $lan && return
}

detectWAN() {
	local wan=$(detectIF wan)
	[ -n "$wan" ] && echo $wan && return
	wan=$(ip route show 2>/dev/null | grep default | sed -re '/^default/ s/default.*dev +([^ ]+).*/\1/')
	[ -n "$wan" ] && echo $wan && return
	[ -f "$networkFuncs" ] && wan=$(. $networkFuncs; network_find_wan wan; echo $wan)
	[ -n "$wan" ] && echo $wan && return
}

lockFunc() {
	#Realize the lock function by busybox lock or flock command.
	#	if !(lock -n $lockFile) >/dev/null 2>&1; then
	#		exit 1
	#	fi
	#The following lock method is realized by other's function.

	local attempts=0
	local flag=0

	while [ "$flag" = 0 ]; do
		local tempfile=$(mktemp $tmpDir/lock.XXXXXX)
		ln $tempfile $lockFile >/dev/null 2>&1 && flag=1
		rm $tempfile

		if [ "$flag" = 1 ]; then
			[ -n "$DEBUG" ] && echo ${updatePID} "got lock after $attempts attempts"
			flag=1
		else
			sleep 1
			attempts=$(($attempts+1))
			[ -n "$DEBUG" ] && echo ${updatePID} "The $attempts attempts."
			[ "$attempts" -ge 10 ] && exit
		fi
	done
}

unlockFunc() {
	#Realize the lock function by busybox lock or flock command.
	#	lock -u $lockFile
	#	rm -f $lockFile
	#	[ -n "$DEBUG" ] && echo ${updatePID} "released lock"
	#The following lock method is realized by other's function.

	rm -f $lockFile
	[ -n "$DEBUG" ] && echo ${updatePID} "released lock"
}

# chain
newChain() {
	local chain=$1
	local ipt=$2
	# Create the RRDIPT_$chain chain (it doesn't matter if it already exists).

	$ipt -t mangle -N RRDIPT_$chain 2> /dev/null

	# Add the RRDIPT_$chain CHAIN to the $chain chain if not present
	$ipt -t mangle -C $chain -j RRDIPT_$chain 2>/dev/null
	if [ $? -ne 0 ]; then
		[ -n "$DEBUG" ] && echo "DEBUG: $ipt chain misplaced, recreating it..."
		$ipt -t mangle -I $chain -j RRDIPT_$chain
	fi
}

# chain tun
newRuleIF() {
	local chain=$1
	local IF=$2
	local ipt=$3
	local cmd=

	if [ "$chain" = "OUTPUT" ]; then
		cmd="$ipt -t mangle -o $IF -j RETURN"
	elif [ "$chain" = "INPUT" ]; then
		cmd="$ipt -t mangle -i $IF -j RETURN"
	fi
	[ -n "$cmd" ] && eval $cmd " -C RRDIPT_$chain 2>/dev/null" || eval $cmd " -A RRDIPT_$chain"
}

publish() {
	# sort DB
	# busybox sort truncates numbers to 32 bits
	grep -v '^#' $DB | awk -F, '{OFS=","; a=sprintf("%f",$6/1e6); $6=""; print a,$0}' | tr -s ',' | sort -rn | awk -F, '{OFS=",";$1=sprintf("%f",$1*1e6);print}' > $tmpDir/sorted_${updatePID}.tmp

	# create HTML page
	local htmPage="$tmpDir/${pb_html##*/}"
	rm -f $htmPage
	cp $dataDir/usage.htm1 $htmPage

	while IFS=, read PEAKUSAGE_IN MAC IP IFACE SPEED_IN SPEED_OUT PEAKUSAGE_OUT TOTAL FIRSTSEEN LASTSEEN
	do
		echo "
new Array(\"$(lookup $MAC $IP $user_def)\",\"$MAC\",\"$IP\",$SPEED_IN,$SPEED_OUT,
$PEAKUSAGE_IN,$PEAKUSAGE_OUT,$TOTAL,\"$FIRSTSEEN\",\"$LASTSEEN\")," >> $htmPage
	done < $tmpDir/sorted_${updatePID}.tmp
	echo "0);" >> $htmPage

	sed "s/(date)/$(date)/" < $dataDir/usage.htm2 >> $htmPage
	mv $htmPage "$pb_html"
}

updatePrepare() {
	checkDbArg
	createDbIfMissing
	checkDB
	[ -e $tmpDir ] || mkdir -p  $tmpDir

	for46="$Monitor46"
	local timeNow=$(cat /proc/uptime | awk '{print $1}')

	if [ -e "$logFile" ]; then
		local timeLast4=$(awk -F'[: ]+' '/ipv4/{print $2}' "$logFile")
		local timeLast6=$(awk -F'[: ]+' '/ipv6/{print $2}' "$logFile")
		interval4=$(awk -v now=$timeNow -v last=$timeLast4 'BEGIN{print (now-last)}');
		interval6=$(awk -v now=$timeNow -v last=$timeLast6 'BEGIN{print (now-last)}');

		for ii in 4 6; do
			[[ -n "$(echo $for46 | grep ${ii})" ]] && {
				if [[ "$(eval echo \$interval${ii})" \> "0.9" ]]; then
					sed -i "s/^ipv${ii}: [0-9\.]\{1,\}/ipv${ii}: $timeNow/ig" "$logFile"
				else
					for46=$(echo "$for46" | sed "s/${ii}//g")
				fi
			}
		done
	else
		echo -e "ipv4: $timeNow\nipv6: $timeNow" >"$logFile"
	fi
	return 0
}

update() {
	updatePID=$( sh -c 'echo $PPID' )

	lockFunc

	local wan=$(detectWAN)
	checkWAN $wan
	interfaces="$interfaces $wan"

	[ "$for46" = 4 ] && IPT='iptables'
	[ "$for46" = 6 ] && IPT='ip6tables'
	[ "$for46" = 46 ] && IPT='iptables ip6tables'

	for ii in $IPT ; do
		if [ -z "$( ${ii}-save | grep RRDIPT )" ]; then

			for chain in $chains; do
				newChain $chain $ii
			done

			# track local data
			for chain in INPUT OUTPUT; do
				for interface in $interfaces; do
					[ -n "$interface" ] && [ -e "/sys/class/net/$interface" ] && newRuleIF $chain $interface $ii
				done
			done
		fi
		# this will add rules for hosts in arp table
		> $tmpDir/${ii}_${updatePID}.tmp

		for chain in $chains; do
			$ii -nvxL RRDIPT_$chain -t mangle -Z >> $tmpDir/${ii}_${updatePID}.tmp
		done
	done

	[ -f $tmpDir/iptables_${updatePID}.tmp ] && (
		awk -v mode="$mode" -v interfaces="$interfaces" -v wanIF="$wan" -v interval=$interval4 \
		-v ipv6="0" -f $binDir/readDB.awk \
		$DB \
		/proc/net/arp \
		$tmpDir/iptables_${updatePID}.tmp
	)

	[ -f $tmpDir/ip6tables_${updatePID}.tmp ] && (
		echo "This file is geneated by 'ip -6 neigh'" > $tmpDir/ip6addr_${updatePID}.tmp
		$(ip -6 neigh >> $tmpDir/ip6addr_${updatePID}.tmp);

		awk -v mode="$mode" -v interfaces="$interfaces" -v wanIF="$wan" -v interval=$interval6 \
		-v ipv6="1" -f $binDir/readDB.awk \
		"$DB6" \
		$tmpDir/ip6addr_${updatePID}.tmp \
		$tmpDir/ip6tables_${updatePID}.tmp
	)

	[ "$Monitor46" = 46 ] && (
		cp $DB $DB46
		cat $DB6 >> $DB46
		awk -f $binDir/readDB.awk "$DB46"
	)

	[ -n "$pb_html" ] && publish

	rm -f $tmpDir/*_${updatePID}.tmp
	unlockFunc
}

renamefile() {
	local base=$(basename -- "$1")
	local ext=$([ -z "${base/*.*/}"  ] && echo ".${base##*.}" || echo '')
	local base="${base%.*}"
	echo "$(dirname $1)/${base}$2$ext" && return
}

ending() {
	iptables-save | grep -v RRDIPT | iptables-restore
	ip6tables-save | grep -v RRDIPT | ip6tables-restore

	if checkPid $pidFile; then
		local pid=$( cat $pidFile )
		rm -rf $lockFile $logFile $pidFile $tmpDir/*
		kill -9 $pid >> /dev/null 2>&1
	fi
	echo "exit!!"
}

checkPid() {
	[ -e "$1" ] && local pid=$(cat $1) || return 1
	[ -d "/proc/$pid" ] && {
		[ -n "$( cat /proc/$pid/cmdline | grep wrtbwmon )" ] && return 0
	}
	return 1
}

sleepProcess() {
	sleep 1m
	kill -CONT $1 >>/dev/null 2>&1
}

loop() {
	trap 'ending' INT TERM HUP QUIT
	if checkPid $pidFile; then
		echo "Another wrtbwmon is on running!!!"
	else
		local loopPID=$( sh -c 'echo $PPID' )
		local SPID=
		echo $loopPID > $pidFile
		while true ;do
			[ -n "$SPID" ] && kill -9 $SPID >>/dev/null 2>&1
			sleepProcess $loopPID &
			SPID=$!
			updatePrepare && update
			kill -STOP $loopPID >>/dev/null 2>&1
		done
	fi
	trap INT TERM HUP QUIT
}

tips() {
	echo \
"Usage: $0 [options...]
Options:
   -k 			Exit the wrtbwmon!
   -f dbfile	Set the DB file path
   -u usrfile	Set the user_def file path
   -p htmlfile	Set the publish htm file path
   -d			Enter the foreground mode.
   -D			Enter the daemo mode.
   -4			Listen to ipv4 only.
   -6			Listen to ipv6 only.
   -46			Listen to ipv4 and ipv6.

Note: [user_file] is an optional file to match users with MAC addresses.
	   Its format is \"00:MA:CA:DD:RE:SS,username\", with one entry per line."
}

############################################################

while [ $# != 0 ];do
	case $1 in
		"-k" )
			/etc/init.d/wrtbwmon stop
			exit 0
		;;
		"-f" )
			shift
			if [ $# -gt 0 ];then
				DB=$1
				DB6="$(renamefile $DB .6)"
				DB46="$(renamefile $DB .46)"
			else
				echo "No db file path seted, exit!!"
				exit 1
			fi
		;;
		"-u")
			shift
			if [ $# -gt 0 ];then
				user_def=$1
			else
				echo "No user define file path seted, exit!!"
				exit 1
			fi
		;;

		"-p")
			shift
			if [ $# -gt 0 ];then
				pb_html=$1
			else
				echo "No publish html file path seted, exit!!"
				exit 1
			fi
		;;

		"-d")
			runMode=1
		;;

		"-D")
			runMode=2
		;;

		"-4")
			Monitor46=4
		;;

		"-6")
			Monitor46=6
		;;

		"-46")
			Monitor46=46
		;;

		"&&" | "||" | ";")
			break
		;;

		"*")
			tips
		;;
	esac

	shift
done

if [ "$runMode" = '1' ]; then
	loop
elif [ "$runMode" = '2' ]; then
	loop >>/dev/null 2>&1 &
else
	updatePrepare && update
fi
`)

// 网络下载
const DetectionDeviceScript = string(`
#!/bin/sh
mkdir -p /usr/share/hiui/rpc/
cat >/usr/share/hiui/rpc/device.lua <<EOF
#!/usr/bin/lua
local iwinfo = require "iwinfo"
local uci = require('uci').cursor()
IFACE_PATTERNS_WIRELESS = {
    "^wlan%d", "^wl%d", "^ath%d", "^%w+%.network%d", "^ra%d"
}
local function is_match_empty(pat, plain)
    return not not string.find('', pat, nil, plain)
end

local function split(str, sep, plain)
    local b, res = 0, {}
    sep = sep or '%s+'

    assert(type(sep) == 'string')
    assert(type(str) == 'string')

    if #sep == 0 then
        for i = 1, #str do res[#res + 1] = string.sub(str, i, i) end
        return res
    end

    assert(not is_match_empty(sep, plain),
           'delimiter can not match empty string')

    while b <= #str do
        local e, e2 = string.find(str, sep, b, plain)
        if e then
            res[#res + 1] = string.sub(str, b, e - 1)
            b = e2 + 1
            if b > #str then res[#res + 1] = "" end
        else
            res[#res + 1] = string.sub(str, b)
            break
        end
    end
    return res
end

local mac = string.upper(arg[1])
local ip = arg[2]
local con_type
local online = 1
if arg[3] == "0x4" then
    con_type = "Wired"
elseif arg[3] == "0x2" then
    online = 1
elseif arg[3] == "0x0" then
    online = 0
end
local name
if arg[4] then
    name = string.gsub(arg[4], '%s+', '')
else
    name = 'unknown'
end

local function _wifi_iface(x)
    for _, p in ipairs(IFACE_PATTERNS_WIRELESS) do
        if x:match(p) then return true end
    end
    return false
end

local function conType(_mac, preType)
    local device = preType
    local ssid;
    if not con_type then
        fs=io.popen("ls /sys/class/net/")
        if fs then
            local _tmp=fs:read("*a")
            local ifaces=_tmp.split(_tmp)
            fs:close()
            for k,x in pairs(ifaces) do
                if _wifi_iface(x) then
                    local driver_type = iwinfo.type(x)
                    local assoclist = iwinfo[driver_type]["assoclist"](x)
                    if driver_type and assoclist then
                        for key, value in pairs(assoclist) do
                            if key == _mac then
                                ssid = iwinfo[driver_type].ssid(x)
                                break
                            end
                        end
                    end
                end
                if ssid then break end
            end            
        end

        if ssid then
            uci:foreach("wireless", "wifi-iface", function(s)
                if s.ssid == ssid then
                    device = s[".name"]
                end
            end)
        end
    end
    return device
end

local function updateDatas()
    local hasMac = false
    for line in io.lines("/etc/clients", "r") do
        if string.len(line) > 10 then
            local client = split(line, '%s+', false)
            if string.find(line, mac) then
                client[1] = mac
                client[2] = ip
                if name ~= client[3] then
                    client[3] = name
                end
                client[4] = conType(mac, client[4])
                client[5] = online
                if client[1] and client[11] then
                    hasMac = true
                    local res = string.format(
                        "%s %s %s %s %s %s %s %s %s %s %s\n",
                        client[1], client[2], client[3], client[4],
                        client[5], client[6], client[7], client[8],
                        client[9], client[10], client[11])
                    local cmd = string.format("sed -i '/%s/c %s' /etc/clients",
                        mac, res)
                    os.execute(cmd)
                    return
                else
                    local cmd = string.format("sed -i '/%s/d' /etc/clients", mac)
                    os.execute(cmd)
                end
            end
        end
    end

    if not hasMac then
        local _conType = conType(mac, "Wired")
        os.execute(string.format(
            "echo '%s %s %s %s 1 0 0 0 0 0 0' >>/etc/clients", mac,
            ip, name, _conType))
    end
end
updateDatas()
EOF

cat >/usr/share/hiui/rpc/clients.lua <<EOF
local M = {}
local json = require 'cjson'
local uci = require 'uci'
local function is_match_empty(pat, plain)
    return not not string.find('', pat, nil, plain)
end
local function split(str, sep, plain)
    local b, res = 0, {}
    sep = sep or '%s+'
    assert(type(sep) == 'string')
    assert(type(str) == 'string')
    if #sep == 0 then
        for i = 1, #str do res[#res + 1] = string.sub(str, i, i) end
        return res
    end
    assert(not is_match_empty(sep, plain),
           'delimiter can not match empty string')
    while b <= #str do
        local e, e2 = string.find(str, sep, b, plain)
        if e then
            res[#res + 1] = string.sub(str, b, e - 1)
            b = e2 + 1
            if b > #str then res[#res + 1] = "" end
        else
            res[#res + 1] = string.sub(str, b)
            break
        end
    end
    return res
end
local function stringToBoolean(param, s)
    if param == s then
        return true
    else
        return false
    end
end
function M.getClients()
    local c = uci.cursor()
    local lines = io.lines("/etc/clients", "r")
    if lines then
        local clients = {}
        for line in lines do
            local item = {}
            local tmp = split(line, '%s+', false)
            if #tmp == 11 then
                item.mac = tmp[1]
                item.ip = tmp[2]
                local _ip = string.match(item.ip, "%d+.%d+.%d+")
                local hasSeg = false
                c:foreach("network", "interface", function(ob)
                    local curSegment
                    if ob.ipaddr then
                        curSegment = string.match(ob.ipaddr, "%d+.%d+.%d+")
                    end
                    if curSegment == _ip then
                        hasSeg = true
                        return
                    end
                end)
                if hasSeg then
                    item.name = tmp[3]
                    item.iface = tmp[4]
                    item.online = stringToBoolean(tmp[5], '1')
                    item.alive = tmp[6]
                    item.blocked = stringToBoolean(tmp[7], '1')
                    item.up = tmp[8]
                    item.down = tmp[9]
                    item.total_up = tmp[10]
                    item.total_down = tmp[11]
                    item.bind = false
                    c:foreach('dhcp', 'host', function(s)
                        if s.mac == item.mac then
                            item.bind = true
                            return
                        end
                    end)
                    table.insert(clients, item)
                end
            end
        end
        return { code = 0, clients = clients }
    else
        return { code = 404 }
    end
end
return M
EOF

cat >/usr/sbin/block-and-qos.sh <<EOF
#!/bin/sh
function addBlockList() {
    local has=\$(ipset list | grep block_device)
    if [ -z "\$has" ]; then
        ipset create block_device hash:mac maxelem 10000
    fi
    [ -z "\$(iptables -S FORWARD | grep block_device)" ] && iptables -I FORWARD -m set --match-set block_device src -j DROP
    awk '\$7==1 {print \$1}' /etc/clients | while read mac; do
        ipset add block_device \$mac
    done

}
case \$1 in
'addBlockList')
    addBlockList
    ;;
*) ;;
esac
EOF

cat >/usr/sbin/detection.sh <<EOF
#!/bin/sh
pidFile=/var/run/detection.pid
function online {
    cp /etc/clients /tmp/clients_bak
    local traffic=\$(uci get hiui.global.traffic)
    if [ "\$traffic" == "1" ]; then
        wrtbwmon -4 -f /tmp/usage.db
        awk '{print \$1,\$2}' /tmp/clients_bak | while read line ip; do
            local online=\$(awk '\$4==tolower("'\$line'") {if ( \$3=="0x2" ) print 1;else print 0;}' /proc/net/arp)
            [ -z "\$online" ] && online=0
            awk -F',' '\$1==tolower("'\$line'") {print \$1,\$4,\$5,\$6,\$7,\$10}' /tmp/usage.db | while read mac down up total_down total_up last_time; do
                if [ -n "\$mac" ] && [ -n "\$last_time" ]; then
                    res=\$(awk '\$1=="'\$line'" {sub(/[0-1]/,"'\$online'",\$5);sub(/[0-9]+/,"'\$last_time'",\$6);sub(/[0-9]+/,"'\$up'",\$8);sub(/[0-9]+/,"'\$down'",\$9);sub(/[0-9]+/,"'\$total_up'",\$10);sub(/[0-9]+/,"'\$total_down'",\$11);print}' /tmp/clients_bak)
                    if [ -n "\$res" ]; then
                        sed -i "/\$line/c \$res" /tmp/clients_bak
                    fi
                fi
            done
            res=\$(awk '\$1=="'\$line'" {sub(/[0-1]/,"'\$online'",\$5);print}' /tmp/clients_bak)
            if [ -n "\$res" ]; then
                sed -i "/\$line/c \$res" /tmp/clients_bak
            fi
        done
    else
        awk '{print \$1,\$2}' /tmp/clients_bak | while read mac ip; do
            local online=\$(awk '\$4==tolower("'\$mac'") {if ( \$3=="0x2" ) print 1;else print 0;}' /proc/net/arp)
            [ -z "\$online" ] && online=0
            res=\$(awk '\$1=="'\$mac'" {sub(/[0-1]/,"'\$online'",\$5);print}' /tmp/clients_bak)
            if [ -n "\$res" ]; then
                sed -i "/\$mac/c \$res" /tmp/clients_bak
            fi
        done
    fi
    awk '!x[\$1]++' /tmp/clients_bak >/etc/clients
}
sbNum=0
function sb() {
    if [ "\$(cat /var/run/rtty)" == "Connected" ]; then
        rm -f /mnt/rtty_reboot
        return
    fi
    if [ "\$(cat /var/run/rtty)" != "Connected" ] && [ "\$(cat /mnt/rtty_reboot)" != "reboot" ]; then
        sbNum=\$((sbNum + 1))
        echo \$sbNum >/mnt/rtty_reboot
        /etc/init.d/rtty restart
    fi
    if [ "\$(cat /mnt/rtty_reboot)" == "6" ]; then
        echo "reboot" >/mnt/rtty_reboot
        reboot
    fi
    if [ "\$(cat /mnt/rtty_reboot)" == "reboot" ]; then
        local host=\$(awk '\$2=="#hi-th-api#" {print \$1}' /etc/dnsmasq.conf | awk -F'/' '{print \$2}')
        tmp='{"content":"","sn":"'\$(uci get rtty.general.id)'","time":"'\$(date +%s)'"}'
        curl -4 -X POST "https://\$host/hi/base/report/rtty_error" -H "Content-Type: application/json" -d \$tmp
        [ "\$?" != "0" ] && lua /mnt/curl.lua "https://\$host/hi/base/report/rtty_error" "POST" \$tmp
    fi
}
function checkRtty() {
    num=0
    if [ -z "$(ps | grep 'rtty' | grep -v 'grep')" ]; then
        checkNum=\$((checkNum + 1))
        if [ \$checkNum -gt 2 ]; then
            /etc/init.d/rtty restart
            checkNum=0
        fi
    fi
}
sleepProcess() {
    sleep 20
    kill -CONT \$1 >>/dev/null 2>&1
}
num=0
checkNum=0
loop() {
    local loopPID=\$(sh -c 'echo \$PPID')
    local SPID=
    echo \$loopPID >\$pidFile
    while true; do
        [ -n "\$SPID" ] && kill -9 \$SPID >>/dev/null 2>&1
        sleepProcess \$loopPID &
        SPID=\$!
        online
        num=\$((num + 1))
        if [ \$num -ge 3 ]; then
            checkRtty
            sb            
        fi
        kill -STOP \$loopPID >>/dev/null 2>&1
    done
}
loop
EOF

cat >/etc/init.d/detection <<EOF
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1
args=/usr/sbin/detection.sh

start_service() {
    procd_open_instance
    procd_set_param command \$args
    procd_set_param respawn
    procd_close_instance
}

EOF

cat >/etc/hotplug.d/dhcp/20-det-clients <<EOF
#!/bin/sh
[ ! -e '/etc/clients' ] && touch /etc/clients
[ "\$ACTION" = "update" -o "\$ACTION" = "add" ] && {
    if [ "\$(awk '\$1<20 {print 0}' /proc/uptime)" == "0" ]; then
        flock -x /tmp/det-clients.lock -c "lua /usr/share/hiui/rpc/device.lua \$MACADDR \$IPADDR 0x4 \$HOSTNAME"
    else
        flock -x /tmp/det-clients.lock -c "lua /usr/share/hiui/rpc/device.lua \$MACADDR \$IPADDR 0x2 \$HOSTNAME"
    fi
}
EOF

[ -d /etc/hotplug.d/firewall ] || mkdir /etc/hotplug.d/firewall
cat >/etc/hotplug.d/firewall/80-add-block <<EOF
#!/bin/sh
[[ -e '/tmp/add-block.lock' && \$ACTION == 'add' ]] && exit 0

if [ \$ACTION == 'add' ]; then
    flock -xn /tmp/add-block.lock -c "block-and-qos.sh addBlockList"
fi
EOF

chmod +x /etc/hotplug.d/dhcp/20-det-clients
chmod +x /etc/hotplug.d/firewall/80-add-block
chmod +x /usr/sbin/detection.sh
chmod +x /usr/sbin/block-and-qos.sh
chmod +x /etc/init.d/detection

/etc/init.d/detection start

`)

// 网络下载
const WireguardScript = string(`#!/bin/sh  /etc/rc.common

. /lib/functions.sh
. /lib/functions/network.sh

START=99
#USE_PROCD=1
#PROC="/usr/bin/wg"
WFILE="/var/etc/wireguard.conf"
AllowIPV4=""
AllowIPV6=""
EXTRA_COMMANDS=downup
model="${board_name#*-}"
guest_exist=""
openwrt_version=$(cat /etc/os-release | grep "VERSION_ID=" | cut -d '"' -f 2)
proxy_func() {
    config_get main_server $1 "main_server"
    config_get enable $1 "enable"
}
servers_func() {
    config_get enable $1 "enable"
}
peers_func() {
    local name
    local private_key
    local public_key
    local preshared_key
    local allowed_ips
    local persistent_keepalive
    local dns
    local dns_ipv4
    local dns_ipv6
    local eport
    local ipv6
    config_get name $1 "name"
    if [ "$name" != "" -a "$name" != "$main_server" ]; then
        continue
    else
        existflag=1
    fi
    config_get address $1 "address"
    config_get listen_port $1 "listen_port"
    config_get private_key $1 "private_key"
    config_get dns $1 "dns"
    config_get end_point $1 "end_point"
    config_get public_key $1 "public_key"
    config_get preshared_key $1 "preshared_key"
    config_get allowed_ips $1 "allowed_ips"
    config_get persistent_keepalive $1 "persistent_keepalive"
    config_get mtu $1 "mtu"
    config_get masq $1 "masq"
    if [ "$masq" == "" ]; then
        # Default is enabled
        masq=1
    fi
    [ -z "$listen_port" ] && return
    echo -e "ListenPort = $listen_port" >>"$WFILE"
    if [ "$private_key" != "" ]; then
        echo -e "PrivateKey = $private_key\n" >>"$WFILE"
    fi
    echo -e "[Peer]" >>"$WFILE"
    [ -n "$public_key" ] && echo -e "PublicKey = $public_key" >>"$WFILE"
    [ -n "$preshared_key" ] && echo -e "PresharedKey = $preshared_key" >>"$WFILE"
    [ -n "$allowed_ips" ] && echo -e "AllowedIPs = $allowed_ips" >>"$WFILE"
    AllowIPV4=$(echo $allowed_ips | cut -d ',' -f 1)
    AllowIPV6=$(echo $allowed_ips | cut -d ',' -f 2)
    if [ "$persistent_keepalive" == "" ]; then
        echo -e "PersistentKeepalive = 25" >>"$WFILE"
    else
        echo -e "PersistentKeepalive = $persistent_keepalive" >>"$WFILE"
    fi
    publicip=$(echo $end_point | cut -d ":" -f1)
    eport=$(echo $end_point | cut -d ":" -f2)
    if [ "$publicip" != "" ]; then
        ip=$(resolveip $publicip | egrep '[0-9]{1,3}(\.[0-9]{1,3}){3}' | grep -v "127.0.0.1" | grep -v "::" | head -n 1)
        if [ "$ip" = "" ]; then
            ip=$(nslookup $publicip 2>/dev/null | grep -v "127.0.0.1" | grep "::" | awk '/Address/ {print $3}')
        fi
        oldhost=$(uci get wireguard.@proxy[0].host)
        if [ "$ip" != "" ]; then
            echo -e "Endpoint = $ip:$eport" >>"$WFILE"
        elif [ -n "$oldhost" ]; then
            echo -e "Endpoint = $oldhost:$eport" >>"$WFILE"
        else
            echo -e "Endpoint = $end_point" >>"$WFILE"
        fi
        if [ "$ip" != "" -a "$oldhost" != "$ip" ]; then
            uci set wireguard.@proxy[0].host="$ip"
            uci commit wireguard
        fi
    fi
    if [ "$dns" != "" ]; then
        rm /tmp/resolv.conf.vpn 2>/dev/null
        for each_dns in $(echo $dns | sed 's/,/ /g'); do
            echo "nameserver $each_dns" >>/tmp/resolv.conf.vpn
        done
        uci set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.vpn'
        uci commit dhcp
        /etc/init.d/dnsmasq restart
    else
        echo -e "nameserver 8.8.8.8\nnameserver 4.4.4.4" >/tmp/resolv.conf.vpn
        uci set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.vpn'
        uci commit dhcp
        /etc/init.d/dnsmasq restart
    fi
}
get_localip_func() {
    local name
    config_get name $1 "name"
    if [ "$name" != "" -a "$name" != "$main_server" ]; then
        continue
    fi
    config_get address $1 "address"
    config_get dns $1 "dns"
    config_get end_point $1 "end_point"
    config_get AllowIP $1 "allowed_ips"
    AllowIPV4=$(echo $AllowIP | cut -d ',' -f 1)
    AllowIPV6=$(echo $AllowIP | cut -d ',' -f 2)
}
lan2wan_forwarding() {
    local src
    local dest
    local action="$1"
    local sections=$(uci show firewall | sed -n 's/\(.*\)=forwarding/\1/p')
    [ -n "$sections" ] || return 1
    for section in $sections; do
        src=$(uci get $section.src)
        dest=$(uci get $section.dest)
        if [ -n "$guest_exist" ]; then
            if [ "$src" = "guestzone" -a "$dest" = "wan" ]; then
                if [ "$action" = "enable" ]; then
                    uci set $section.enabled="1"
                elif [ "$action" = "disable" ]; then
                    [ -z "$AllowIPV4" -o "$AllowIPV4" = "0.0.0.0/0" ] && [ -z "$AllowIPV6" -o "$AllowIPV6" = "::/0" ] && uci set $section.enabled="0"
                else
                    echo "Please add options: enable|disable"
                fi
            fi
        fi
        [ -n "$src" -a "$src" = "lan" -a -n "$dest" -a "$dest" = "wan" ] || continue
        if [ "$action" = "enable" ]; then
            uci set $section.enabled="1"
        elif [ "$action" = "disable" ]; then
            [ -z "$AllowIPV4" -o "$AllowIPV4" = "0.0.0.0/0" ] && [ -z "$AllowIPV6" -o "$AllowIPV6" = "::/0" ] && uci set $section.enabled="0"
        else
            echo "Please add options: enable|disable"
        fi
    done
}
wireguard_add_firewall() {
    local access=$(uci get wireguard.@proxy[0].access)
    uci set firewall.AllowWireguard='rule'
    uci set firewall.AllowWireguard.name='Allow-Wireguard'
    uci set firewall.AllowWireguard.target='ACCEPT'
    uci set firewall.AllowWireguard.src='wan'
    uci set firewall.AllowWireguard.proto='udp tcp'
    uci set firewall.AllowWireguard.family='ipv4'
    uci set firewall.AllowWireguard.dest_port="$listen_port"
    uci set firewall.wireguard='zone'
    uci set firewall.wireguard.name='wireguard'
    uci set firewall.wireguard.input=$access
    uci set firewall.wireguard.forward='DROP'
    uci set firewall.wireguard.output='ACCEPT'
    uci set firewall.wireguard.masq="$masq"
    uci set firewall.wireguard.mtu_fix='1'
    uci set firewall.wireguard.device='wg0'
    uci set firewall.wireguard.masq6='1'
    uci set firewall.wireguard_wan='forwarding'
    uci set firewall.wireguard_wan.src='wireguard'
    uci set firewall.wireguard_wan.dest='wan'
    uci set firewall.wireguard_lan='forwarding'
    uci set firewall.wireguard_lan.src='wireguard'
    uci set firewall.wireguard_lan.dest='lan'
    [ "$access" != "ACCEPT" ] && {
        uci set firewall.wireguard_lan.enabled='0'
    }
    uci set firewall.lan_wireguard='forwarding'
    uci set firewall.lan_wireguard.src='lan'
    uci set firewall.lan_wireguard.dest='wireguard'
    if [ -n "$guest_exist" ]; then
        uci set firewall.guest_wireguard='forwarding'
        uci set firewall.guest_wireguard.src='guestzone'
        uci set firewall.guest_wireguard.dest='wireguard'
        uci set firewall.wireguard_guest='forwarding'
        uci set firewall.wireguard_guest.src='wireguard'
        uci set firewall.wireguard_guest.dest='guestzone'
    fi
    uci commit firewall
    /etc/init.d/firewall reload
}
wireguard_delete_firewall() {
    uci delete firewall.AllowWireguard
    uci delete firewall.wireguard
    uci delete firewall.wireguard_wan
    uci delete firewall.wireguard_lan
    uci delete firewall.lan_wireguard
    if [ -n "$guest_exist" ]; then
        uci delete firewall.guest_wireguard
        uci delete firewall.wireguard_guest
    fi
    uci commit firewall
    /etc/init.d/firewall reload
}
init_config() {
    local main_server
    local enable
    rm -rf "$WFILE"
    config_load wireguard
    config_foreach proxy_func proxy
    if [ "$enable" == "1" -a "$main_server" != "" ]; then
        ip link del dev wg0 1>/dev/null 2>&1 || true
        echo "[Interface]" >"$WFILE"
        config_foreach peers_func peers
    else
        rm /var/run/hiwg.lock -rf
        exit 1
    fi
}
get_wan_nomwan3_info() {
    local tmpiface
    network_find_wan tmpiface
    network_get_gateway gw $tmpiface
    network_get_device interface $tmpiface
}
get_wan_iface_and_gateway() {
    iface=$(cat /var/run/mwan3/indicator 2>/dev/null || echo "unknown")
    [ "$iface" != "unknown" ] && {
        interface=$(ifstatus $iface | jsonfilter -e @.l3_device) #get ifanme
        proto=$(ifstatus $iface | jsonfilter -e @.proto)
        result=$(echo $iface | grep "modem")
        if [ "$result" != "" -a "$proto" = "qmi" ]; then
            gw=$(ifstatus ${iface}_4 | jsonfilter -e @.route[0].nexthop) #get gateway
        else
            gw=$(ifstatus $iface | jsonfilter -e @.route[0].nexthop)
        fi
    }
    [ "$iface" = "unknown" ] && {
        get_wan_nomwan3_info
    }
}
start() {
    logger -t wireguard "wireguard client start"
    while [ 1 ]; do
        [ ! -f /var/run/hiwg.lock ] && break
        sleep 1
    done
    touch /var/run/hiwg.lock
    local address
    local address_ipv4
    local address_ipv6
    local listen_port
    local end_point
    local gw
    local interface
    local masq
    local mtu
    local existflag=0
    local ipv6
    init_config
    [ "$existflag" = 0 ] && {
        rm /var/run/hiwg.lock -rf
        exit 1
    }
    local interface=$(uci -q get system.@led[1].dev)
    [ "$model" = "mv1000" ] && [ "$interface" != "wg0" ] && {
        uci set system.@led[1].dev='wg0'
        uci commit system
        sleep 1
        /etc/init.d/system restart >>/dev/null
        /etc/init.d/led restart >>/dev/null
    }
    get_wan_iface_and_gateway
    lan2wan_forwarding disable
    wireguard_add_firewall
    ip link add dev wg0 type wireguard
    ip addr add "$address" dev wg0
    ip link set up dev wg0
    if [ "$mtu" != "" ]; then
        ip link set mtu "$mtu" wg0
    fi
    timeout 5 pwd 1>/dev/null 2>&1
    if [ "$?" = "0" ]; then
        timeout 5 wg setconf wg0 $WFILE
    else
        timeout -t 5 wg setconf wg0 $WFILE
    fi
    runflag=$(echo $?)
    if [ "$runflag" != 0 ]; then
        ip link del wg0
        [ -f "/tmp/resolv.conf.vpn" ] && {
            rm -rf /tmp/resolv.conf.vpn
            uci del dhcp.@dnsmasq[0].resolvfile
            uci commit dhcp
            /etc/init.d/dnsmasq restart
        }
        rm -rf $WFILE
        echo f >/proc/net/nf_conntrack
        rm /var/run/hiwg.lock -rf
        if [ "$model" = "mv1000" ]; then
            /etc/init.d/network restart &
        fi
        exit 1
    fi
    publicip=$(echo $end_point | cut -d ":" -f1)
    rpublicip=$(echo $publicip | grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}")
    if [ "$rpublicip" != "" ]; then
        if [ "$publicip" != "$gw" ]; then
            ip route add $publicip via $gw dev $interface 1>/dev/null 2>&1
        fi
    else
        if [ "$publicip" != "$gw" ]; then
            route add $publicip gw $gw dev $interface 1>/dev/null 2>&1
        fi
    fi
    if [ -n "$AllowIPV4" -a "$AllowIPV4" != "0.0.0.0/0" ]; then
        ip route add "$AllowIPV4" dev wg0
    else
        ip route add 0/1 dev wg0
        ip route add 128/1 dev wg0
    fi
    echo f >/proc/net/nf_conntrack
    env -i ACTION="ifup" INTERFACE="wg" DEVICE="wg0" /sbin/hotplug-call iface
    if [ "$model" = "mv1000" ]; then
        sync
        sleep 5
        /etc/init.d/network restart &
    fi
    local DDNS=$(iptables -nL -t mangle | grep WG_DDNS)
    local lanip=$(uci get network.lan.ipaddr)
    local gateway=${lanip%.*}.0/24
    if [ -z "$DDNS" ]; then
        iptables -t mangle -N WG_DDNS
        iptables -A WG_DDNS -t mangle -i br-lan -s $gateway -d $publicip -j MARK --set-mark 0x60000
        iptables -t mangle -I PREROUTING -j WG_DDNS
        ip rule add fwmark 0x60000/0x60000 lookup 31 pref 31
        ip route add $publicip dev wg0 table 31
    fi

    : <<EOF
        policy=$(uci get glconfig.route_policy.enable)
        if [ "$policy" != "1" ];then
                logger -t wireguard "start setting local policy"
                if [ "$ipv6" != "" ];then
                        local_ip=$(echo "$address_ipv4" | grep -m 1 -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
                else
                        local_ip=$(echo "$address" | grep -m 1 -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
                fi
                if [ -n "$local_ip" ];then
                        ip rule add from $local_ip lookup 53 pref 53
                        route="$(ip route)"
                        IFS_sav=$IFS
                        IFS=$'\n\n'
                        for line in $route
                        do
                        IFS=$IFS_sav
                        if [ ! -n "$(echo "$line" | grep -w -e tun0 -e wg0)" ];then
                                ip route add $line table 53
                        fi
                        IFS=$'\n\n'
                        done
                        IFS=$IFS_sav
                        vpn_dns=$(cat /tmp/resolv.conf.vpn | grep -m 1 -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
                        ip route add $vpn_dns dev wg0 table 53
                fi
                logger -t wireguard "start changing dns resolve"
        fi
EOF
    logger -t wiregaurd "client start completed, del hiwg.lock"
    rm /var/run/hiwg.lock -rf
}
stop() {
    logger -t wireguard "wireguard client stop"
    while [ 1 ]; do
        [ ! -f /var/run/hiwg.lock ] && break
        sleep 1
    done
    touch /var/run/hiwg.lock
    local main_server
    local enable
    local address
    local dns
    local end_point
    local gw
    local interface
    config_load wireguard_server
    config_foreach servers_func servers
    if [ "$enable" == "1" ]; then
        rm /var/run/hiwg.lock -rf
        exit 1
    fi
    config_load wireguard
    config_foreach proxy_func proxy
    config_foreach get_localip_func peers
    get_wan_iface_and_gateway
    if [ -n "$AllowIPV4" -a "$AllowIPV4" != "0.0.0.0/0" ]; then
        ip route del "$AllowIPV4" dev wg0
    else
        ip route del 0/1 dev wg0
        ip route del 128/1 dev wg0
    fi
    host=$(uci get wireguard.@proxy[0].host)
    if [ "$host" != "" ]; then
        ip route del $host 1>/dev/null 2>&1
    else
        publicip=$(echo $end_point | cut -d ":" -f1)
        ip=$(resolveip $publicip | egrep '[0-9]{1,3}(\.[0-9]{1,3}){3}' | grep -v "127.0.0.1" | grep -v "::" | head -n 1)
        if [ "$ip" = "" ]; then
            ip=$(nslookup $publicip 2>/dev/null | grep -v "127.0.0.1" | grep "::" | awk '/Address/ {print $3}')
        fi
        if [ "$ip" != "" ]; then
            ip route del $ip 1>/dev/null 2>&1
        fi
    fi
    [ -f "/tmp/resolv.conf.vpn" ] && {
        rm -rf /tmp/resolv.conf.vpn
        uci del dhcp.@dnsmasq[0].resolvfile
        uci commit dhcp
        /etc/init.d/dnsmasq restart
    }
    lan2wan_forwarding enable
    wireguard_delete_firewall
    ip link del dev wg0 1>/dev/null 2>&1
    rm $WFILE -rf
    echo f >/proc/net/nf_conntrack
    env -i ACTION="ifdown" INTERFACE="wg" /sbin/hotplug-call iface
    if [ "$model" = "mv1000" ]; then
        sync
    fi
    local DDNS=$(iptables -nL -t mangle | grep WG_DDNS)
    if [ -n "$DDNS" ]; then
        ip rule del fwmark 0x60000/0x60000 lookup 31 pref 31
        iptables -t mangle -D PREROUTING -j WG_DDNS
        iptables -t mangle -F WG_DDNS
        iptables -t mangle -X WG_DDNS
    fi
    : <<EOF
        ip route flush table 53
        ip rule del table 53
        rm /etc/resolv.conf
        ln -s /tmp/resolv.conf /etc/resolv.conf
EOF
    condition_enable_flow_offload
    logger -t wiregaurd "client stop completed, del hiwg.lock"
    rm /var/run/hiwg.lock -rf
}
downup() {
    while [ 1 ]; do
        [ ! -f /var/run/hiwg.lock ] && break
        sleep 1
    done
    touch /var/run/hiwg.lock
    local address
    local listen_port
    local end_point
    local gw
    local interface
    local masq
    local mtu
    local existflag=0
    local model="${board_name#*-}"
    init_config
    [ "$existflag" = 0 ] && {
        rm /var/run/hiwg.lock -rf
        exit 1
    }
    get_wan_iface_and_gateway
    ip link add dev wg0 type wireguard
    ip addr add "$address" dev wg0
    ip link set up dev wg0
    if [ "$mtu" != "" ]; then
        ip link set mtu "$mtu" wg0
    fi
    timeout 5 pwd 1>/dev/null 2>&1
    if [ "$?" = "0" ]; then
        timeout 5 wg setconf wg0 $WFILE
    else
        timeout -t 5 wg setconf wg0 $WFILE
    fi
    runflag=$(echo $?)
    if [ "$runflag" != 0 ]; then
        ip link del wg0
        [ -f "/tmp/resolv.conf.vpn" ] && {
            rm -rf /tmp/resolv.conf.vpn
            uci del dhcp.@dnsmasq[0].resolvfile
            uci commit dhcp
            /etc/init.d/dnsmasq restart
        }
        rm -rf $WFILE
        echo f >/proc/net/nf_conntrack
        rm /var/run/hiwg.lock -rf
        if [ "$model" = "mv1000" ]; then
            /etc/init.d/network restart &
        fi
        exit 1
    fi
    publicip=$(echo $end_point | cut -d ":" -f1)
    rpublicip=$(echo $publicip | grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}")
    if [ "$rpublicip" != "" ]; then
        if [ "$publicip" != "$gw" ]; then
            ip route add $publicip via $gw dev $interface 1>/dev/null 2>&1
        fi
    else
        if [ "$publicip" != "$gw" ]; then
            route add $publicip gw $gw dev $interface 1>/dev/null 2>&1
        fi
    fi
    if [ -n "$AllowIPV4" -a "$AllowIPV4" != "0.0.0.0/0" ]; then
        ip route add "$AllowIPV4" dev wg0
    else
        ip route add 0/1 dev wg0
        ip route add 128/1 dev wg0
    fi
    echo f >/proc/net/nf_conntrack
    env -i ACTION="ifup" INTERFACE="wg" DEVICE="wg0" /sbin/hotplug-call iface
    rm /var/run/hiwg.lock -rf
    if [ "$model" = "mv1000" ]; then
        sync
        sleep 5
        /etc/init.d/network restart &
    fi
    local DDNS=$(iptables -nL -t mangle | grep WG_DDNS)
    local lanip=$(uci get network.lan.ipaddr)
    local gateway=${lanip%.*}.0/24
    if [ -n "$DDNS" ]; then
        ip rule del fwmark 0x60000/0x60000 lookup 31 pref 31
        iptables -t mangle -D PREROUTING -j WG_DDNS
        iptables -t mangle -F WG_DDNS
        iptables -t mangle -X WG_DDNS
    fi
    iptables -t mangle -N WG_DDNS
    iptables -A WG_DDNS -t mangle -i br-lan -s $gateway -d $publicip -j MARK --set-mark 0x60000
    iptables -t mangle -I PREROUTING -j WG_DDNS
    ip rule add fwmark 0x60000/0x60000 lookup 31 pref 31
    ip route add $publicip dev wg0 table 31
}
`)

const CommonUtilsContent = string(`
#!/bin/bash

_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}

_base64d() {
    echo -n "$1" | base64 -d | sed 's/\\n//g'
}

_random() {
    echo -n $(date +%s) | md5sum | md5sum | cut -d ' ' -f 1
}

_filemd5() {
    if [ -f "$1" ]; then
        echo -n $(md5sum $1 | cut -d ' ' -f1)
    else
        echo ""
    fi
}

_sign() {
	secretKey=$(uci get rtty.general.token)
	nonce=$(echo -n $(date +%s) | md5sum | md5sum | cut -d ' ' -f 1)
	ts=$(date +%s)
	append="nonce=${nonce}&ts=${ts}&ver=1.0"
	sign=$(echo -n "${append}${secretKey}" | md5sum  | cut -d ' ' -f 1)
	queries="?${append}&sign=${sign}"
	echo -n $queries
}
`)

// 网络下载
const ShuntDomainPartial = string(`
for D in $(cat ${DOMAINFILE} 2>/dev/null); do
    echo "server=/${D}/{{.dnsIp}} #{{.th}}#" >> /etc/dnsmasq.conf
    #
    charA="$(cat $DNSFILE | grep -n "ipset=/${D}/")"
    if [ -n "$charA" ]; then
        charB="$(echo "$charA" | grep -E "(/|,){{.th}}(,|$)")"
        if [ -z "$charB" ]; then
            charC="$(echo "$charA" | awk -F ":" '{print $1}')"
            charD="$(echo "$charA" | awk -F ":" '{print $2}')"
            sed -i "${charC}d" $DNSFILE
            echo "${charD},{{.th}}" >> $DNSFILE
        fi
    else
        echo "ipset=/${D}/{{.th}}" >> $DNSFILE
    fi
done
/etc/init.d/dnsmasq restart
for D in $(cat ${DOMAINFILE} 2>/dev/null); do (nslookup $D > /dev/null 2>&1 &); done
`)

// 网络下载
const ShuntContent = string(`
#!/bin/bash
ACTION=$1
DNSFILE="/etc/dnsmasq.d/domain_hicloud.conf"
LOGFILE="/tmp/hicloud/shunt/{{.th}}.log"
DOMAINFILE="/tmp/hicloud/shunt/{{.th}}.domain"

echo "start: $(date "+%Y-%m-%d %H:%M:%S")" > ${LOGFILE}

mkdir -p /etc/dnsmasq.d
mkdir -p /tmp/hicloud/shunt

if [ -z "$(cat /etc/dnsmasq.conf | grep conf-dir=/etc/dnsmasq.d)" ]; then
    sed -i /conf-dir=/d /etc/dnsmasq.conf
    echo conf-dir=/etc/dnsmasq.d >> /etc/dnsmasq.conf
fi

if [ ! -f "$DNSFILE" ]; then
    touch $DNSFILE
fi

gatewayIP=$(ip route show 1/0 | head -n1 | sed -e 's/^default//' | awk '{print $2}' | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print $1"."$2"."$3"."$4}')
if [ -z "${gatewayIP}" ]; then
    echo "Unable to get gateway IP"
    exit 1
fi
gatewayCIP=$(echo "${gatewayIP}" | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print $1"."$2"."$3".0/24"}')

echo "remove" >> ${LOGFILE}
{{.removeString}}
sed -i /#{{.th}}#/d /etc/dnsmasq.conf
sed -i 's/,{{.th}},/,/g' ${DNSFILE}
sed -i 's/,{{.th}}$//g' ${DNSFILE}
sed -i 's/\/{{.th}},/\//g' ${DNSFILE}
sed -i '/\/{{.th}}$/d' ${DNSFILE}

if [ -z "${ACTION}" ]; then
    echo "install" >> ${LOGFILE}
    if [[ -z "$(iptables -L shunt-1 -t mangle -w 2>/dev/null | grep shunt-1)" ]]; then
        for i in $(seq 1 80); do
            iptables -w -t mangle -N shunt-${i}
            iptables -w -t mangle -A PREROUTING -j shunt-${i}
            iptables -w -t nat -N shunt-${i}
            iptables -w -t nat -A PREROUTING -j shunt-${i}
        done
    fi
    {{.installString}}
fi
echo "end" >> ${LOGFILE}

exit 0
`)

// 网络下载
const ShuntBatchAdded = string(`
exec_shunt_url() {
    local url=$1
    local save=$2
    tmp="/tmp/.hi_$(cat /proc/sys/kernel/random/uuid | cut -c1-8)"
    curl -sSL -4 -o "${tmp}" "${url}"
    if [ ! -f "${tmp}" ]; then
        echo "Failed download exec file '$url'"
        exit 1
    fi
    if [ "$(_filemd5 ${save})" = "$(_filemd5 ${tmp})" ]; then
        rm -f "${tmp}"
        echo "Same file skips exec '$url' '$save'"
    else
        if [ -f "$save" ]; then
            bash $save remove
            rm -f "${save}"
        fi
        mv "${tmp}" "$save"
        if [ ! -f "$save" ]; then
            echo "Failed to move file '$url' '$save'"
            exit 2
        fi
        bash $save
    fi
}

mkdir -p /tmp/hicloud/shunt

array=(
:{{.ths}}
)

for file in $(ls /tmp/hicloud/shunt 2>/dev/null); do
    if [[ "${file}" =~ .*\.sh$ ]] && [[ ! "${array[@]}" =~ ":${file}" ]]; then
        bash +x /tmp/hicloud/shunt/${file} remove
        pathname="$(echo ${file} | sed 's/\.sh$//')"
        rm -f /tmp/hicloud/shunt/${pathname}.* &> /dev/null
    fi
done

{{.cmds}}
`)

// 直接执行
const WireguardAdded = string(`
wireguard_start() {
    model=$(uci get rtty.general.description)
    if [ "$model" = "x300b" ]; then
        if [ "$(uci get glconfig.route_policy)" != "route_policy" ]; then
            uci set glconfig.route_policy=route_policy
        fi
        if [ "$(uci get glconfig.route_policy.enable)" != "1" ]; then
            uci set glconfig.route_policy.enable=1
            uci commit glconfig
        fi
    fi
    uci set wireguard.@proxy[0].enable="1"
    uci commit wireguard
    if [ -n "$(wg)" ]; then
        if [ -z "$(grep -rn wireguard_wan /etc/config/firewall)" ]; then
            /etc/init.d/wireguard restart >/dev/null 2>&1
        else
            [ "$(wireguard_hotup)" = "no" ] && /etc/init.d/wireguard downup >/dev/null 2>&1
        fi
        wireguard_confirm downup
    else
        if [ -f "/etc/config/wireguard_back" ]; then
            cat /etc/config/wireguard_back > /etc/config/wireguard
        fi
        uci set wireguard.@proxy[0].enable="1"
        uci commit wireguard
        /etc/init.d/wireguard start >/dev/null 2>&1
        wireguard_confirm start
    fi
}

wireguard_confirm() {
    (
        sleep 5
        if [ -z "$(wg)" ]; then
            /etc/init.d/wireguard $1 >/dev/null 2>&1
        else
            local endpoint=$(uci get wireguard.@peers[0].end_point | awk -F':' '{print $1}')
            if [ -z "$(route -n |grep $endpoint)" ]; then
                /etc/init.d/wireguard downup >/dev/null 2>&1
            fi
        fi
    ) >/dev/null 2>&1 &
}

wireguard_hotup() {
    ip address show wg0 &>/dev/null
    if [ $? -ne 0 ]; then
        echo "no"
        return
    fi
    PeerName=""
    MainServer=$(uci get wireguard.@proxy[0].main_server)
    i=0
    while [ "$i" -le "5" ]; do
        PeerName=$(uci get wireguard.@peers[$i].name)
        if [ -z "$PeerName" ]; then
            break
        elif [ "$PeerName" = "$MainServer" ]; then
            NewInetIp=$(uci get wireguard.@peers[$i].address)

            PrivateKey=$(uci get wireguard.@peers[$i].private_key)
            ListenPort=$(uci get wireguard.@peers[$i].listen_port)

            PublicKey=$(uci get wireguard.@peers[$i].public_key)
            AllowedIPs=$(uci get wireguard.@peers[$i].allowed_ips)
            Endpoint=$(uci get wireguard.@peers[$i].end_point)
            PersistentKeepalive=$(uci get wireguard.@peers[$i].persistent_keepalive)
            break
        fi
        i=$((i + 1))
    done

    if [ -n "$NewInetIp" ]; then
        cat >/var/etc/wireguard.conf <<-EOF
[Interface]
PrivateKey = $PrivateKey
ListenPort = $ListenPort

[Peer]
PublicKey = $PublicKey
AllowedIPs = $AllowedIPs
Endpoint = $Endpoint
PersistentKeepalive = $PersistentKeepalive
EOF
        OldInetIp=$(ip address show wg0 | grep inet | awk '{print $2}')
        if [ "$OldInetIp" = "$NewInetIp" ]; then
            wg syncconf wg0 /var/etc/wireguard.conf
        else
            ip address add dev wg0 $NewInetIp
            wg syncconf wg0 /var/etc/wireguard.conf
            if [ -n "$OldInetIp" ]; then
                ip address del dev wg0 $OldInetIp
                chack=$(ip address show wg0 | grep $NewInetIp)
                if [ -z "$chack" ]; then
                    ip address add dev wg0 $NewInetIp
                fi
            fi
        fi
        AllowIPV4=$(echo $AllowedIPs | cut -d ',' -f 1)
        if [ -n "$AllowIPV4" -a "$AllowIPV4" != "0.0.0.0/0" ]; then
            ip route add "$AllowIPV4" dev wg0 &> /dev/null
        else
            ip route add 0/1 dev wg0 &> /dev/null
            ip route add 128/1 dev wg0 &> /dev/null
        fi
    else
        echo "no"
    fi
}

set_wireguard_conf() {
    if [ -e "/etc/config/wireguard_back" ]; then
        cat >/tmp/wireguard_back <<-EOF
{{.wg_conf}}
EOF
        local newmd5=$(md5sum /tmp/wireguard_back | awk '{print $1}')
        local oldmd5=$(md5sum /etc/config/wireguard_back | awk '{print $1}')
        if [ "$oldmd5" == "$newmd5" ]; then
            return
        fi
    fi
    cat >/etc/config/wireguard_back <<-EOF
{{.wg_conf}}
EOF
    cat /etc/config/wireguard_back > /etc/config/wireguard
    wireguard_start
}

clear_wireguard_conf() {
    cat > /etc/config/wireguard <<-EOF
config proxy
  option enable '0'
EOF
    rm -f /etc/config/wireguard_back
    /etc/init.d/wireguard stop
}

set_lanip() {
    [ "$(uci get wireguard.@proxy[0].enable)" == "0" ] && return
    if [ "$(uci get network.lan.ipaddr)" != "{{.lan_ip}}" ]; then
        (
            uci set network.lan.ipaddr="{{.lan_ip}}"
            uci commit network
            sleep 2
            /etc/init.d/network restart
            [ -e "/usr/sbin/ssdk_sh" ] && {
                sleep 5; ssdk_sh debug phy set 2 0 0x840; ssdk_sh debug phy set 3 0 0x840
                sleep 5; ssdk_sh debug phy set 2 0 0x1240; ssdk_sh debug phy set 3 0 0x1240
            }
            [ "$(uci get rtty.general.description)" == "a1300" ] && {
                swconfig dev switch0 set linkdown 1
                swconfig dev switch0 set linkdown 0
                swconfig dev switch0 set reset 1
                swconfig dev switch0 set apply 1
            }
        ) >/dev/null 2>&1 &
    fi
}

set_hotdnsq() {
    hotdnsqFile=/etc/hotplug.d/iface/99-hi-wireguard-dnsmasq
    cat > ${hotdnsqFile} <<-EOF
#!/bin/sh
echo "nameserver {{.dns_server}}" > /etc/resolv.dnsmasq.conf 
if [ "\$ACTION" = "ifup" ] && [ "\$INTERFACE" = "lan" ]; then
    /etc/init.d/rtty restart
fi
EOF
    chmod +x ${hotdnsqFile}
    ${hotdnsqFile}
}

clear_hotdnsq() {
    rm -f /etc/hotplug.d/iface/99-hi-wireguard-dnsmasq
    local gatewayIP=$(ip route show 1/0 | head -n1 | sed -e 's/^default//' | awk '{print $2}' | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print $1"."$2"."$3"."$4}')
    if [ -n "${gatewayIP}" ]; then
        cat > /etc/resolv.dnsmasq.conf <<-EOE
nameserver ${gatewayIP}
nameserver 8.8.8.8
nameserver 8.8.4.4
EOE
    fi
}
`)

const WireguardConfExample = string(`
config proxy
    option enable '1'
    option access 'ACCEPT'
    option main_server 'hk-server'

config peers 'wg_peer_01'
    option name 'hk-server'
    option address '10.136.216.29/32'
    option listen_port '30000'
    option private_key 'SOsFN9fM1kFz3M6x/j4XqRzoGIrNC8TYVvDW1PT9T2Y='
    option dns '8.8.8.8'
    option end_point '8.219.153.138:55555'
    option public_key 'Z0WLWr25VJh0Lt/9MWvZyMGzLIIRFnd3Jaij5v05L0Q='
    option allowed_ips '0.0.0.0/0'
    option persistent_keepalive '25'
    option mtu '1360'
`)

// 直接执行
const InitContent = string(`
#!/bin/bash

set_bypass_host() {
    local host="$1"
    local thName="hi-th-api"
    local domainFile="/etc/dnsmasq.d/domain_hicloud.conf"
    #---next upgrade remove----
    local byId=99
    rm -f /etc/hotplug.d/iface/${byId}-hi-bypass-route
    rm -f /etc/hotplug.d/iface/${byId}-hi-bypass-dnsmasq
    rm -f /etc/hotplug.d/firewall/${byId}-hi-bypass-iptables
    #---next upgrade remove----
    local old2="$(cat ${domainFile} | grep "ipset=/${host}/")"
    local old1="$(cat /etc/dnsmasq.conf | grep "${host}")"
    local gatewayIP=$(ip route show 1/0 | head -n1 | sed -e 's/^default//' | awk '{print $2}' | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print $1"."$2"."$3"."$4}')
    if [ -z "$gatewayIP" ]; then
        (
            sleep 20
            set_bypass_host "$host"
        ) >/dev/null 2>&1 &
        echo "no gateway ip"
        return
    fi
    if [ ! -f "$domainFile" ]; then
        touch $domainFile
    fi
    sed -i "/#${thName}#/d" /etc/dnsmasq.conf
    sed -i "/${thName}/d" ${domainFile}
    timeout -t 2 pwd 1>/dev/null 2>&1
    if [ "$?" = "0" ]; then
        timeout -t 2 nslookup ${host} ${gatewayIP}
    else
        timeout 2 nslookup ${host} ${gatewayIP}
    fi
    runflag=$(echo $?)
    if [ "$runflag" != 0 ]; then
        ip route add 8.8.8.8 via ${gatewayIP} 
        echo "server=/${host}/8.8.8.8 #${thName}#" >> /etc/dnsmasq.conf
    else
        echo "server=/${host}/${gatewayIP} #${thName}#" >> /etc/dnsmasq.conf
    fi
    charA="$(cat ${domainFile} | grep -n "ipset=/${host}/")"
    if [ -z "$charA" ]; then
        echo "ipset=/${host}/hi-th-rtty #${thName}#" >> ${domainFile}
    fi
    if [ "$old1" != "$(cat /etc/dnsmasq.conf |grep ${host})" ] || [ "$old2" != "$(cat ${domainFile} |grep ${host})" ]; then
        /etc/init.d/dnsmasq restart
    fi
    (sleep 5;nslookup "${host}" "127.0.0.1") > /dev/null 2>&1 &
}

_sign() {
	secretKey=$(uci get rtty.general.token)
	nonce=$(echo -n $(date +%s) | md5sum | md5sum | cut -d ' ' -f 1)
	ts=$(date +%s)
	append="nonce=${nonce}&ts=${ts}&ver=1.0"
	sign=$(echo -n "${append}${secretKey}" | md5sum  | cut -d ' ' -f 1)
	queries="?${append}&sign=${sign}"
	echo -n $queries
}

downloadScript() {
    uci set rtty.general.git_commit="{{.gitCommit}}"
    uci commit rtty
cat >/mnt/curl.lua<<EOB
local ltn12 = require("ltn12")
local https = require 'ssl.https'
local json = require 'cjson'
local response_body = {}
local request_body = arg[3] and arg[3] or '{}'
https.request({
    url = arg[1],
    method = arg[2],
    headers = {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = #request_body;
    },
    source = ltn12.source.string(request_body),
    sink = ltn12.sink.table(response_body)
})
print(table.concat(response_body))
EOB

    mkdir -p /etc/hotplug.d/dhcp/
cat >/etc/hotplug.d/dhcp/99-hi-dhcp<<EOF
[ "\$ACTION" = "add" ] && {
    flock -xn /tmp/hi-clients.lock -c /usr/sbin/hi-clients
}
EOF
    chmod +x /etc/hotplug.d/dhcp/99-hi-dhcp

    mkdir -p /etc/hotplug.d/net/
    curl --connect-timeout 3 -sSL -4 -o "/etc/hotplug.d/net/99-hi-wifi" "{{.wifiCmdUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/etc/hotplug.d/net/99-hi-wifi" ] || {
        local res=$(lua /mnt/curl.lua "{{.wifiCmdUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/etc/hotplug.d/net/99-hi-wifi
    }
    chmod +x /etc/hotplug.d/net/99-hi-wifi

    curl --connect-timeout 3 -sSL -4 -o "/usr/sbin/hi-static-leases" "{{.staticLeasesCmdUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/usr/sbin/hi-static-leases" ] || {
        local res=$(lua /mnt/curl.lua "{{.staticLeasesCmdUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/usr/sbin/hi-static-leases
    }
    chmod +x /usr/sbin/hi-static-leases

    curl --connect-timeout 3 -sSL -4 -o "/usr/sbin/hi-clients" "{{.dhcpCmdUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/usr/sbin/hi-clients" ] || {
        local res=$(lua /mnt/curl.lua "{{.dhcpCmdUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/usr/sbin/hi-clients
    }
    chmod +x /usr/sbin/hi-clients
    [ -z "crontab -l|grep hi-clients" ] && echo "* * * * * flock -xn /tmp/hi-clients.lock -c /usr/sbin/hi-clients" >>/tmp/cronbak
    /etc/init.d/cron reload

    [ ! -e "/etc/init.d/wireguard" ] && {
        curl --connect-timeout 3 -sSL -4 -o "/etc/init.d/wireguard" "{{.wireguardScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
        chmod +x /etc/init.d/wireguard
    }
    curl --connect-timeout 3 -sSL -4 -o "/usr/sbin/syslogUpload" "{{.routerlogScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/usr/sbin/syslogUpload" ] || {
        local res=$(lua /mnt/curl.lua "{{.routerlogScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/usr/sbin/syslogUpload
    }
    chmod +x /usr/sbin/syslogUpload
    sed -i '/syslogUpload/d' /etc/crontabs/root
    echo "* */1 * * * flock -xn /tmp/sysUpload.lock -c /usr/sbin/syslogUpload" >>/etc/crontabs/root ; /etc/init.d/cron restart
    syslogUpload edit &

    sed -i '/devid/d' /etc/rc.local
    tmp='{"content":"","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
    host="{{.restartReportUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    sed -i '$i (sleep 10;curl -4 -X POST '\"$host\"' -H "Content-Type: application/json" -d '\'$tmp\'') &' /etc/rc.local
}

downloadExtraScript(){
    curl --connect-timeout 3 -sSL -4 -o "/tmp/detection_device_script.sh" "{{.detdeviceScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/tmp/detection_device_script.sh" ] || {
        local res=$(lua /mnt/curl.lua "{{.detdeviceScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/tmp/detection_device_script.sh
    }
    chmod +x /tmp/detection_device_script.sh
    curl --connect-timeout 3 -sSL -4 -o "/usr/sbin/wrtbwmon" "{{.wrtbwmonScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/usr/sbin/wrtbwmon" ] || {
        local res=$(lua /mnt/curl.lua "{{.wrtbwmonScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/usr/sbin/wrtbwmon
    }
    chmod +x /usr/sbin/wrtbwmon
    curl --connect-timeout 3 -sSL -4 -o "/usr/sbin/readDB.awk" "{{.readdbawkScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)"
    [ -e "/usr/sbin/hi-static-leases" ] || {
        local res=$(lua /mnt/curl.lua "{{.readdbawkScriptUrl}}$(_sign)&devid=$(uci get rtty.general.id)" "GET")
        echo "$res">/usr/sbin/readDB.awk
    }
    sh /tmp/detection_device_script.sh
}

set_bypass_host "{{.apiHost}}" &

git_commit=$(uci get rtty.general.git_commit 2>/dev/null)
onlyid=$(uci get rtty.general.onlyid)
if [ "${git_commit}" != "{{.gitCommit}}" ] || [ "${onlyid}" != "{{.onlyid}}" ]; then
    [ -e "/usr/share/hiui/rpc/system.lua" ] && [ ! -e "/mnt/first" ] && {
        sed -i 's/goodlife/speedbox/g' /etc/config/wireless
        sed -i 's/GL-//g' /etc/config/wireless
        sn=$(uci get rtty.general.id)
        echo -e "$sn\n$sn" | (passwd root)
        touch /mnt/first
    }
    downloadScript 
fi

[ -n "$(grep apconfig.lua /etc/hotplug.d/net/99-hi-wifi)" ] || downloadScript 
[ -n "$(grep hi_static_leases /usr/sbin/hi-static-leases)" ] || downloadScript
[ -n "$(grep clients.lua /usr/sbin/hi-clients)" ] || downloadScript
[ -e "/usr/sbin/detection.sh" ] || downloadExtraScript &

sn=$(uci get rtty.general.id)
pwd=$(uci get hiui.@user[0].password)
webpwd=$(echo -n "$pwd:$sn" |md5sum|awk '{print $1}')
tmp='{"webpwd":"'$webpwd'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}' 
curl --connect-timeout 3 -4 -X POST "{{.webpwdReportUrl}}" -H "Content-Type: application/json" -d $tmp &
[ "$?" != "0" ] && lua /mnt/curl.lua "{{.webpwdReportUrl}}" "POST" $tmp &
/etc/hotplug.d/net/99-hi-wifi &
/usr/sbin/hi-static-leases &
/usr/sbin/hi-clients &
`)

// 网络下载
const ClientsReportAdded = string(`
#!/bin/sh
. /usr/share/libubox/jshn.sh
json_init
wrtbwmon -4 -f /tmp/usage.db
json_add_array "clients"
num=0
awk -F',' 'NR!=1 {print $1,$2,$3,$4,$5,$10}' /tmp/usage.db >/tmp/.clients
while read mac ip iface down up last_time; do
    online=$(awk '$4=="'$mac'" {if ( $3=="0x2" ) print 1;else print 0;}' /proc/net/arp)
    if [ "$ip" != "NA" ] && [ -n "$online" ]; then
        if [ $(($(date +%s) - $last_time)) -lt 28800 ]; then
            name=$(awk '$1=="'$mac'" {if ( $4!="*" ) print $4;else print Unknown}' /tmp/dhcp.leases)
            [ -z "$name" ] && name="Unknown"
            bind=$(grep $mac /etc/config/dhcp)
            if [ -z "$bind" ]; then
                bind='0'
            else
                bind='1'
            fi
            blocked=0
            if [ ! -e "/etc/clients" ]; then
                [ -e "/mnt/blocked" ] && [ -z "$(grep $mac /mnt/blocked)" ] && blocked=1
            else
                blocked=$(awk '$1==toupper("'$mac'") {print $7}' /etc/clients)
            fi
            json_add_object $num
            json_add_string 'mac' $mac
            json_add_string 'ip' $ip
            json_add_string 'name' $name
            json_add_string 'iface' $iface
            json_add_boolean 'online' $onlne
            json_add_int 'alive' $last_time
            json_add_boolean 'blocked' $blocked
            json_add_int 'up' $up
            json_add_int 'down' $down
            qos_up=0
            qos_down=0
            [ -e "/etc/config/qos" ] && {
                _mac=$(echo $mac | sed 's/://g')
                qos_up=$(uci get qos.$_mac.upload)
                qos_down=$(uci get qos.$_mac.download)
            }
            json_add_string 'qos_up' $qos_up
            json_add_string 'qos_down' $qos_down
            json_add_boolean 'bind' $bind
            json_close_object
            echo "cur=$JSON_CUR"
            num=$((num + 1))
        fi
    fi
done </tmp/.clients
json_close_array
json_add_int 'code' 0
RES=$(json_dump)
if [ -z "$RES" ]; then
    exit 1
fi
if [ -e "/etc/glversion" ]; then
    version=$(cat /etc/glversion)
else
    version=$(cat /etc/openwrt_release|grep DISTRIB_RELEASE |awk -F'=' '{gsub(/\047/,""); print $2}')
fi
webVer=$(awk '/hiui-ui-core/ {getline;print $2}' /usr/lib/opkg/status)
rttyVer=$(awk '/Package: rtty-openssl/ {getline;print $2}' /usr/lib/opkg/status)
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'","ver":"'$version'","webVer":"'$webVer'","rttyVer":"'$rttyVer'"}'
echo -n $tmp | curl -4 -X POST "{{.reportUrl}}$(_sign)" -H "Content-Type: application/json" -d @-
[ "$?" != "0" ] && lua /mnt/curl.lua "{{.reportUrl}}$(_sign)" "POST" $tmp
`)

// 网络下载
const ApConfigReportAdded = string(`
cat >/tmp/apconfig.lua <<EOF
local json = require 'cjson'
local iwinfo = require 'iwinfo'
local uci = require 'uci'
local c = uci.cursor()
local result = {}
c:foreach("wireless", "wifi-device", function(s)
    s.encryptions = encryptions(s.type)
    s.device = s[".name"]
    s.interfaces = {}
    c:foreach("wireless", "wifi-iface", function(res)
        if res.device == s[".name"] and res['.name'] ~= "sta" then
            c:foreach("network", "interface", function(ss)
                if ss[".name"] == res[".name"] then
                    res.ipsegment = ss.ipaddr
                end
            end)
            if res.hidden and res.hidden == "1" then
                res.hidden = true
            else
                res.hidden = false
            end
            if res.disabled and res.disabled == "1" then
                res.enable = false
            else
                res.enable = true
            end
            res.encrypt = res.encryption
            table.insert(s.interfaces, res)
        end
    end)
    if string.lower(s.band) == "2g" then
        result["wifi_2g"] = s
    elseif string.lower(s.band) == "5g" and s.htmode ~= "HE160" then
        result["wifi_5g"] = s
    end
end)
return json.encode(result)
EOF
if [ -e "/var/run/delwifi.lock" ] || [ -e "/var/run/addwifi.lock" ]; then
    exit 0
fi
RES=$(lua /tmp/apconfig.lua)
if [ -z "$RES" ]; then
    exit 1
fi
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
curl -4 -X POST "{{.reportUrl}}$(_sign)" -H "Content-Type: application/json" -d $tmp
[ "$?" != "0" ] && lua /mnt/curl.lua "{{.reportUrl}}$(_sign)" "POST" $tmp
`)

// 网络下载
const StaticLeasesReportAdded = string(`
. /lib/functions.sh
list=""
function host_func() {
    config_get ip $1 "ip"
    config_get mac $1 "mac"
    config_get name $1 "name"
    ipseg=$(echo $ip|awk -F"." '{print $1"."$2"."$3}')
    if [ -n "$(grep $ipseg /etc/config/network)" ]; then
        tmp='{"mac":"'$mac'","ip":"'$ip'","name":"'$name'"}'
        if [ -z "$list" ]; then
            list=$tmp
        else
            list="$list,$tmp"
        fi
    else
        uci delete dhcp.$1
    fi
}

config_load dhcp
config_foreach host_func host
uci commit dhcp
RES=$(echo -e '{"code":0,"list":['"$list"']}')
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
RES=$(curl --connect-timeout 3 -4 -X POST "{{.reportUrl}}$(_sign)" -H "Content-Type: application/json" -d $tmp)
[ "${RES}" != "success" ] && lua /mnt/curl.lua "{{.reportUrl}}$(_sign)" "POST" $tmp
echo 'success'
`)

// 直接执行
const SetStaticLeasesContent = string(`
#!/bin/bash

# delete
for mac_str in $(cat /etc/config/dhcp | grep '\<host\>' | awk '{print $3}' | sed -r "s/'//g"); do
    uci delete dhcp.$mac_str
done

# add
{{.addString}}
uci commit dhcp

# report
if [ -f "/usr/sbin/hi-static-leases" ]; then
    /usr/sbin/hi-static-leases &
fi
`)

// 直接执行
const EditWifiContent = string(`
. /lib/functions.sh
if [ -e "/var/run/delwifi.lock" ] || [ -e "/var/run/addwifi.lock" ]; then
    echo '{"code":103,"msg":"wifi deleting or adding"}'
    exit 1
fi
handle_wifi(){
    {{.addString}}
    ssid=$(uci get wireless.$1.ssid)
}
handle_wifi {{.name}}
uci commit wireless
_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}
RES=$(lua /tmp/apconfig.lua)
host="{{.reportUrl}}$(_sign)""&token={{.token}}"
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
curl -4 -X POST "$host" -H "Content-Type: application/json" -d $tmp
[ "$?" != "0" ] && lua /mnt/curl.lua "$host" "POST" $tmp

if [ "$(cat /etc/openwrt_version)" == "15.05.1" ]; then
    (
        /sbin/wifi reload
        sleep 10
        {{.chaos_calmer}}
        uci commit network
        uci commit wireless
        /etc/init.d/network reload
    ) >/dev/null 2>&1 &
else
    /sbin/wifi reload >/dev/null 2>&1 &
fi
`)

// 直接执行
const BlockedContent = string(`
. /usr/share/libubox/jshn.sh
while [ 1 ]; do
    [ ! -f /var/run/block.lock ] && break
    sleep 1
done
json_init
json_load '{{.macs}}'
if [ "{{.action}}" == "addBlocked" ]; then
    status=1
elif [ "{{.action}}" == "delBlocked" ]; then
    status=0
fi
dump_item() {
    local mac=$(echo $1|tr a-z A-Z)
    res=$(awk '$1=="'$mac'" {sub(/[0-1]/,"'$status'",$7);print}' /etc/clients)
    sed -i "/$mac/c $res" /etc/clients
    if [ "$status" == "0" ]; then
        ipset del block_device $mac
        sed -i "/$mac/d" /mnt/blocked
    elif [ "$status" == "1" ]; then
        ipset add block_device $mac
        echo $mac >>/mnt/blocked
    fi
}
touch /var/run/block.lock
json_for_each_item "dump_item" "macs"
rm -f /var/run/block.lock
hi-clients
`)

// 直接执行
const GetVersionContent = string(`
if [ -e "/etc/glversion" ]; then
    version=$(cat /etc/glversion)
else
    version=$(cat /etc/openwrt_release|grep DISTRIB_RELEASE |awk -F'=' '{gsub(/\047/,""); print $2}')
fi
if [ -e "/tmp/sysinfo/board_name_alias" ]; then
    model=$(cat /tmp/sysinfo/board_name_alias)
else
    model=$(awk -F',' '{print $2}' /tmp/sysinfo/board_name)
fi
webVer=$(awk '/hiui-ui/ {getline;print $2}' /usr/lib/opkg/status)
echo -e '{"version":"'$version'","model":"'$model'","webVer":"'$webVer'"}'
`)

// 直接执行
const SpeedTestContent = string(`
#!/bin/sh
. /usr/share/libubox/jshn.sh
json_init
speedpid=$(ps | grep '[s]peedtest_cpp' | awk '{print $1}')
if [ ! -z "${speedpid}" ]; then
	kill -9 ${speedpid} >>/dev/null 2>&1 
fi
speedtest_cpp --output json >/tmp/speedtest
json_load "$(cat /tmp/speedtest)"
json_add_string "sn" "$(uci get rtty.general.id)"
json_add_int "code" "0"
result=$(json_dump)
curl -4 -X POST {{.callurl}} -H 'Content-Type: application/json' -d "${result}"
[ "$?" != "0" ] && lua /mnt/curl.lua "{{.callurl}}" "POST" "$result"
`)

// 直接执行
const FetchLogContent = string(`
dmesg > /tmp/dmesg.log

[ -f "/var/log/syslog.log" ] && curl -4 -X POST "{{.url}}$(_sign)&is_manual={{.isManual}}&admin_id={{.adminId}}&log_type=sys" -F file=@/var/log/syslog.log
curl -4 -X POST "{{.url}}$(_sign)&is_manual={{.isManual}}&admin_id={{.adminId}}&log_type=dmsg" -F file=@/tmp/dmesg.log
`)

// 直接执行
const SyncVersionContent = string(`
#!/bin/sh
[ -e "/tmp/hiui" ] && rm -rf /tmp/hiui
echo '{{.verInfo}}' > /tmp/version.info
`)

// 直接执行
const AddWifiContent = string(`
. /lib/functions.sh

if [ -e "/var/run/addwifi.lock" ]; then
    echo '{"code":102,"msg":"wifi adding"}'
    exit 1
fi
{{.ipSegment}}
touch /var/run/addwifi.lock
{{.wireless}}
uci commit wireless
{{.network}}
if [ "$(cat /etc/openwrt_version)" == "15.05.1" ]; then
    wifi reload
    sleep 20
    {{.chaos_calmer}}
    uci commit network
    uci commit wireless
else
    {{.openwrt}}
    uci commit network
    uci commit wireless
    wifi reload
fi
{{.dhcp}}
uci commit dhcp
handle_firewall(){
    local tmp=$1
    config_get name "$1" "name"
    if [ "$name" == "lan" ]; then
        {{.firewall}}
    fi
}
config_load firewall
config_foreach handle_firewall zone
uci commit firewall
rm -f /var/run/addwifi.lock
_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}
RES=$(lua /tmp/apconfig.lua)
host="{{.reportUrl}}$(_sign)""&token={{.token}}"
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
for i in 1 2 3 4 5; do
	curl -4 --connect-timeout 3 -m 6 -X POST "$host" -H "Content-Type: application/json" -d $tmp
	if [ "$(echo $?)" == "0" ]; then
		exit 0
    else
        lua /mnt/curl.lua "$host" "POST" $tmp
	fi
	sleep 3
done
/etc/init.d/firewall reload
/etc/init.d/network reload
`)

// 直接执行
const DelWifiContent = string(`
if [ -e "/var/run/delwifi.lock" ]; then
    echo '{"code":102,"msg":"wifi deleting"}'
    exit 1
fi
touch /var/run/delwifi.lock
{{.del}}
uci commit firewall
uci commit network
uci commit wireless
uci commit dhcp
_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}
RES=$(lua /tmp/apconfig.lua)
host="{{.reportUrl}}$(_sign)""&token={{.token}}"
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
curl -4 -X POST "$host" -H "Content-Type: application/json" -d $tmp
if [ "$?" != "0" ]; then
    lua /mnt/curl.lua "$host" "POST" $tmp
fi
rm -f /var/run/delwifi.lock
wifi reload &
`)

// 直接执行
const DelAllCustomWifi = string(`
#!/bin/sh
. /lib/functions.sh
handle_wifi(){
    local tmp=$1
    if [ -n "$(echo $tmp|grep -E 'wlan[0-9]{10}')" ]; then
        uci delete dhcp.$tmp
        uci delete network.$tmp
        uci delete wireless.$tmp
        sed -i "/$tmp/d" /etc/config/firewall
    fi
}
config_load wireless
config_foreach handle_wifi wifi-iface
uci commit firewall
uci commit network
uci commit wireless
uci commit dhcp
wifi reload &
`)

// 直接执行
const DiagnosisContent = string(`
#!/bin/bash

. /lib/functions/network.sh
get_wan_iface_and_gateway() {
    iface=$(cat /var/run/mwan3/indicator 2>/dev/null || echo "unknown")
    [ "$iface" != "unknown" ] && {
        interface=$(ifstatus $iface | jsonfilter -e @.l3_device)
        proto=$(ifstatus $iface | jsonfilter -e @.proto)
        result=$(echo $iface | grep "modem")
        if [ "$result" != "" -a "$proto" = "qmi" ]; then
            gw=$(ifstatus ${iface}_4 | jsonfilter -e @.route[0].nexthop)
        else
            gw=$(ifstatus $iface | jsonfilter -e @.route[0].nexthop)
        fi
    }
    [ "$iface" = "unknown" ] && {
        local tmpiface
        network_find_wan tmpiface
        network_get_gateway gw $tmpiface
    }
}
ips={{.ip}}
if [ -z "$ips" ]; then
    get_wan_iface_and_gateway
    ips=$gw
fi
(
    RES=$(oping -c 5 ${ips} | base64 | tr -d "\n")
    tmp='{"content":"'$RES'","sn":"'$(uci get rtty.general.id)'","type":"{{.type}}","batch":"{{.batch}}","index":0}'
	curl -4 -X POST "{{.callbackUrl}}" -H "Content-Type: application/json" -d $tmp
    [ "$?" != "0" ] && lua /mnt/curl.lua "{{.callbackUrl}}" "POST" $tmp
) &
echo '{"code":1,"msg":"ping task start"}'
`)

// 直接执行
const IpkRemoteUpgrade = string(`

rm -rf /tmp/ipk
curl -s -o /tmp/ipk.zip {{.remotePath}} && mkdir -p /tmp/ipk
unzip /tmp/ipk.zip -d /tmp/ipk
arch=$(opkg status rtty-openssl | grep -E 'Architecture' | awk '{print $2=$2}')
find /tmp/ipk ! -name "*all.ipk" ! -name "*$arch.ipk" -maxdepth 1 -type f -exec rm {} +
opkg install /tmp/ipk/*.ipk && touch /tmp/ipk/success
if [ -e "/tmp/ipk/success" ]; then
    if [ -e "/etc/glversion" ]; then
        version=$(cat /etc/glversion)
    else
        version=$(cat /etc/openwrt_release|grep DISTRIB_RELEASE |awk -F'=' '{gsub(/\047/,""); print $2}')
    fi
    webVer=$(awk '/hiui-ui-core/ {getline;print $2}' /usr/lib/opkg/status)
    rttyVer=$(awk '/Package: rtty-openssl/ {getline;print $2}' /usr/lib/opkg/status)
    tmp='{"content":"","sn":"'$(uci get rtty.general.id)'","ver":"'$version'","webVer":"'$webVer'","rttyVer":"'$rttyVer'"}'
	host="{{.verUrl}}$(_sign)"
    curl -4 -X POST "$host" -H "Content-Type: application/json" -d $tmp
    [ "$?" != "0" ] && lua /mnt/curl.lua "$host" "POST" $tmp
    echo "success"
fi
`)

// 网络下载
const RouterLogUpload = string(`
if [ -z "$(uci get system.@system[0].log_file)" ] || [ "$1" == "edit" ]; then
    uci set system.@system[0].log_file='/var/log/syslog.log'
    uci set system.@system[0].log_buffer_size='128'
    uci set system.@system[0].log_size='5120'
    uci commit system
    /etc/init.d/log restart
    exit 0
fi
host="{{.logUrl}}/$(uci get rtty.general.id)$(_sign)"
dmesg >/var/log/dmesg.log
curl -F file=@/var/log/dmesg.log "$host""&log_type=dmesg"
res=$(curl -F file=@/var/log/syslog.log "$host""&log_type=sys")
if [ $res == 'success' ]; then
    rm /var/log/syslog.log
    /etc/init.d/log restart
fi
[ -e "/var/log/exec.log" ] && curl -F file=@/var/log/exec.log "$host""&log_type=exec"
`)

// 直接执行
const ClientQos = string(`
[ ! -e "/etc/config/qos" ] && {
    /etc/init.d/eqos start
}
status=$(tc class list dev br-lan)
[ -z "$status" ] && eqos start 125000 125000
{{.setRule}}
hi-clients &
`)

func FromTemplateContent(templateContent string, envMap map[string]interface{}) string {
	tmpl, err := template.New("text").Parse(templateContent)
	defer func() {
		if r := recover(); r != nil {
			log.Println("Template parse failed:", err)
		}
	}()
	if err != nil {
		panic(1)
	}
	var buffer bytes.Buffer
	_ = tmpl.Execute(&buffer, envMap)
	return string(buffer.Bytes())
}

func ShuntDomainTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(ShuntDomainPartial))
	return FromTemplateContent(sb.String(), envMap)
}

func ShuntTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(ShuntContent))
	return FromTemplateContent(sb.String(), envMap)
}

func ShuntBatchTemplate(envMap map[string]interface{}) string {
	text := fmt.Sprintf("%s\n%s", CommonUtilsContent, ShuntBatchAdded)
	var sb strings.Builder
	sb.Write([]byte(text))
	return FromTemplateContent(sb.String(), envMap)
}

func WireguardTemplate(envMap map[string]interface{}) string {
	text := fmt.Sprintf("%s\n%s", CommonUtilsContent, WireguardAdded)
	var sb strings.Builder
	sb.Write([]byte(text))
	return FromTemplateContent(sb.String(), envMap)
}

func InitTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(InitContent))
	return FromTemplateContent(sb.String(), envMap)
}

func ApiReportTemplate(envMap map[string]interface{}) string {
	var text string
	if envMap["requestType"] == "static_leases" {
		text = fmt.Sprintf("%s\n%s", CommonUtilsContent, StaticLeasesReportAdded)
	} else if envMap["requestType"] == "apconfig" {
		text = fmt.Sprintf("%s\n%s", CommonUtilsContent, ApConfigReportAdded)
	} else if envMap["requestType"] == "clients" {
		text = fmt.Sprintf("%s\n%s", CommonUtilsContent, ClientsReportAdded)
	}
	var sb strings.Builder
	sb.Write([]byte(text))
	return FromTemplateContent(sb.String(), envMap)
}

func SetStaticLeasesTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(SetStaticLeasesContent))
	return FromTemplateContent(sb.String(), envMap)
}

func EditWifiTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, EditWifiContent)))
	return FromTemplateContent(sb.String(), envMap)
}

func BlockedTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, BlockedContent)))
	return FromTemplateContent(sb.String(), envMap)
}

func GetVersion(name string) string {
	var sb strings.Builder
	if name == "firmware" {
		sb.Write([]byte(GetVersionContent))
	} else {
		sb.WriteString(fmt.Sprintf("awk '/Package: %s$/ {getline;print $2}' /usr/lib/opkg/status", name))
	}
	return sb.String()
}

func SpeedTestTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(SpeedTestContent))
	return FromTemplateContent(sb.String(), envMap)
}

func FetchLogTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, FetchLogContent)))
	return FromTemplateContent(sb.String(), envMap)
}

func SyncVersionTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(SyncVersionContent))
	return FromTemplateContent(sb.String(), envMap)
}

func AddWifiTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, AddWifiContent)))
	return FromTemplateContent(sb.String(), envMap)
}

func DelWifiTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, DelWifiContent)))
	return FromTemplateContent(sb.String(), envMap)
}

func DiagnosisTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(DiagnosisContent))
	return FromTemplateContent(sb.String(), envMap)
}

func WireguardScriptTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(WireguardScript))
	return FromTemplateContent(sb.String(), envMap)
}

func WrtbwmonScriptTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(WrtbwmonScript))
	return FromTemplateContent(sb.String(), envMap)
}
func DetectionDeviceScriptTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(DetectionDeviceScript))
	return FromTemplateContent(sb.String(), envMap)
}
func ReadDBAWKTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(ReadDBAWK))
	return FromTemplateContent(sb.String(), envMap)
}
func IpkRemoteUpgradeTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, IpkRemoteUpgrade)))
	return FromTemplateContent(sb.String(), envMap)
}
func RouterLogUploadTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(fmt.Sprintf("%s\n%s", CommonUtilsContent, RouterLogUpload)))
	return FromTemplateContent(sb.String(), envMap)
}
func ClientQosTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(ClientQos))
	return FromTemplateContent(sb.String(), envMap)
}
