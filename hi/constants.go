package hi

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"text/template"
)

const WireguardScript = string(`
#!/bin/sh  /etc/rc.common

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

    # Load whether to enable masquerading from the wireguard configuration
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
    #[ -n "$end_point" ] && echo -e "Endpoint = $end_point" >> "$WFILE"
    if [ "$persistent_keepalive" == "" ]; then
        echo -e "PersistentKeepalive = 25" >>"$WFILE"
    else
        echo -e "PersistentKeepalive = $persistent_keepalive" >>"$WFILE"
    fi
    publicip=$(echo $end_point | cut -d ":" -f1)
    eport=$(echo $end_point | cut -d ":" -f2)
    #echo "publicip=$publicip eport=$eport" >/dev/console
    if [ "$publicip" != "" ]; then
        ip=$(resolveip $publicip | egrep '[0-9]{1,3}(\.[0-9]{1,3}){3}' | grep -v "127.0.0.1" | grep -v "::" | head -n 1)
        if [ "$ip" = "" ]; then
            ip=$(nslookup $publicip 2>/dev/null | grep -v "127.0.0.1" | grep "::" | awk '/Address/ {print $3}')
        fi
        #echo "ip=$ip" >/dev/console
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
    #echo "get_localip_func address=$address"
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

        #echo "well"
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
    #echo "firewall local_port=$local_port"
    # Listen Port Tcp/UDP
    uci set firewall.AllowWireguard='rule'
    uci set firewall.AllowWireguard.name='Allow-Wireguard'
    uci set firewall.AllowWireguard.target='ACCEPT'
    uci set firewall.AllowWireguard.src='wan'
    uci set firewall.AllowWireguard.proto='udp tcp'
    uci set firewall.AllowWireguard.family='ipv4'
    uci set firewall.AllowWireguard.dest_port="$listen_port"
    #zone
    uci set firewall.wireguard='zone'
    uci set firewall.wireguard.name='wireguard'
    uci set firewall.wireguard.input=$access
    uci set firewall.wireguard.forward='DROP'
    uci set firewall.wireguard.output='ACCEPT'
    uci set firewall.wireguard.masq="$masq"
    uci set firewall.wireguard.mtu_fix='1'
    uci set firewall.wireguard.device='wg0'
    uci set firewall.wireguard.masq6='1'
    #forwarding wireguard to wan
    uci set firewall.wireguard_wan='forwarding'
    uci set firewall.wireguard_wan.src='wireguard'
    uci set firewall.wireguard_wan.dest='wan'
    #forwarding wireguard to lan
    uci set firewall.wireguard_lan='forwarding'
    uci set firewall.wireguard_lan.src='wireguard'
    uci set firewall.wireguard_lan.dest='lan'
    [ "$access" != "ACCEPT" ] && {
        uci set firewall.wireguard_lan.enabled='0'
    }
    #forwarding lan to wireguard
    uci set firewall.lan_wireguard='forwarding'
    uci set firewall.lan_wireguard.src='lan'
    uci set firewall.lan_wireguard.dest='wireguard'

    if [ -n "$guest_exist" ]; then
        #forwarding guest to wireguard
        uci set firewall.guest_wireguard='forwarding'
        uci set firewall.guest_wireguard.src='guestzone'
        uci set firewall.guest_wireguard.dest='wireguard'
        #forwarding wireguard to guest
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
    #echo "tmpiface=$tmpiface interface=$interface gw=$gw" >/dev/console
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
        #interface=$(uci get network.$iface.ifname)
        #gw=$(route | grep default | grep $interface | awk '{print $2}')
        #echo "iface=$iface interface=$interface gw=$gw" >/dev/console
    }
    [ "$iface" = "unknown" ] && {
        get_wan_nomwan3_info
        #echo "interface=$interface gw=$gw" >/dev/console
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

    #ip link del dev wg0 1>/dev/null 2>&1 || true
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
    #wireguard_delete_firewall
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
        #wireguard_delete_firewall
        [ -f "/tmp/resolv.conf.vpn" ] && {
            rm -rf /tmp/resolv.conf.vpn
            uci del dhcp.@dnsmasq[0].resolvfile
            uci commit dhcp
            /etc/init.d/dnsmasq restart
        }
        #lan2wan_forwarding enable
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

    #fix ddns conflict
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
                # local policy
                logger -t wireguard "start setting local policy"
                if [ "$ipv6" != "" ];then
                        local_ip=$(echo "$address_ipv4" | grep -m 1 -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
                else
                        local_ip=$(echo "$address" | grep -m 1 -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
                fi
                # create new route table
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

                # deal with dns resolve
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
        #ip=$(resolveip $publicip | egrep '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n 1)
        if [ "$ip" = "" ]; then
            #ip=$(nslookup $publicip 2>/dev/null | awk '/Address 1/ {print $3}')
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
    #delete firewall
    lan2wan_forwarding enable
    wireguard_delete_firewall
    #delete wg0
    ip link del dev wg0 1>/dev/null 2>&1
    rm $WFILE -rf
    echo f >/proc/net/nf_conntrack
    env -i ACTION="ifdown" INTERFACE="wg" /sbin/hotplug-call iface

    if [ "$model" = "mv1000" ]; then
        sync
    fi

    #delete DDNS Chain
    local DDNS=$(iptables -nL -t mangle | grep WG_DDNS)
    if [ -n "$DDNS" ]; then
        ip rule del fwmark 0x60000/0x60000 lookup 31 pref 31
        iptables -t mangle -D PREROUTING -j WG_DDNS
        iptables -t mangle -F WG_DDNS
        iptables -t mangle -X WG_DDNS
    fi

    : <<EOF
        # local policy
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
        #wireguard_delete_firewall
        [ -f "/tmp/resolv.conf.vpn" ] && {
            rm -rf /tmp/resolv.conf.vpn
            uci del dhcp.@dnsmasq[0].resolvfile
            uci commit dhcp
            /etc/init.d/dnsmasq restart
        }
        #lan2wan_forwarding enable
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
`)

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

const ShuntBatchAdded = string(`
exec_shunt_url() {
    local url=$1
    local save=$2
    local tmp="/tmp/.hi_$(_random)"
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
        # rm -f /tmp/hicloud/shunt/${pathname}.* &> /dev/null
    fi
done

{{.cmds}}
`)

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
    enable=$(uci get wireguard.@proxy[0].enable)
    if [ "$enable" != "1" ]; then
        if [ -n "$(wg)" ]; then
            uci set wireguard.@proxy[0].enable="1"
            uci commit wireguard
            enable="1"
        fi
    fi
    if [ "$enable" = "1" ]; then
        if [ "$(wireguard_hotup)" = "no" ]; then
            /etc/init.d/wireguard downup
        fi
        wireguard_confirm downup
    else
        if [ -f "/etc/config/wireguard_back" ]; then
            cat /etc/config/wireguard_back > /etc/config/wireguard
        fi
        uci set wireguard.@proxy[0].enable="1"
        uci commit wireguard
        /etc/init.d/wireguard start
        wireguard_confirm start
    fi
}

wireguard_confirm() {
    (
        sleep 5
        if [ -z "$(wg)" ]; then
            /etc/init.d/wireguard $1
        else
            local endpoint=$(uci get wireguard.@peers[0].end_point | awk -F':' '{print $1}')
            if [ -z "$(route -n |grep $endpoint)" ]; then
                /etc/init.d/wireguard downup
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
    #
    PeerName=""
    MainServer=$(uci get wireguard.@proxy[0].main_server)
    i=0
    while [ "$i" -le "10" ]; do
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
                sleep 10; ssdk_sh debug phy set 2 0 0x840; ssdk_sh debug phy set 3 0 0x840
                sleep 5; ssdk_sh debug phy set 2 0 0x1240; ssdk_sh debug phy set 3 0 0x1240
            }
        ) >/dev/null 2>&1 &
    fi
}

set_hotdnsq() {
    hotdnsqFile=/etc/hotplug.d/iface/99-hi-wireguard-dnsmasq
    cat > ${hotdnsqFile} <<-EOF
#!/bin/sh
cat > /etc/resolv.dnsmasq.conf <<-EOE
nameserver {{.dns_server}}
nameserver 8.8.8.8
nameserver 8.8.4.4
EOE
[ "\$ACTION" = "ifup" ] && [ "\$INTERFACE" = "lan" ] && {
    /etc/init.d/rtty restart
}
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

const InitContent = string(`
#!/bin/bash

set_bypass_host() {
    local host="$1"
    
    local byId=99
    local thName="hi-th-api"
    
    local tableId=$(printf '9999%d' $byId)
    local markId=$(printf '0x%x' $tableId)

    local domainFile="/etc/dnsmasq.d/domain_hicloud.conf"
    local hotRouteFile="/etc/hotplug.d/iface/${byId}-hi-bypass-route"
    local hotdnsqFile="/etc/hotplug.d/iface/${byId}-hi-bypass-dnsmasq"
    local hotiptaFile="/etc/hotplug.d/firewall/${byId}-hi-bypass-iptables"

    local gatewayIP=$(ip route show 1/0 | head -n1 | sed -e 's/^default//' | awk '{print $2}' | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255{print $1"."$2"."$3"."$4}')
    if [ -z "$gatewayIP" ]; then
        (
            sleep 20
            set_bypass_host "$host"
        ) >/dev/null 2>&1 &
        echo "no gateway ip"
        return
    fi

    mkdir -p /etc/dnsmasq.d
    mkdir -p /etc/hotplug.d/iface/
    mkdir -p /etc/hotplug.d/firewall/

    if [ -z "$(cat /etc/dnsmasq.conf | grep 'conf-dir=/etc/dnsmasq.d')" ]; then
        sed -i /conf-dir=/d /etc/dnsmasq.conf
        echo 'conf-dir=/etc/dnsmasq.d' >> /etc/dnsmasq.conf
    fi
    if [ -z "$(cat /etc/dnsmasq.conf | grep 'resolv-file=/etc/resolv.dnsmasq.conf')" ]; then
        sed -i /resolv-file=/d /etc/dnsmasq.conf
        echo 'resolv-file=/etc/resolv.dnsmasq.conf' >> /etc/dnsmasq.conf
    fi

    if [ ! -f "$domainFile" ]; then
        touch $domainFile
    fi

    iptables -w -t mangle -D OUTPUT -m set --match-set ${thName} dst -j ACCEPT &> /dev/null
    iptables -w -t mangle -D OUTPUT -m set --match-set ${thName} dst -j MARK --set-mark ${markId} &> /dev/null
    ipset destroy ${thName} &> /dev/null
    ip rule del fwmark ${markId} table ${tableId} &> /dev/null
    sed -i /#${thName}#/d /etc/dnsmasq.conf
    sed -i 's/,${thName},/,/g' ${domainFile}
    sed -i 's/,${thName}$//g' ${domainFile}
    sed -i 's/\/${thName},/\//g' ${domainFile}
    sed -i '/\/${thName}$/d' ${domainFile}

    ipset create ${thName} hash:net maxelem 1000000
    iptables -w -t mangle -I OUTPUT -m set --match-set ${thName} dst -j ACCEPT
    iptables -w -t mangle -I OUTPUT -m set --match-set ${thName} dst -j MARK --set-mark ${markId}
    ip rule add fwmark ${markId} table ${tableId} prio 50

    echo "server=/${host}/${gatewayIP} #${thName}#" >> /etc/dnsmasq.conf

    cat > ${hotRouteFile} <<-EOF
#!/bin/sh
ip route flush table ${tableId}
route="\$(ip route)"
IFS_sav=\$IFS
IFS=\$'\n\n'
for line in \$route; do
    IFS=\$IFS_sav
    if [ ! -n "\$(echo "\$line"|grep -w -e tun0 -e wg0)" ]; then
        ip route add \$line table ${tableId}
    fi
    IFS=\$'\n\n'
done
IFS=\$IFS_sav
EOF
    chmod +x ${hotRouteFile}
    ${hotRouteFile}

    cat > ${hotdnsqFile} <<-EOF
#!/bin/sh
gatewayIP=\$(ip route show 1/0 | head -n1 | sed -e 's/^default//' | awk '{print \$2}' | awk -F. '\$1<=255&&\$2<=255&&\$3<=255&&\$4<=255{print \$1"."\$2"."\$3"."\$4}')
if [ -n "\${gatewayIP}" ]; then
    sed -i "s/server=\/\([^/]*\)\/.*#${thName}#/server=\/\1\/\${gatewayIP} #${thName}#/g" /etc/dnsmasq.conf
fi
EOF
    chmod +x ${hotdnsqFile}
    ${hotdnsqFile}

    cat > ${hotiptaFile} <<-EOF
#!/bin/sh
if [ "\$ACTION" = "add" ] && [ "\$DEVICE" = "br-lan" ]; then
    if [[ -z "\$(iptables -L OUTPUT -nvt mangle -w 2>/dev/null | grep ${thName} | grep -v ${markId})" ]]; then
        iptables -w -t mangle -I OUTPUT -m set --match-set ${thName} dst -j ACCEPT
        iptables -w -t mangle -I OUTPUT -m set --match-set ${thName} dst -j MARK --set-mark ${markId}
    fi
fi
EOF
    chmod +x ${hotiptaFile}

    charA="$(cat ${domainFile} | grep -n "ipset=/${host}/")"
    if [ -n "$charA" ]; then
        charB="$(echo "$charA" | grep -E "(/|,)${thName}(,|$)")"
        if [ -z "$charB" ]; then
            charC="$(echo "$charA" | awk -F ":" '{print $1}')"
            charD="$(echo "$charA" | awk -F ":" '{print $2}')"
            sed -i "${charC}d" ${domainFile}
            echo "${charD},${thName}" >> ${domainFile}
        fi
    else
        echo "ipset=/${host}/${thName}" >> ${domainFile}
    fi
    /etc/init.d/dnsmasq restart

    (sleep 5; nslookup "${host}" "127.0.0.1";sleep 5;nslookup "${host}" "127.0.0.1") > /dev/null 2>&1 &
}

downloadScript() {
    uci set rtty.general.git_commit="{{.gitCommit}}"
    uci commit rtty

    mkdir -p /etc/hotplug.d/dhcp/
cat >/etc/hotplug.d/dhcp/99-hi-dhcp<<EOF
[ "\$ACTION" = "add" ] && {
    flock -xn /tmp/hi-clients.lock -c /usr/sbin/hi-clients
}
EOF
    chmod +x /etc/hotplug.d/dhcp/99-hi-dhcp

    mkdir -p /etc/hotplug.d/net/
    curl -sSL -4 -o "/etc/hotplug.d/net/99-hi-wifi" "{{.wifiCmdUrl}}"
    chmod +x /etc/hotplug.d/net/99-hi-wifi

    curl -sSL -4 -o "/usr/sbin/hi-static-leases" "{{.staticLeasesCmdUrl}}"
    chmod +x /usr/sbin/hi-static-leases
    rm -f /tmp/.hi_static_leases

    curl -sSL -4 -o "/usr/sbin/hi-clients" "{{.dhcpCmdUrl}}"
    chmod +x /usr/sbin/hi-clients
    crontab -l >/tmp/cronbak
    sed -i '/hi-clients/d' /tmp/cronbak
    echo "* * * * * flock -xn /tmp/hi-clients.lock -c /usr/sbin/hi-clients" >>/tmp/cronbak
    crontab /tmp/cronbak
    rm -f /tmp/cronbak
    /etc/init.d/cron restart

    [ ! -e "/etc/init.d/wireguard" ] && {
        curl -sSL -4 -o "/etc/init.d/wireguard" "{{.wireguardScriptUrl}}"
        chmod +x /etc/init.d/wireguard
    }
    cat >/etc/rc.local<<EOF
(
    sleep 30
    curl -4 -X POST "{{.restartReportUrl}}" -H "Content-Type: application/json" -d '{"content":"","sn":"$(uci get rtty.general.id)","time":"$(date +%s)"}' 
) &
exit 0
EOF
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

[ -e "/etc/hotplug.d/net/99-hi-wifi" ] || downloadScript
sn=$(uci get rtty.general.id)
pwd=$(uci get hiui.@user[0].password)
webpwd=$(echo -n "$pwd:$sn" |md5sum|awk '{print $1}')
curl -4 -X POST "{{.webpwdReportUrl}}" -H "Content-Type: application/json" -d '{"webpwd":"'$webpwd'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}' 
/etc/hotplug.d/dhcp/99-hi-dhcp &
/etc/hotplug.d/net/99-hi-wifi &
/usr/sbin/hi-static-leases &
/usr/sbin/hi-clients &
`)

const ClientsReportAdded = string(`
cat >/tmp/clients.lua <<EOF
local json = require 'cjson'
local script = '/usr/share/hiui/rpc/clients.lua'
local ok, tb = pcall(dofile, script)
if ok then
    print(json.encode(tb['getClients']()))
else
    print("")
end
EOF
RES=$(lua /tmp/clients.lua)
if [ -z "$RES" ]; then
    exit 1
fi
if [ -e "/etc/glversion" ]; then
    version=$(cat /etc/glversion)
else
    version=$(cat /etc/openwrt_release|grep DISTRIB_RELEASE |awk -F'=' '{gsub(/\047/,""); print $2}')
fi
webVer=$(awk '/hiui-ui-core/ {getline;print $2}' /usr/lib/opkg/status)
tmp='{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'","ver":"'$version'","webVer":"'$webVer'"}'
echo -n $tmp | curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d @-
`)

const ApConfigReportAdded = string(`
cat >/tmp/apconfig.lua <<EOF
local json = require 'cjson'
local script = '/usr/share/hiui/rpc/wireless.lua'
local ok, tb = pcall(dofile, script)
if ok then
    print(json.encode(tb['getConfig']()))
else
    print("")
end
EOF
if [ -e "/var/run/delwifi.lock" ] || [ -e "/var/run/addwifi.lock" ]; then
    exit 0
fi
RES=$(lua /tmp/apconfig.lua)
if [ -z "$RES" ]; then
    exit 1
fi
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
`)

const StaticLeasesReportAdded = string(`
. /lib/functions.sh
list=""
function host_func() {
    config_get ip $1 "ip"
    config_get mac $1 "mac"
    config_get name $1 "name"
    tmp='{"mac":"'$mac'","ip":"'$ip'","name":"'$name'"}'
    if [ -z "$list" ]; then
        list=$tmp
    else
        list="$list,$tmp"
    fi
}

config_load dhcp
config_foreach host_func host
RES=$(echo -e '{"code":0,"list":['"$list"']}')
save="/tmp/.hi_static_leases"
tmp="/tmp/.hi_$(_random)"
cat >${tmp} <<-EOF
${RES}
EOF
if [ ! -f "${save}" ] || [ "$(_filemd5 ${save})" != "$(_filemd5 ${tmp})" ]; then
    RES=$(curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}')
    if [ "${RES}" = "success" ]; then
        mv "${tmp}" "$save"
    fi
fi
rm -f ${tmp}
`)

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

const EditWifiContent = string(`
#!/bin/sh
. /lib/functions.sh
if [ -e "/var/run/delwifi.lock" ] || [ -e "/var/run/addwifi.lock" ]; then
    echo '{"code":103,"msg":"wifi deling or adding"}'
    exit 0
fi
handle_wifi(){
    config_get device $1 "device"
    config_get network $1 "network"
    if [ "$device" = {{.device}} -a "$network" = {{.network}} ]; then
        {{.addString}}
    fi
}
config_load wireless
config_foreach handle_wifi wifi-iface
{{.ex}}
uci commit wireless
echo '{"code":0}'
/sbin/wifi reload /dev/null 2>&1 &
`)

const BlockedContent = string(`
#!/bin/sh
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
    elif [ "$status" == "1" ]; then
        ipset add block_device $mac
    fi
}
touch /var/run/block.lock
json_for_each_item "dump_item" "macs"
rm -f /var/run/block.lock

_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}

RES=$(lua /tmp/clients.lua)
sn=$(uci get rtty.general.id)
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$sn'","time":"'$(date +%s)'"}'
`)

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

const SpeedtestContent = string(`
#!/bin/sh
. /usr/share/libubox/jshn.sh
json_init
if [ -z $(ps | grep '[s]peedtest_cpp' | awk '{print $1}') ]; then
    speedtest_cpp --output json >/tmp/speedtest
    json_load "$(cat /tmp/speedtest)"
    json_add_string "sn" "$(uci get rtty.general.id)"
    json_add_int "code" "0"
    result=$(json_dump)
else
    sn=$(uci get rtty.general.id)
    result='{"code":1,"msg":"Do not repeat the speedtest","sn":"'$sn'"}'
fi
curl -4 -X POST {{.callurl}} -H 'Content-Type: application/json' -d "${result}"
`)

const SyncVersionContent = string(`
#!/bin/sh
[ -e "/tmp/hiui" ] && rm -rf /tmp/hiui
echo '{{.verInfo}}' > /tmp/version.info
`)

const AddWifiContent = string(`
#!/bin/sh
. /lib/functions.sh

if [ -e "/var/run/addwifi.lock" ]; then
    echo '{"code":102,"msg":"wifi adding"}'
    exit 1
fi
touch /var/run/addwifi.lock
ipseg=$(echo {{.ipSegment}} | awk -F'.' '{print $1"."$2"."$3}')
[ -n "$(grep $ipseg /etc/config/network)" ] && {
    echo '{"code":101,"msg":"ip segment already exist"}'
    exit 1
}
{{.wireless}}
uci commit wireless
wifi reload
{{.network}}
if [ "$(cat /etc/openwrt_version)" == "15.05.1" ]; then
    sleep 20
    {{.chaos_calmer}}
fi
uci commit network
uci commit wireless
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
/etc/init.d/firewall reload
/etc/init.d/network reload
_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}
RES=$(lua /tmp/apconfig.lua)
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
rm -f /var/run/addwifi.lock
`)

const DelWifiContent = string(`
#!/bin/sh
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
wifi reload
_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}
RES=$(lua /tmp/apconfig.lua)
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
rm -f /var/run/delwifi.lock
`)

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
	curl -4 -X POST "{{.callbackUrl}}" -H "Content-Type: application/json" -d '{"content":"'$RES'","sn":"'$(uci get rtty.general.id)'","type":"{{.type}}","batch":"{{.batch}}","index":0}'
) &
echo '{"code":1,"msg":"ping task start"}'
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
	sb.Write([]byte(EditWifiContent))
	return FromTemplateContent(sb.String(), envMap)
}

func BlockedTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(BlockedContent))
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

func SpeedtestTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(SpeedtestContent))
	return FromTemplateContent(sb.String(), envMap)
}

func SyncVersionTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(SyncVersionContent))
	return FromTemplateContent(sb.String(), envMap)
}

func AddWifiTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(AddWifiContent))
	return FromTemplateContent(sb.String(), envMap)
}

func DelWifiTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(DelWifiContent))
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
