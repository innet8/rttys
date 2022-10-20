package hi

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"text/template"
)

const CommonUtilsContent = string(`
#!/bin/bash
. /lib/functions/gl_util.sh

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

_localtoken() {
    token=$(ls /tmp/gl_token_* 2>/dev/null | awk 'END {print}' | awk -F '_' '{print $3}')
    [ -z "$token" ] && {
        token=$(_random)
    }
    [ ! -f "/tmp/gl_token_$token" ] && {
        echo "$token" >/tmp/gl_token_$token
    }
    echo -n "$token"
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
        #
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

wireguard_stop() {
    if [ -n "$(wg)" ]; then
        /bin/sh /etc/rc.common /etc/init.d/wireguard stop
    fi
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
    wireguard_stop
}

set_lanip() {
    if [ "$(uci get network.lan.ipaddr)" != "{{.lan_ip}}" ]; then
        (
            sleep 2
            uci set network.lan.ipaddr="{{.lan_ip}}"
            uci commit network
            sleep 2
            /etc/init.d/network restart
            [ -e "/usr/sbin/ssdk_sh" ] && {
                /etc/init.d/gl_tertf restart
                sleep 10; ssdk_sh debug phy set 2 0 0x840; ssdk_sh debug phy set 3 0 0x840
                sleep 5; ssdk_sh debug phy set 2 0 0x1240; ssdk_sh debug phy set 3 0 0x1240
            }
        ) >/dev/null 2>&1 &
    fi
}

set_hotdnsq() {
    rm -f /etc/hotplug.d/iface/100-hi-bypass-dnsmasq    # 下次更新删除这行
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
    rm -f /etc/hotplug.d/iface/100-hi-bypass-dnsmasq    # 下次更新删除这行
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
    fi
    if [[ -z "\$(iptables -L OUTPUT -nvt mangle -w 2>/dev/null | grep ${thName} | grep ${markId})" ]]; then
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

set_bypass_host "{{.apiHost}}" &

git_commit=$(uci get rtty.general.git_commit 2>/dev/null)
onlyid=$(uci get rtty.general.onlyid)
if [ "${git_commit}" != "{{.gitCommit}}" ] || [ "${onlyid}" != "{{.onlyid}}" ]; then
    uci set rtty.general.git_commit="{{.gitCommit}}"
    uci commit rtty

    mkdir -p /etc/hotplug.d/dhcp/
    curl -sSL -4 -o "/etc/hotplug.d/dhcp/99-hi-dhcp" "{{.dhcpCmdUrl}}"
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
fi

/etc/hotplug.d/dhcp/99-hi-dhcp &
/etc/hotplug.d/net/99-hi-wifi &
/usr/sbin/hi-static-leases &
/usr/sbin/hi-clients &
`)

// ApiReportAdded todo 上报终端列表时处理一下同个ip只保留最新的mac地址
const ApiReportAdded = string(`
RES=$(curl "{{.requestUrl}}" -H "Authorization: $(_localtoken)")
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'
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
    RES=$(curl "{{.requestUrl}}" -H "Authorization: $(_localtoken)")
fi
if [ -e "/etc/glversion" ]; then
    version=$(cat /etc/glversion)
else
    version=$(cat /etc/openwrt_release|grep DISTRIB_RELEASE |awk -F'=' '{gsub(/\047/,""); print $2}')
fi
webVer=$(awk '/hiui-ui-core/ {getline;print $2}' /usr/lib/opkg/status)
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'","ver":"'$version'","webVer":"'$webVer'"}'
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
RES=$(lua /tmp/apconfig.lua)
if [ -z "$RES" ]; then
    RES=$(curl "{{.requestUrl}}" -H "Authorization: $(_localtoken)")
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
/sbin/wifi reload
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
echo '{{.verInfo}}' > /tmp/version.info
`)

const AddWifiContent = string(`
#!/bin/sh
. /lib/functions.sh

ipseg=$(echo {{.ipSegment}} | awk -F'.' '{print $1"."$2"."$3}')
[ -n "$(grep $ipseg /etc/config/network)" ] && {
    echo '{"code":101,"msg":"ipsegment already exist"}'
    exit 0
} 
uci set wireless.{{.wifinet}}=wifi-iface
uci set wireless.{{.wifinet}}.device='{{.device}}'
uci set wireless.{{.wifinet}}.mode='ap'
uci set wireless.{{.wifinet}}.ssid='{{.ssid}}'
uci set wireless.{{.wifinet}}.encryption='{{.encryption}}'
uci set wireless.{{.wifinet}}.key='{{.key}}'
uci commit wireless
wifi reload
slee 3
device=$(iwinfo | grep {{.ssid}} | awk '{print $1}')
uci set network.{{.wifinet}}=interface
uci set network.{{.wifinet}}.proto='static'
uci set network.{{.wifinet}}.ipaddr='{{.ipSegment}}'
uci set network.{{.wifinet}}.netmask='255.255.255.0'
uci commit network
uci set wireless.{{.wifinet}}.network='{{.wifinet}}'
uci commit wireless

handle_firewall(){
    local tmp=$1
    config_get name "$1" "name"
    if [ "$name" == "lan" ]; then
        [ -z "$(grep {{.wifinet}} /etc/config/firewall)" ] && uci add_list firewall.$tmp.network='{{.wifinet}}'
    fi
}
config_load firewall
config_foreach handle_firewall zone
uci commit firewall

uci set dhcp.{{.wifinet}}=dhcp
uci set dhcp.{{.wifinet}}.interface='{{.wifinet}}'
uci set dhcp.{{.wifinet}}.start='100'
uci set dhcp.{{.wifinet}}.limit='150'
uci set dhcp.{{.wifinet}}.leasetime='12h'
uci commit dhcp

/etc/init.d/firewall reload
/etc/init.d/network reload

_base64e() {
    echo -n "$1" | base64 | tr -d "\n"
}
RES=$(lua /tmp/apconfig.lua)
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(uci get rtty.general.id)'","time":"'$(date +%s)'"}'

`)

const DelWifiContent = string(`
#!/bin/sh
uci delete dhcp.{{.wifinet}}
uci delete network.{{.wifinet}}
uci delete wireless.{{.wifinet}}
sed -i '/{{.wifinet}}/d' /etc/config/firewall
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
