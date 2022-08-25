package hi

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"text/template"
)

const ShuntDomainContent = string(`
for D in ` + "`cat ${DOMAINFILE} 2>/dev/null`" + `; do
    sed -i "/^server=/${D}/*/d" /etc/dnsmasq.conf
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
for D in ` + "`cat ${DOMAINFILE} 2>/dev/null`" + `; do (nslookup $D > /dev/null 2>&1 &); done
`)

const ShuntContent = string(`
#!/bin/bash
ACTION=$1
DNSFILE="/etc/dnsmasq.d/domain_hicloud.conf"
LOGFILE="/tmp/hicloud/shunt/{{.th}}.log"
DOMAINFILE="/tmp/hicloud/shunt/{{.th}}.domain"

mkdir -p /tmp/hicloud/shunt

echo "start: $(date "+%Y-%m-%d %H:%M:%S")" > ${LOGFILE}

if [ ! -f "$DNSFILE" ]; then
    touch $DNSFILE
fi

echo "remove" >> ${LOGFILE}
{{.removeString}}
sed -i /#{{.th}}#/d /etc/dnsmasq.conf
sed -i 's/,{{.th}},/,/g' ${DNSFILE}
sed -i 's/,{{.th}}$//g' ${DNSFILE}
sed -i 's/\/{{.th}},/\//g' ${DNSFILE}
sed -i '/\/{{.th}}$/d' ${DNSFILE}

if [ -z "${ACTION}" ]; then
    echo "install" >> ${LOGFILE}
    if [[ -z ` + "`iptables -L shunt-1 -t mangle 2>/dev/null | grep shunt-1`" + ` ]]; then
        for i in ` + "`seq 1 80`" + `; do
            iptables -t mangle -N shunt-${i}
            iptables -t mangle -A PREROUTING -j shunt-${i}
        done
    fi
    localGwIp=$(ip route show 1/0 | head -n1 | sed -e 's/^default//' | awk '{print $2}')
    {{.installString}}
fi
echo "end" >> ${LOGFILE}

exit 0
`)

const ShuntBatchContent = string(`
mkdir -p /tmp/hicloud/shunt

array=(
:{{.ths}}
)

for file in ` + "`ls /tmp/hicloud/shunt 2>/dev/null`" + `; do
    if [[ "${file}" =~ .*\.sh$ ]] && [[ ! "${array[@]}" =~ ":${file}" ]]; then
        bash +x /tmp/hicloud/shunt/${file} remove
        pathname="$(echo ${file} | sed 's/\.sh$//')"
        rm -f /tmp/hicloud/shunt/${pathname}.* &> /dev/null
    fi
done

{{.cmds}}
`)

const RouterUtilsContent = string(`
#!/bin/bash
. /lib/functions/gl_util.sh

_random() {
    echo -n $(date +%s) | md5sum | md5sum | cut -d ' ' -f 1
}

_localtoken() {
    [ -z "$token" ] && {
        token=$(_random)
    }
    [ ! -f "/tmp/gl_token_$token" ] && {
        echo "$token" >/tmp/gl_token_$token
    }
    echo -n "$token"
}

_downfile() {
    url=$1
    save=$2
    wget -q "$url" -O $save &>/dev/null
    if [ $? -ne 0 ]; then
        wget-ssl -q "$url" -O $save &>/dev/null
        if [ $? -ne 0 ]; then
            curl -4 -s -o $save "$url" &>/dev/null
        fi
    fi
}

_runfile() {
    url=$1
    save=$2
    _downfile "$url" "$save"
    if [ -f "$save" ];then
        bash $save
    else
        echo "Failed to download execution file '$url'"
        exit 1
    fi
}

_wgstart() {
    model=$(get_model)
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
        wgret=$(wg)
        if [ -n "$wgret" ]; then
            uci set wireguard.@proxy[0].enable="1"
            uci commit wireguard
            enable="1"
        fi
    fi
    if [ "$enable" = "1" ]; then
        if [ $(_wghotup) = "no" ]; then
            /bin/sh /etc/rc.common /etc/init.d/wireguard downup
        fi
        _wgconfirm downup
    else
        if [ -f "/etc/config/wireguard_back" ]; then
            cat /etc/config/wireguard_back > /etc/config/wireguard
        fi
        #
        uci set wireguard.@proxy[0].enable="1"
        uci commit wireguard
        /bin/sh /etc/rc.common /etc/init.d/wireguard start
        _wgconfirm start
    fi
}

_wgconfirm() {
    (
        sleep 3
        wgret=$(wg)
        if [ -z "$wgret" ]; then
            /bin/sh /etc/rc.common /etc/init.d/wireguard $1
        fi
    ) >/dev/null 2>&1 &
}

_wgstop() {
    /bin/sh /etc/rc.common /etc/init.d/wireguard stop
    uci set wireguard.@proxy[0].enable="0"
    uci commit wireguard
}

_wghotup() {
    ip address show wg0 &>/dev/null
    if [ $? -ne 0 ]; then
        echo "no"
        return
    fi
    #
    PeerName=""
    MainServer=$(uci get wireguard.@proxy[0].main_server)
    i=0
    while [ "$i" -le "100" ]; do
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
            ip route add "$AllowIPV4" dev wg0
        else
            ip route add 0/1 dev wg0
            ip route add 128/1 dev wg0
        fi
    else
        echo "no"
    fi
}

_edit_lan() {
    LOCALTOKEN=$(_localtoken)
    RES=$(curl --connect-timeout 10 -m 10 -H "Authorization: $LOCALTOKEN" "http://127.0.0.1/cgi-bin/api/router/setlanip" -X POST -d "newip=$1&start=20&end=240")
    EXI=$(echo "$RES" | grep '.code')
    if [ -z "$EXI" ]; then
        echo -n "error"
    else
        echo -n "ok"
    fi
}
`)

const RouterWireguardContent = string(`
_clear_wireguard_conf() {
    cat > /etc/config/wireguard <<-EOF
config proxy
  option enable '0'
EOF
    rm -f /etc/config/wireguard_back
}

_set_wireguard_conf() {
    cat >/etc/config/wireguard_back <<-EOF
{{.conf}}
EOF
    cat /etc/config/wireguard_back > /etc/config/wireguard
}

_set_lan_ip() {
    if [ "$(uci get network.lan.ipaddr)" != "{{.lan_ip}}" ]; then
        (
            sleep 2
            _edit_lan "{{.lan_ip}}"
        ) >/dev/null 2>&1 &
    fi
}
`)

const WireguardConfExampleContent = string(`config proxy
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
    option mtu '1360'`)

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
	sb.Write([]byte(ShuntDomainContent))
	return FromTemplateContent(sb.String(), envMap)
}

func ShuntTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(ShuntContent))
	return FromTemplateContent(sb.String(), envMap)
}

func ShuntBatchTemplate(envMap map[string]interface{}) string {
	text := fmt.Sprintf("%s\n%s", RouterUtilsContent, ShuntBatchContent)
	var sb strings.Builder
	sb.Write([]byte(text))
	return FromTemplateContent(sb.String(), envMap)
}

func RouterWireguardTemplate(envMap map[string]interface{}) string {
	text := fmt.Sprintf("%s\n%s", RouterUtilsContent, RouterWireguardContent)
	var sb strings.Builder
	sb.Write([]byte(text))
	return FromTemplateContent(sb.String(), envMap)
}
