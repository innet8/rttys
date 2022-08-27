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
if [ -z "${gatewayIP}" ];then
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
    if [[ -z ` + "`iptables -L shunt-1 -t mangle 2>/dev/null | grep shunt-1`" + ` ]]; then
        for i in ` + "`seq 1 80`" + `; do
            iptables -t mangle -N shunt-${i}
            iptables -t mangle -A PREROUTING -j shunt-${i}
        done
    fi
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

exec_shunt_url() {
    local url=$1
    local save=$2
    local tmp="/tmp/.hi_$(_random)"
    curl -sSL -4 -o "${tmp}" "${url}"
    if [ ! -f "${tmp}" ];then
        echo "Failed download exec file '$url'"
        exit 1
    fi
    if [ "$(_filemd5 ${save})" = "$(_filemd5 ${tmp})" ]; then
        rm -f "${tmp}"
        echo "Same file skips exec '$url' '$save'"
    else
        if [ -f "$save" ];then
            bash $save remove
            rm -f "${save}"
        fi
        mv "${tmp}" "$save"
        if [ ! -f "$save" ];then
            echo "Failed to move file '$url' '$save'"
            exit 2
        fi
        bash $save
    fi
}

{{.cmds}}
`)

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
    if [ -f "$1" ];then
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
        if [ -n "$(wg)" ]; then
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
        if [ -z "$(wg)" ]; then
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
    RES=$(curl -X POST "http://127.0.0.1/cgi-bin/api/router/setlanip" -H "Authorization: $(_localtoken)" -d "newip=$1&start=20&end=240")
    EXI=$(echo "$RES" | grep '.code')
    if [ -z "$EXI" ]; then
        echo -n "error"
    else
        echo -n "ok"
    fi
}

_get_static_leases() {
    local list=""
    for mac_str in $(cat /etc/config/dhcp | grep '\<host\>' | awk '{print $3}' | sed -r "s/'//g"); do
        tmp='{"mac":"'$(uci get dhcp.$mac_str.mac 2>/dev/null)'","ip":"'$(uci get dhcp.$mac_str.ip 2>/dev/null)'","name":"'$(uci get dhcp.$mac_str.name 2>/dev/null)'"}'
        if [ -z "$list" ]; then
            list=$tmp
        else
            list="$list,$tmp"
        fi
    done
    echo -e '{"code":0,"list":['"$list"']}'
}
`)

const WireguardContent = string(`
clear_wireguard_conf() {
    cat > /etc/config/wireguard <<-EOF
config proxy
  option enable '0'
EOF
    rm -f /etc/config/wireguard_back
    _wgstop
}

set_wireguard_conf() {
    cat >/etc/config/wireguard_back <<-EOF
{{.conf}}
EOF
    cat /etc/config/wireguard_back > /etc/config/wireguard
    _wgstart
}

set_lan_ip() {
    if [ "$(uci get network.lan.ipaddr)" != "{{.lan_ip}}" ]; then
        (
            sleep 2
            _edit_lan "{{.lan_ip}}"
        ) >/dev/null 2>&1 &
    fi
}
`)

const WireguardConfExampleContent = string(`
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

git_commit=$(uci get rtty.general.git_commit 2>/dev/null)
if [ "${git_commit}" != "{{.gitCommit}}" ];then
    uci set rtty.general.git_commit="{{.gitCommit}}"
    uci commit rtty

    mkdir -p /etc/hotplug.d/dhcp/
    curl -sSL -4 -o "/etc/hotplug.d/dhcp/99-hi-dhcp" "{{.dhcpCmdUrl}}"
    chmod +x /etc/hotplug.d/dhcp/99-hi-dhcp

    mkdir -p /etc/hotplug.d/net/
    curl -sSL -4 -o "/etc/hotplug.d/net/99-hi-wifi" "{{.wifiCmdUrl}}"
    chmod +x /etc/hotplug.d/net/99-hi-wifi

    curl -sSL -4 -o "/etc/init.d/hi-static-leases" "{{.staticLeasesCmdUrl}}"
    chmod +x /etc/init.d/hi-static-leases
    crontab -l >/tmp/cronbak
    sed -i '/\/etc\/init.d\/hi-static-leases/d' /tmp/cronbak
    sed -i '/^$/d' /tmp/cronbak
    echo "* * * * * sh /etc/init.d/hi-static-leases" >>/tmp/cronbak
    crontab /tmp/cronbak
    rm -f /tmp/cronbak
    /etc/init.d/cron enable
    /etc/init.d/cron restart
fi

/etc/hotplug.d/dhcp/99-hi-dhcp &
/etc/hotplug.d/net/99-hi-wifi &
/etc/init.d/hi-static-leases &
`)

const ApiReportContent = string(`
RES=$(curl "{{.requestUrl}}" -H "Authorization: $(_localtoken)")
curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(get_default_sn)'","time":"'$(date +%s)'"}'
`)

const StaticLeasesReportContent = string(`
RES=$(_get_static_leases)
save="/tmp/.hi_static_leases"
tmp="/tmp/.hi_$(_random)"
cat >${tmp} <<-EOF
${RES}
EOF
if [ -f "${save}" ] && [ "$(_filemd5 ${save})" != "$(_filemd5 ${tmp})" ]; then
    RES=$(curl -4 -X POST "{{.reportUrl}}" -H "Content-Type: application/json" -d '{"content":"'$(_base64e "$RES")'","sn":"'$(get_default_sn)'","time":"'$(date +%s)'"}')
    if [ "${RES}" = "success" ];then
        mv "${tmp}" "$save"
    fi
fi
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
if [ -f "/etc/init.d/hi-static-leases" ];then
    /etc/init.d/hi-static-leases &
fi
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
	sb.Write([]byte(ShuntDomainContent))
	return FromTemplateContent(sb.String(), envMap)
}

func ShuntTemplate(envMap map[string]interface{}) string {
	var sb strings.Builder
	sb.Write([]byte(ShuntContent))
	return FromTemplateContent(sb.String(), envMap)
}

func ShuntBatchTemplate(envMap map[string]interface{}) string {
	text := fmt.Sprintf("%s\n%s", CommonUtilsContent, ShuntBatchContent)
	var sb strings.Builder
	sb.Write([]byte(text))
	return FromTemplateContent(sb.String(), envMap)
}

func WireguardTemplate(envMap map[string]interface{}) string {
	text := fmt.Sprintf("%s\n%s", CommonUtilsContent, WireguardContent)
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
	if envMap["requestUrl"] == "static_leases" {
		text = fmt.Sprintf("%s\n%s", CommonUtilsContent, StaticLeasesReportContent)
	} else {
		text = fmt.Sprintf("%s\n%s", CommonUtilsContent, ApiReportContent)
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
