package hi

import (
	"bytes"
	"log"
	"strings"
	"text/template"
)

const ShuntDomainContent = string(`
for D in ` + "`cat ${DOMAINFILE} 2>/dev/null`" + `; do
    sed -i '/^server=/${D}/*/d' /etc/dnsmasq.conf
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
#!/bin/sh
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
    if [ -z ` + "`iptables -L shunt-1 -t mangle 2>/dev/null | grep shunt-1`" + ` ]; then
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
