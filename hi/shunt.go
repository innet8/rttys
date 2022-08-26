package hi

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// GetCmdBatch 获取批量分流脚本
func GetCmdBatch(apiUrl string, Shunts []ShuntInfo) string {
	var cmds []string
	var ths []string
	for _, Shunt := range Shunts {
		th := fmt.Sprintf("hi-th-%d", Shunt.ID)
		cmds = append(cmds, fmt.Sprintf("_runfile \"%s/hi/shunt/cmd/%d\" \"/tmp/hicloud/shunt/%s.sh\"", apiUrl, Shunt.ID, th))
		ths = append(ths, fmt.Sprintf("%s.sh", th))
	}
	var envMap = make(map[string]interface{})
	envMap["cmds"] = strings.Join(cmds, "\n")
	envMap["ths"] = strings.Join(ths, ":\n")
	return ShuntBatchTemplate(envMap)
}

// GetCmd 获取分流脚本
func GetCmd(apiUrl string, Shunt ShuntInfo) string {
	th := fmt.Sprintf("hi-th-%d", Shunt.ID)
	id16 := strconv.FormatInt(int64(Shunt.ID), 16)
	table := Shunt.ID%10000 + 10000
	prio := Shunt.Prio
	if prio == 0 {
		prio = 50
	}
	//
	sources := String2Array(Shunt.Source)
	rules := String2Array(Shunt.Rule)
	dnsIp := "${localGwIp}"
	//
	var install []string
	var remove []string
	//
	install = append(install, fmt.Sprintf("ip rule add fwmark 0x%s/0xffffffff table %d prio %d", id16, table, prio))
	if Shunt.Out == "blackhole" {
		install = append(install, fmt.Sprintf("ip route add blackhole default table %d", table))
	} else if IsIp(Shunt.Out) {
		install = append(install, fmt.Sprintf("ip route add default via %s table %d", Shunt.Out, table))
		dnsIp = Shunt.Out
	} else {
		install = append(install, fmt.Sprintf("ip route add default via ${localGwIp} table %d", table))
	}
	if len(rules) > 0 {
		install = append(install, fmt.Sprintf("ipset create %s hash:net maxelem 1000000", th))
		var domain []string
		for _, rule := range rules {
			if IsCidr(rule) {
				install = append(install, fmt.Sprintf("ipset add %s %s", th, rule))
			} else if IsDomain(rule) {
				domain = append(domain, rule)
			}
		}
		for _, source := range sources {
			if source == "all" {
				source = "${localGwIp}/24"
			}
			if strings.Contains(source, "-") {
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -m iprange --src-range %s -m set --match-set %s dst -j ACCEPT", prio, source, th))
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -m iprange --src-range %s -m set --match-set %s dst -j MARK --set-xmark 0x%s/0xffffffff", prio, source, th, id16))
			} else {
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -s %s -m set --match-set %s dst -j ACCEPT", prio, source, th))
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -s %s -m set --match-set %s dst -j MARK --set-xmark 0x%s/0xffffffff", prio, source, th, id16))
			}
		}
		if len(domain) > 0 {
			install = append(install, fmt.Sprintf("curl -sSL \"%s/hi/shunt/domain/%d\" | sh", apiUrl, Shunt.ID))
			var envMap = make(map[string]interface{})
			envMap["dnsIp"] = dnsIp
			envMap["th"] = th
			install = append(install, ShuntDomainTemplate(envMap))
		}
	} else {
		for _, source := range sources {
			if source == "all" {
				source = "${localGwIp}/24"
			}
			if strings.Contains(source, "-") {
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -m iprange --src-range %s -j ACCEPT", prio, source))
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -m iprange --src-range %s -j MARK --set-xmark 0x%s/0xffffffff", prio, source, id16))
			} else {
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -s %s -j ACCEPT", prio, source))
				install = append(install, fmt.Sprintf("iptables -t mangle -I shunt-%d -s %s -j MARK --set-xmark 0x%s/0xffffffff", prio, source, id16))
			}
		}
	}
	installString := strings.ReplaceAll(strings.Join(install, "\n"), "\n", "\n    ")
	//
	tmps := make(map[string]string)
	array := strings.Split(installString, "\n")
	for index, item := range array {
		item = strings.Trim(item, " ")
		if strings.HasPrefix(item, "ip rule add") {
			tmps[fmt.Sprintf("a_%d", index)] = RegexpReplace(`^\s*ip rule add(.*?)$`, item, "ip rule del$1 &> /dev/null")
		} else if strings.HasPrefix(item, "ip route add") {
			tmps[fmt.Sprintf("b_%d", index)] = RegexpReplace(`^\s*ip route add(.*?)$`, item, fmt.Sprintf("ip route del default table %d &> /dev/null", table))
		} else if strings.HasPrefix(item, "iptables -t mangle -I") {
			tmps[fmt.Sprintf("c_%d", index)] = RegexpReplace(`^\s*iptables -t mangle -I(.*?)$`, item, "iptables -t mangle -D$1 &> /dev/null")
		} else if strings.HasPrefix(item, fmt.Sprintf("ipset create %s", th)) {
			tmps[fmt.Sprintf("d_%d", index)] = RegexpReplace(fmt.Sprintf(`^\s*ipset create %s(.*?)$`, th), item, fmt.Sprintf("ipset destroy %s &> /dev/null", th))
		}
	}
	var keys []string
	for k := range tmps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		remove = append(remove, tmps[k])
	}
	removeString := strings.Join(remove, "\n")
	//
	var envMap = make(map[string]interface{})
	envMap["outIp"] = Shunt.Out
	envMap["installString"] = installString
	envMap["removeString"] = removeString
	envMap["th"] = th
	return ShuntTemplate(envMap)
}

// GetDomain 获取域名脚本
func GetDomain(Shunt ShuntInfo) string {
	th := fmt.Sprintf("hi-th-%d", Shunt.ID)
	var install []string
	var domain []string
	rules := String2Array(Shunt.Rule)
	if len(rules) > 0 {
		for _, rule := range rules {
			if IsDomain(rule) {
				domain = append(domain, rule)
			}
		}
	}
	if len(domain) > 0 {
		install = append(install, fmt.Sprintf("cat > /tmp/hicloud/shunt/%s.domain <<-EOF", th))
		install = append(install, strings.Join(domain, "\n"))
		install = append(install, "EOF")
	} else {
		install = append(install, `# echo "Domain not exist"`)
	}
	installString := strings.Join(install, "\n")
	return fmt.Sprintf("#!/bin/sh\n%s", installString)
}
