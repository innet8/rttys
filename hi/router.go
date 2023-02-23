package hi

import (
	"encoding/json"
	"fmt"
	"strings"
)

type StaticLeasesModel struct {
	Mac  string `json:"mac"`
	Ip   string `json:"ip"`
	Name string `json:"name"`
}

type WifiModel struct {
	Name       string `json:".name"`
	Device     string `json:"device"`
	Ssid       string `json:"ssid"`
	Key        string `json:"key"`
	Channel    string `json:"channel"`
	Encryption string `json:"encrypt"`
	Disabled   string `json:"disabled"` // 1-关；0-开
	Hidden     string `json:"hidden"`
	Network    string `json:"network"`
}

type AddWifiModel struct {
	Device     string `json:"device"`
	Ssid       string `json:"ssid"`
	Key        string `json:"key"`
	Wifinet    string `json:"wifinet"`
	Encryption string `json:"encryption"`
	Hidden     string `json:"hidden"`
	IpSegment  string `json:"ipSegment"`
}

type DeleteWifiModal struct {
	Wifinets []string `json:"wifinet"`
}

type QosModal struct {
	Mac string `json:"mac"`
	Ul  string `json:"upload"`
	Dl  string `json:"download"`
}

func IpkUpgradeCmd(remotePath string, verUrl string) string {
	var envMap = make(map[string]interface{})
	envMap["remotePath"] = remotePath
	envMap["verUrl"] = verUrl
	return IpkRemoteUpgradeTemplate(envMap)
}

func FirmwareUpgradeCmd(path string) string {
	var cmds []string
	cmds = append(cmds, "#!/bin/sh")
	cmds = append(cmds, fmt.Sprintf("curl -4 -s -o /tmp/firmware.img '%s' >/dev/null", path))
	cmds = append(cmds, "sysupgrade /tmp/firmware.img ")
	return strings.Join(cmds, "\n")
}

func VersionCmd(name string) string {
	return GetVersion(name)
}

func WireguardCmd(wg WgModel) string {
	var cmds []string
	//
	var envMap = make(map[string]interface{})
	envMap["wg_conf"] = wg.Conf
	envMap["lan_ip"] = wg.LanIp
	envMap["dns_server"] = wg.DnsServer
	cmds = append(cmds, WireguardTemplate(envMap))
	//
	if wg.ID == 0 {
		// 关闭wg
		cmds = append(cmds, "clear_wireguard_conf")
	} else {
		// 开启wg
		if IsIp(wg.LanIp) {
			// 设置lan
			cmds = append(cmds, "set_lanip")
		}
		cmds = append(cmds, "set_wireguard_conf")
	}
	if IsIp(wg.DnsServer) {
		// 设置dns服务器ip
		cmds = append(cmds, "set_hotdnsq")
	} else {
		// 取消dns服务器ip
		cmds = append(cmds, "clear_hotdnsq")
	}
	return strings.Join(cmds, "\n")
}

func StaticLeasesCmd(list []StaticLeasesModel) string {
	var cmds []string
	//
	for _, item := range list {
		if IsIp(item.Ip) {
			name := RandString(6)
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.%s=host", name))
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.%s.name=\"%s\"", name, item.Name))
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.%s.ip=\"%s\"", name, item.Ip))
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.%s.mac=\"%s\"", name, item.Mac))
		}
	}
	var envMap = make(map[string]interface{})
	envMap["addString"] = strings.Join(cmds, "\n")
	return SetStaticLeasesTemplate(envMap)
}

func BlockedCmd(list []string, action string, url string) string {
	newList := map[string]interface{}{
		"macs": list,
	}
	var cmds, err = json.Marshal(newList)
	if err != nil {
		return ""
	}
	var envMap = make(map[string]interface{})
	envMap["macs"] = string(cmds)
	envMap["action"] = action
	envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/dhcp", url)
	return BlockedTemplate(envMap)
}

// ApiResultCheck 验证路由器接口返回内容是否正确（不正确返回空）
func ApiResultCheck(result string) string {
	type RouterClientsModel struct {
		Code int `json:"code"`
	}
	var data RouterClientsModel
	if ok := json.Unmarshal([]byte(result), &data); ok == nil {
		if data.Code == 0 {
			return result
		}
	}
	return ""
}

// EditWifiCmd wifi修改
func EditWifiCmd(wifi WifiModel, reportUrl, token string) string {
	var cmds []string
	var chaos_calmer []string
	if wifi.Ssid != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.ssid=%s", wifi.Ssid))
	}
	if wifi.Key != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.key=%s", wifi.Key))
	}
	if wifi.Encryption != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.encryption=%s", wifi.Encryption))
	}
	if wifi.Hidden != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.hidden=%s", wifi.Hidden))
	}
	if wifi.Disabled != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.disabled=%s", wifi.Disabled))
	}
	if wifi.Device != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.device=%s", wifi.Device))
	}
	chaos_calmer = append(chaos_calmer, "device=$(cat $(grep -l \"ssid=${ssid}$\" /var/run/*.conf ) | awk -F= '$1==\"interface\" {print $2}')")
	chaos_calmer = append(chaos_calmer, fmt.Sprintf("uci set network.%s.ifname=$device", wifi.Name))
	chaos_calmer = append(chaos_calmer, fmt.Sprintf("uci set wireless.%s.ifname=$device", wifi.Name))
	var envMap = make(map[string]interface{})
	envMap["addString"] = strings.Join(cmds, "\n")
	envMap["chaos_calmer"] = strings.Join(chaos_calmer, "\n")
	envMap["name"] = wifi.Name
	envMap["reportUrl"] = reportUrl
	envMap["token"] = token
	return EditWifiTemplate(envMap)
}

func FetchLogCmd(url, isManual, adminId string) string {
	var envMap = make(map[string]interface{})
	envMap["url"] = url
	envMap["isManual"] = isManual
	envMap["adminId"] = adminId
	return FetchLogTemplate(envMap)
}

func SyncVersionCmd(versions []VersionModel, description string) string {
	var vs = make(map[string]interface{})
	for _, v := range versions {
		if v.Description == description || v.Description == "" {
			vs[v.Type] = map[string]interface{}{
				"version": v.Version,
				"notes":   v.Notes,
				"url":     v.Url,
				"size":    v.Size,
				"md5":     v.Md5,
			}
		}
	}
	verInfo, _ := json.Marshal(vs)
	envMap := make(map[string]interface{})
	envMap["verInfo"] = string(verInfo)
	return SyncVersionTemplate(envMap)
}

// AddWifiCmd 添加WiFi命令
func AddWifiCmd(models []AddWifiModel, report, token string) string {
	var network []string
	var wireless []string
	var dhcp []string
	var firewall []string
	var chaos_calmer []string
	var openwrt []string
	var ipSegment []string
	for _, model := range models {
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s=wifi-iface", model.Wifinet))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.device=%s", model.Wifinet, model.Device))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.mode=ap", model.Wifinet))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.ssid='%s'", model.Wifinet, model.Ssid))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.encryption=%s", model.Wifinet, model.Encryption))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.hidden=%s", model.Wifinet, model.Hidden))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.key='%s'", model.Wifinet, model.Key))
		wireless = append(wireless, fmt.Sprintf("uci set wireless.%s.network=%s", model.Wifinet, model.Wifinet))
		ipSegment = append(ipSegment, fmt.Sprintf("[ -n \"$(ip=%s;grep ${ip%%.*} /etc/config/network)\" ] && exit 0", model.IpSegment))
		network = append(network, fmt.Sprintf("uci set network.%s=interface", model.Wifinet))
		network = append(network, fmt.Sprintf("uci set network.%s.proto=static", model.Wifinet))
		network = append(network, fmt.Sprintf("uci set network.%s.ipaddr=%s", model.Wifinet, model.IpSegment))
		network = append(network, fmt.Sprintf("uci set network.%s.netmask=255.255.255.0", model.Wifinet))
		chaos_calmer = append(chaos_calmer, fmt.Sprintf("device=$(cat $(grep -l \"ssid=%s$\" /var/run/*.conf ) | awk -F= '$1==\"interface\" {print $2}')", model.Ssid))
		chaos_calmer = append(chaos_calmer, fmt.Sprintf("uci set network.%s.ifname=$device", model.Wifinet))
		chaos_calmer = append(chaos_calmer, fmt.Sprintf("uci set wireless.%s.ifname=$device", model.Wifinet))
		openwrt = append(openwrt, fmt.Sprintf("uci set network.%s.device=%s", model.Wifinet, model.Wifinet))
		openwrt = append(openwrt, fmt.Sprintf("uci set wireless.%s.ifname=%s", model.Wifinet, model.Wifinet))
		dhcp = append(dhcp, fmt.Sprintf("uci set dhcp.%s=dhcp", model.Wifinet))
		dhcp = append(dhcp, fmt.Sprintf("uci set dhcp.%s.interface=%s", model.Wifinet, model.Wifinet))
		dhcp = append(dhcp, fmt.Sprintf("uci set dhcp.%s.start=100", model.Wifinet))
		dhcp = append(dhcp, fmt.Sprintf("uci set dhcp.%s.limit=150", model.Wifinet))
		dhcp = append(dhcp, fmt.Sprintf("uci set dhcp.%s.leasetime=12h", model.Wifinet))
		firewall = append(firewall, fmt.Sprintf("[ -z \"$(grep %s /etc/config/firewall)\" ] && uci add_list firewall.$tmp.network=%s", model.Wifinet, model.Wifinet))
	}
	var envMap = make(map[string]interface{})
	envMap["reportUrl"] = report
	envMap["token"] = token
	envMap["ipSegment"] = strings.Join(ipSegment, "\n")
	envMap["wireless"] = strings.Join(wireless, "\n")
	envMap["network"] = strings.Join(network, "\n")
	envMap["chaos_calmer"] = strings.Join(chaos_calmer, "\n")
	envMap["openwrt"] = strings.Join(openwrt, "\n")
	envMap["dhcp"] = strings.Join(dhcp, "\n")
	envMap["firewall"] = strings.Join(firewall, "\n")
	return AddWifiTemplate(envMap)
}

// DelWifiCmd 删除WiFi命令
func DelWifiCmd(wifinets []string, report, token string) string {
	var cmds []string
	for _, wifinet := range wifinets {
		cmds = append(cmds, fmt.Sprintf("uci delete dhcp.%s", wifinet))
		cmds = append(cmds, fmt.Sprintf("uci delete network.%s", wifinet))
		cmds = append(cmds, fmt.Sprintf("uci delete wireless.%s", wifinet))
		cmds = append(cmds, fmt.Sprintf("sed -i '/%s/d' /etc/config/firewall", wifinet))
	}
	var envMap = make(map[string]interface{})
	envMap["del"] = strings.Join(cmds, "\n")
	envMap["reportUrl"] = report
	envMap["token"] = token
	return DelWifiTemplate(envMap)
}

func DiagnosisCmd(callbackUrl, typ, batch, ip string) string {
	var envMap = make(map[string]interface{})
	envMap["callbackUrl"] = callbackUrl
	envMap["type"] = typ
	envMap["ip"] = ip
	envMap["batch"] = batch
	return DiagnosisTemplate(envMap)
}

func ClientQosCmd(list []QosModal, action string, host string) string {
	var cmds []string
	for _, item := range list {
		if action == "add" {
			cmds = append(cmds, fmt.Sprintf("eqos add %s %s %s", item.Mac, item.Dl, item.Ul))
		} else if action == "del" {
			cmds = append(cmds, fmt.Sprintf("eqos del %s ", item.Mac))
		} else if action == "update" {
			cmds = append(cmds, fmt.Sprintf("[ -n \"$(grep %s /etc/config/qos| grep -v '#')\" ] && eqos del %s only_remove_ts", strings.ToLower(item.Mac), item.Mac))
			cmds = append(cmds, fmt.Sprintf("eqos add %s %s %s", item.Mac, item.Dl, item.Ul))
		}
	}
	var envMap = make(map[string]interface{})
	envMap["setRule"] = strings.Join(cmds, "\n")
	envMap["nodeHost"] = host
	return ClientQosTemplate(envMap)
}

// SameDHCPMacAndIPs 检查dhcp是否相同
func SameDHCPMacAndIPs(dbResult, result string) bool {
	type client struct {
		Mac string `json:"mac"`
		Ip  string `json:"ip"`
	}
	type resultStruct struct {
		Clients []client `json:"clients"`
		Code    int      `json:"code"`
	}

	var dbRes resultStruct
	json.Unmarshal([]byte(dbResult), &dbRes)
	var dbResMd5s []string
	for _, client := range dbRes.Clients {
		dbResMd5s = append(dbResMd5s, StringMd5(fmt.Sprintf("mac=%s&ip=%s", client.Mac, client.Ip)))
	}

	var res resultStruct
	json.Unmarshal([]byte(result), &res)
	var resMd5s []string
	for _, client := range res.Clients {
		resMd5s = append(resMd5s, StringMd5(fmt.Sprintf("mac=%s&ip=%s", client.Mac, client.Ip)))
	}

	if len(dbResMd5s) != len(resMd5s) {
		return false
	}

	same := false
	for _, dbResMd5 := range dbResMd5s {
		same = false
		for _, resMd5 := range resMd5s {
			if dbResMd5 == resMd5 {
				same = true
				break
			}
		}
		if !same {
			break
		}
	}
	return same
}
