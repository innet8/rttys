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
	IpSegment  string `json:"ipSegment"`
}

func IpkUpgradeCmd(path string) string {
	var cmds []string
	cmds = append(cmds, "#!/bin/sh")
	cmds = append(cmds, fmt.Sprintf("curl -4 -s -o /tmp/software.ipk '%s' >/dev/null", path))
	cmds = append(cmds, "opkg install /tmp/software.ipk")
	return strings.Join(cmds, "\n")
}

func FirmwareUpgradeCmd(path string) string {
	var cmds []string
	cmds = append(cmds, "#!/bin/sh")
	cmds = append(cmds, fmt.Sprintf("curl -4 -s -o /tmp/firmware.img '%s' >/dev/null", path))
	cmds = append(cmds, "sysupgrade /tmp/firmware.img -y")
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
		cmds = append(cmds, "set_wireguard_conf")
	}
	if IsIp(wg.LanIp) {
		// 设置lan
		cmds = append(cmds, "set_lanip")
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
func EditWifiCmd(wifi WifiModel) string {
	var cmds []string
	var ex []string
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
	if wifi.Channel != "" {
		ex = append(ex, fmt.Sprintf("uci set wireless.%s.channel=%s", wifi.Device, wifi.Channel))
	}
	if wifi.Disabled != "" {
		cmds = append(cmds, fmt.Sprintf("uci set wireless.$1.disabled=%s", wifi.Disabled))
	}

	var envMap = make(map[string]interface{})
	envMap["addString"] = strings.Join(cmds, "\n")
	envMap["ex"] = strings.Join(ex, "\n")
	envMap["device"] = wifi.Device
	envMap["network"] = wifi.Network
	return EditWifiTemplate(envMap)
}

func SpeedtestCmd(callurl string) string {
	var envMap = make(map[string]interface{})
	envMap["callurl"] = callurl
	return SpeedtestTemplate(envMap)
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

func AddWifiCmd(model AddWifiModel, report string) string {
	var envMap = make(map[string]interface{})
	envMap["wifinet"] = model.Wifinet
	envMap["ssid"] = model.Ssid
	envMap["device"] = model.Device
	envMap["encryption"] = model.Encryption
	envMap["key"] = model.Key
	envMap["ipSegment"] = model.IpSegment
	envMap["reportUrl"] = report
	return AddWifiTemplate(envMap)
}

func DelWifiCmd(wifinet string, report string) string {
	var envMap = make(map[string]interface{})
	envMap["wifinet"] = wifinet
	envMap["reportUrl"] = report
	return DelWifiTemplate(envMap)
}
