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
	var cmds string
	if name == "firmware" {
		cmds = "[ -e '/etc/glversion' ] && {\ncat /etc/glversion ; exit 0\n}\ncat /etc/openwrt_release|grep DISTRIB_RELEASE |awk -F'=' '{print $2}'"
	} else {
		cmds = fmt.Sprintf("opkg info %s |grep 'Version' |awk '{print $2=$2}'", name)
	}
	return cmds
}

func WireguardCmd(wg WgModel) string {
	var cmds []string
	//
	var envMap = make(map[string]interface{})
	envMap["wg_conf"] = wg.Conf
	envMap["lan_ip"] = wg.LanIp
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
