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

func WireguardCmd(wg WgInfo) string {
	var cmds []string
	//
	var envMap = make(map[string]interface{})
	envMap["conf"] = wg.Conf
	envMap["lan_ip"] = wg.LanIp
	cmds = append(cmds, WireguardTemplate(envMap))
	//
	if wg.ID == 0 {
		// 关闭wg
		cmds = append(cmds, "_clear_wireguard_conf")
	} else {
		// 开启wg
		cmds = append(cmds, "_set_wireguard_conf")
	}
	if IsIp(wg.LanIp) {
		// 设置lan
		cmds = append(cmds, "_set_lan_ip")
	}
	return strings.Join(cmds, "\n")
}

func StaticLeasesCmd(list []StaticLeasesModel) string {
	var cmds []string
	//
	for _, item := range list {
		if IsIp(item.Ip) {
			cmds = append(cmds, "uci add dhcp host")
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.@host[-1].name=\"%s\"", item.Name))
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.@host[-1].ip=\"%s\"", item.Ip))
			cmds = append(cmds, fmt.Sprintf("uci set dhcp.@host[-1].mac=\"%s\"", item.Mac))
		}
	}
	return strings.Join(cmds, "\n")
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
