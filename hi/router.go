package hi

import (
	"strings"
)

func WireguardCmd(wg WgInfo) string {
	var cmds []string
	//
	var envMap = make(map[string]interface{})
	envMap["conf"] = wg.Conf
	envMap["lan_ip"] = wg.LanIp
	cmds = append(cmds, RouterWireguardTemplate(envMap))
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
