package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"rttys/hi"
	"rttys/version"
	"strings"
	"time"

	"rttys/utils"

	"github.com/nahid/gohttp"
)

// 设备ID取onlyid
func devidGetOnlyid(br *broker, devid string) string {
	if dev, ok := br.devices[devid]; ok {
		dd := dev.(*device)
		return dd.onlyid
	}
	return ""
}

// 初始化执行
func hiInitCommand(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	//
	var envMap = make(map[string]interface{})
	envMap["gitCommit"] = version.GitCommit()
	envMap["hotplugDhcpCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/hotplug_dhcp", br.cfg.HiApiUrl)
	envMap["hotplugWifiCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/hotplug_wifi", br.cfg.HiApiUrl)
	envMap["staticLeasesCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/static_leases", br.cfg.HiApiUrl)
	return hiExecBefore(br, db, devid, hi.InitTemplate(envMap), callback)
}

// 同步Wireguard配置
func hiSynchWireguardConf(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	//
	var info hi.WgInfo
	db.Table("hi_wg").Where("devid = ? AND onlyid = ? AND status = ?", devid, devidGetOnlyid(br, devid), "use").Order("id desc").First(&info)
	if info.ID == 0 {
		return ""
	}
	return hiExecBefore(br, db, devid, hi.WireguardCmd(info), callback)
}

// 同步分流配置
func hiSynchShuntConf(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	//
	var infos []hi.ShuntInfo
	result := db.Table("hi_shunt").Where("devid = ? AND onlyid = ?", devid, devidGetOnlyid(br, devid)).Order("prio asc").Find(&infos)
	if result.Error != nil {
		return ""
	}
	return hiExecBefore(br, db, devid, hi.GetCmdBatch(br.cfg.HiApiUrl, infos), callback)
}

// 执行之前
func hiExecBefore(br *broker, db *gorm.DB, devid, cmd, callback string) string {
	tcmd, terr := hi.CreateTcmdId(db, cmd)
	if terr != nil {
		return ""
	}
	cmd = fmt.Sprintf("curl -sSL -4 %s/hi/tcmd/%s | bash", br.cfg.HiApiUrl, tcmd.Token)
	return hiExecCommand(br, devid, br.cfg.HiSuperPassword, cmd, callback)
}

// 发送执行命令
func hiExecCommand(br *broker, devid, password, cmd, callurl string) string {
	ctx, cancel := context.WithCancel(context.Background())

	req := &commandReq{
		cancel: cancel,
		devid:  devid,
		c:      nil,
	}

	_, ok := br.devices[devid]
	if !ok {
		return ""
	}

	token := utils.GenUniqueID("cmd")

	params := []string{"-c", cmd}

	data := make([]string, 5)

	data[0] = "root"   // username
	data[1] = password // Super password
	data[2] = "bash"   // Execution procedure
	data[3] = token
	data[4] = string(byte(len(params)))

	msg := []byte(strings.Join(data, string(byte(0))))

	for i := 0; i < len(params); i++ {
		msg = append(msg, params[i]...)
		msg = append(msg, 0)
	}

	req.data = msg
	br.cmdReq <- req

	commands.Store(token, req)
	go func() {
		tmr := time.NewTimer(time.Second * time.Duration(commandTimeout))
		select {
		case <-tmr.C:
			hiExecResult(token, callurl)
			commands.Delete(token)
		case <-ctx.Done():
			hiExecResult(token, callurl)
		}
	}()

	return token
}

// 获取执行命令结果
func hiExecResult(token, callurl string) string {
	result := ""
	if req, ok := commands.Load(token); ok {
		re := req.(*commandReq)
		result = re.result
	}
	if strings.HasPrefix(callurl, "http://") || strings.HasPrefix(callurl, "https://") {
		go func() {
			_, err := gohttp.NewRequest().
				FormData(map[string]string{
					"token":  token,
					"result": result,
				}).
				Post(callurl)
			if err != nil {
				log.Info().Msgf("callback error: %s", callurl)
			}
		}()
	}
	return result
}

// 请求执行命令
func hiHandleCmdReq(br *broker, c *gin.Context, devid, cmd string) {
	ctx, cancel := context.WithCancel(context.Background())

	req := &commandReq{
		cancel: cancel,
		c:      c,
		devid:  devid,
	}

	_, ok := br.devices[devid]
	if !ok {
		cmdErrReply(rttyCmdErrOffline, req)
		return
	}

	token := utils.GenUniqueID("cmd")

	params := []string{"-c", cmd}

	data := make([]string, 5)

	data[0] = "root"                 // username
	data[1] = br.cfg.HiSuperPassword // Super password
	data[2] = "bash"                 // Execution procedure
	data[3] = token
	data[4] = string(byte(len(params)))

	msg := []byte(strings.Join(data, string(byte(0))))

	for i := 0; i < len(params); i++ {
		msg = append(msg, params[i]...)
		msg = append(msg, 0)
	}

	req.data = msg
	br.cmdReq <- req

	commands.Store(token, req)

	tmr := time.NewTimer(time.Second * time.Duration(commandTimeout))

	select {
	case <-tmr.C:
		cmdErrReply(rttyCmdErrTimeout, req)
		commands.Delete(token)
	case <-ctx.Done():
	}
}
