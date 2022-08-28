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
	envMap["dhcpCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/dhcp", br.cfg.HiApiUrl)
	envMap["wifiCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/wifi", br.cfg.HiApiUrl)
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
	var wg hi.WgModel
	db.Table("hi_wg").Where("devid = ? AND onlyid = ? AND status = ?", devid, devidGetOnlyid(br, devid), "use").Last(&wg)
	return hiExecBefore(br, db, devid, hi.WireguardCmd(wg), callback)
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
	var shunts []hi.ShuntModel
	result := db.Table("hi_shunt").Where("devid = ? AND onlyid = ?", devid, devidGetOnlyid(br, devid)).Order("prio asc").Find(&shunts)
	if result.Error != nil {
		return ""
	}
	return hiExecBefore(br, db, devid, hi.GetCmdBatch(br.cfg.HiApiUrl, shunts), callback)
}

// 执行之前
func hiExecBefore(br *broker, db *gorm.DB, devid, cmd, callback string) string {
	onlyid := devidGetOnlyid(br, devid)
	cmdr, err := hi.CreateCmdr(db, devid, onlyid, cmd)
	if err != nil {
		return ""
	}
	return hiExecCommand(br, cmdr, callback)
}

// 发送执行命令
func hiExecCommand(br *broker, cmdr *hi.CmdrModel, callurl string) string {
	ctx, cancel := context.WithCancel(context.Background())

	req := &commandReq{
		cancel: cancel,
		devid:  cmdr.Devid,
		c:      nil,
		h: &hiReq{
			db:    br.cfg.DB,
			token: cmdr.Token,
		},
	}

	_, ok := br.devices[cmdr.Devid]
	if !ok {
		return ""
	}

	token := utils.GenUniqueID("cmd")

	cmd := fmt.Sprintf("curl -sSL -4 %s/hi/cmdr/%s | bash", br.cfg.HiApiUrl, cmdr.Token)
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
	go func() {
		tmr := time.NewTimer(time.Second * time.Duration(commandTimeout))
		select {
		case <-tmr.C:
			hiExecCallback(token, callurl, true)
			hiExecOvertime(token)
			commands.Delete(token)
		case <-ctx.Done():
			hiExecCallback(token, callurl, false)
		}
	}()

	return token
}

// 请求执行命令
func hiExecRequest(br *broker, c *gin.Context, cmdr *hi.CmdrModel) {
	ctx, cancel := context.WithCancel(context.Background())

	req := &commandReq{
		cancel: cancel,
		c:      c,
		devid:  cmdr.Devid,
		h: &hiReq{
			db:    br.cfg.DB,
			token: cmdr.Token,
		},
	}

	_, ok := br.devices[cmdr.Devid]
	if !ok {
		cmdErrReply(rttyCmdErrOffline, req)
		return
	}

	token := utils.GenUniqueID("cmd")

	cmd := fmt.Sprintf("curl -sSL -4 %s/hi/cmdr/%s | bash", br.cfg.HiApiUrl, cmdr.Token)
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
		hiExecOvertime(token)
		commands.Delete(token)
	case <-ctx.Done():
	}
}

// 执行命令回应
func hiExecCallback(token, callurl string, overtime bool) string {
	var result string
	if overtime {
		result = `{"ret":0,"msg":"overtime","data":{}}`
	} else {
		result = `{"ret":0,"msg":"","data":{}}`
		if req, ok := commands.Load(token); ok {
			re := req.(*commandReq)
			if re.h != nil {
				result = re.h.result
			}
		}
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

// 执行命令结果
func hiExecResult(hir *hiReq) {
	db, err := hi.InstanceDB(hir.db)
	if err != nil {
		return
	}
	db.Table("hi_cmdr").Where("token = ?", hir.token).Updates(map[string]interface{}{
		"result":   hir.result,
		"end_time": uint32(time.Now().Unix()),
	})
}

// 执行命令结果（超时）
func hiExecOvertime(token string) {
	if req, ok := commands.Load(token); ok {
		res := req.(*commandReq)
		if res.h != nil {
			res.h.result = `{"ret":0,"msg":"overtime","data":{}}`
			go hiExecResult(res.h)
		}
	}
}
