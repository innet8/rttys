package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gopkg.in/errgo.v2/fmt/errors"
	"gorm.io/gorm"
	"rttys/hi"
	"rttys/hi/xrsa"
	"rttys/version"
	"sort"
	"strconv"
	"strings"
	"time"

	"rttys/utils"

	"github.com/nahid/gohttp"
)

// 设备ID取设备信息
func devidGetDev(br *broker, devid string) *device {
	if dev, ok := br.devices[devid]; ok {
		dd := dev.(*device)
		return dd
	}
	return nil
}

// 设备ID取onlyid
func devidGetOnlyid(br *broker, devid string) string {
	if dev, ok := br.devices[devid]; ok {
		dd := dev.(*device)
		return dd.onlyid
	}
	return ""
}

// 保存设备信息（设备上线）
func deviceOnline(br *broker, devid string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	devInfo := devidGetDev(br, devid)
	if devInfo == nil {
		return
	}
	//
	var data hi.DeviceModel
	db.Table("hi_device").Where("devid = ? AND onlyid = ?", devid, devInfo.onlyid).Last(&data)
	if data.ID > 0 {
		data.Online = uint32(time.Now().Unix())
		db.Table("hi_device").Save(data)
	} else {
		data.Devid = devInfo.id
		data.Onlyid = devInfo.onlyid
		data.Description = devInfo.desc
		data.Online = uint32(time.Now().Unix())
		db.Table("hi_device").Create(&data)
	}
}

// 验证用户（验证签名）
func userAuth(c *gin.Context, db *gorm.DB, devid string) (*hi.UserModel, error) {
	query := c.Request.URL.Query()
	data := make(map[string]string)
	sign := c.GetHeader("sign")
	for key, value := range query {
		if len(value) > 0 && len(value[0]) > 0 {
			if key == "sign" {
				sign = value[0]
			} else {
				data[key] = value[0]
			}
		}
	}
	for _, key := range []string{"openid", "ver", "ts", "nonce"} {
		if len(data[key]) == 0 {
			return nil, errors.New(fmt.Sprintf("%s empty", key))
		}
		if key == "ts" {
			ts, _ := strconv.ParseInt(data[key], 10, 64)
			if ts+300 < time.Now().Unix() {
				return nil, errors.New("ts expired")
			}
		}
	}
	//
	var userData *hi.UserModel
	db.Table("hi_user").Where("openid = ?", data["openid"]).Last(&userData)
	if userData.ID == 0 {
		return nil, errors.New("openid error")
	}
	//
	var keys []string
	var array []string
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		array = append(array, fmt.Sprintf("%s=%s", k, data[k]))
	}
	err := xrsa.VerifySign(strings.Join(array, "&"), sign, userData.Public)
	if err != nil {
		return nil, err
	}
	//
	if len(devid) > 0 {
		var deviceData hi.DeviceModel
		db.Table("hi_device").Where("devid = ?", devid).Order("bind_time desc").Last(&deviceData)
		if deviceData.ID == 0 {
			return nil, errors.New("device not exist")
		}
		if deviceData.BindOpenid != userData.Openid {
			return nil, errors.New("device is not your binding")
		}
	}
	return userData, nil
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

	cmd := fmt.Sprintf("curl -sSL -4 %s/hi/other/cmdr/%s | bash", br.cfg.HiApiUrl, cmdr.Token)
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

	cmd := fmt.Sprintf("curl -sSL -4 %s/hi/other/cmdr/%s | bash", br.cfg.HiApiUrl, cmdr.Token)
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
