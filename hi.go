package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"rttys/config"
	"rttys/hi"
	"rttys/hi/xrsa"
	"rttys/version"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gopkg.in/errgo.v2/fmt/errors"
	"gorm.io/gorm"

	"rttys/utils"

	"github.com/nahid/gohttp"
)

var shuntCmdMd5 sync.Map

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

// deviceGetIP 获取设备IP
func deviceGetIP(dev *device) string {
	conn := dev.conn
	addr := conn.RemoteAddr()
	ip := ""
	switch addr := addr.(type) {
	case *net.UDPAddr:
		ip = addr.IP.String()
	case *net.TCPAddr:
		ip = addr.IP.String()
	}
	return ip
}

// 保存设备信息（设备上线）
func deviceOnline(br *broker, devid string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	defer closeDB(db)
	devInfo := devidGetDev(br, devid)
	if devInfo == nil {
		return
	}
	//
	var deviceData hi.DeviceModel
	db.Table("hi_device").Where(map[string]interface{}{
		"devid": devid,
	}).Last(&deviceData)
	//
	deviceData.Online = uint32(time.Now().Unix())
	deviceData.Description = devInfo.desc
	deviceData.IP = deviceGetIP(devInfo)
	deviceData.SecretKey = strings.ToUpper(hi.StringMd5(hi.RandString(16)))
	if deviceData.ID == 0 {
		// 新设备
		deviceData.Devid = devInfo.id
		deviceData.Onlyid = devInfo.onlyid
		db.Table("hi_device").Create(&deviceData)
	} else {
		// 更新设备
		if devInfo.onlyid != deviceData.Onlyid {
			if len(deviceData.Onlyid) > 0 {
				// 取消绑定
				db.Table("hi_wg").Where(map[string]interface{}{"devid": devid}).Update("status", "unbind")
				db.Table("hi_shunt").Where(map[string]interface{}{"devid": devid}).Update("status", "unbind")
				db.Table("hi_wifi_task").Where(map[string]interface{}{"devid": devid}).Update("status", "unbind")
				deviceData.BindOpenid = ""
			}
			deviceData.Onlyid = devInfo.onlyid
		}
		db.Table("hi_device").Save(&deviceData)
	}
	go hiSaveMessage(br.cfg.DB, devid, Connected, "", "", false)
	go hiInitCommand(br, devid, "")
	go hiSyncWireguardConf(br, devid, "")
	go hiSyncShuntConf(br, devid, "")
	go hiSyncVersion(br, deviceData.BindOpenid, devid)
	go hiReport(br, deviceData, "online", "")
	go hiExecWifiTask(br, devid)
}

func deviceOffline(br *broker, devid string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	defer closeDB(db)
	var deviceData hi.DeviceModel
	db.Table("hi_device").Where(map[string]interface{}{
		"devid": devid,
	}).Last(&deviceData)
	go hiSaveMessage(br.cfg.DB, devid, Disconnected, "", "", false)
	hiReport(br, deviceData, "offline", "")
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
	db.Table("hi_user").Where(map[string]interface{}{
		"openid": data["openid"],
	}).Last(&userData)
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
		db.Table("hi_device").Where(map[string]interface{}{
			"devid": devid,
		}).Order("bind_time desc").Last(&deviceData)
		if deviceData.ID == 0 {
			return nil, errors.New("device not exist")
		}
		if deviceData.BindOpenid != userData.Openid {
			return nil, errors.New("device is not your binding")
		}
	}
	return userData, nil
}

// hiVerifySign 验证签名
func hiVerifySign(br *broker, c *gin.Context) bool {
	nonce := c.Query("nonce")
	ts := c.Query("ts")
	ver := c.Query("ver")
	calcMd5 := hi.StringMd5(fmt.Sprintf("nonce=%s&ts=%s&ver=%s%s", nonce, ts, ver, br.cfg.Token))
	return strings.ToUpper(calcMd5) == strings.ToUpper(c.Query("sign"))
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
	defer closeDB(db)
	//
	var envMap = make(map[string]interface{})
	envMap["gitCommit"] = version.GitCommit()
	envMap["onlyid"] = devidGetOnlyid(br, devid)
	envMap["apiHost"] = hi.UrlDomain(br.cfg.HiApiUrl)
	envMap["dhcpCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/dhcp", br.cfg.HiApiUrl)
	envMap["wifiCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/wifi", br.cfg.HiApiUrl)
	envMap["staticLeasesCmdUrl"] = fmt.Sprintf("%s/hi/base/cmd/static_leases", br.cfg.HiApiUrl)
	envMap["wireguardScriptUrl"] = fmt.Sprintf("%s/hi/base/cmd/wireguard_script", br.cfg.HiApiUrl)
	envMap["restartReportUrl"] = fmt.Sprintf("%s/hi/base/report/restarted", br.cfg.HiApiUrl)
	envMap["webpwdReportUrl"] = fmt.Sprintf("%s/hi/base/report/webpwd", br.cfg.HiApiUrl)
	envMap["wrtbwmonScriptUrl"] = fmt.Sprintf("%s/hi/base/cmd/wrtbwmon_script", br.cfg.HiApiUrl)
	envMap["readdbawkScriptUrl"] = fmt.Sprintf("%s/hi/base/cmd/readDB_awk", br.cfg.HiApiUrl)
	envMap["detdeviceScriptUrl"] = fmt.Sprintf("%s/hi/base/cmd/detection_device_script", br.cfg.HiApiUrl)
	envMap["routerlogScriptUrl"] = fmt.Sprintf("%s/hi/base/cmd/router_log", br.cfg.HiApiUrl)
	return hiExecBefore(br, db, devid, hi.InitTemplate(envMap), callback, Init)
}

// 同步Wireguard配置
func hiSyncWireguardConf(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	defer closeDB(db)
	//
	var wg hi.WgModel
	db.Table("hi_wg").Where(map[string]interface{}{
		"status": "use",
		"devid":  devid,
		"onlyid": devidGetOnlyid(br, devid),
	}).Last(&wg)
	return hiExecBefore(br, db, devid, hi.WireguardCmd(wg), callback, SyncWireguard)
}

// 同步分流配置
func hiSyncShuntConf(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	defer closeDB(db)
	//
	var shunts []hi.ShuntModel
	result := db.Table("hi_shunt").Where(map[string]interface{}{
		"status": "use",
		"devid":  devid,
		"onlyid": devidGetOnlyid(br, devid),
	}).Order("prio asc").Find(&shunts)
	if result.Error != nil {
		return ""
	}
	// 同样的分流命令，不重复执行
	cmd := hi.GetCmdBatch(br.cfg.HiApiUrl, shunts)
	cmdMd5 := hi.StringMd5(cmd)
	if v, ok := shuntCmdMd5.Load(devid); ok {
		md5 := v.(string)
		if md5 == cmdMd5 {
			return ""
		} else {
			shuntCmdMd5.Store(devid, cmdMd5)
		}
	} else {
		shuntCmdMd5.Store(devid, cmdMd5)
	}
	return hiExecBefore(br, db, devid, cmd, callback, SyncShuntConf)
}

// 同步版本
func hiSyncVersion(br *broker, openid, devid string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	defer closeDB(db)

	var versions []hi.VersionModel
	result := db.Table("hi_version").Where(map[string]interface{}{
		"openid": openid,
	}).Find(&versions)
	if result.Error != nil {
		return ""
	}

	c := map[string]interface{}{
		"bind_openid": openid,
	}
	if devid != "" {
		c["devid"] = devid
	}
	var devices []hi.DeviceModel
	result = db.Table("hi_device").Where(c).Find(&devices)
	if result.Error != nil {
		return ""
	}

	for _, device := range devices {
		hiExecBefore(br, db, device.Devid, hi.SyncVersionCmd(versions, device.Description), "", SyncVersion)
	}
	return ""
}

// 重启设备
func hiRebootDevice(br *broker, devid string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	defer closeDB(db)
	return hiExecBefore(br, db, devid, "#!/bin/sh\nreboot", "", Reboot)
}

// 固件升级
func hiDeviceFirmwareUpgrade(br *broker, devid string, path string, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return ""
	}
	defer closeDB(db)
	return hiExecBefore(br, db, devid, hi.FirmwareUpgradeCmd(path), callback, UpgradeFirmware)
}

// 执行之前
func hiExecBefore(br *broker, db *gorm.DB, devid, cmd, callback, action string) string {
	onlyid := devidGetOnlyid(br, devid)
	cmdr, err := hi.CreateCmdr(db, devid, onlyid, cmd, action)
	if err != nil {
		return ""
	}
	return hiExecCommand(br, cmdr, callback, "")
}

// 发送执行命令
func hiExecCommand(br *broker, cmdr *hi.CmdrModel, callurl string, devid string) string {
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
	// WiFi 任务
	if devid != "" {
		token = cmdr.Token
	}
	cmdConfig := hi.Base64Encode(cmdr.Cmd)

	// cmd := fmt.Sprintf("curl -sSL -4 %s/hi/other/cmdr/%s | bash", br.cfg.HiApiUrl, cmdr.Token)
	cmd := fmt.Sprintf("echo %s | base64 -d > /tmp/%s && bash -x /tmp/%s >>/var/log/exec.log 2>&1 && rm /tmp/%s", cmdConfig, token, token, token)
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

	//go hiPushCmdrStart(cmdr)

	commands.Store(token, req)
	go func(cmdrid uint32, devid string) {
		isWifiTask := devid != ""
		duration := commandTimeout
		if isWifiTask {
			duration = 120 // wifi任务2分钟超时
		}
		tmr := time.NewTimer(time.Second * time.Duration(duration))
		isTimeout := false
		select {
		case <-tmr.C:
			hiExecCallback(token, callurl, true)
			hiExecOvertime(token)
			isTimeout = true
			commands.Delete(token)
		case <-ctx.Done():
			hiExecCallback(token, callurl, false)
		}
		if isWifiTask {
			if isTimeout {
				hiUpdateWifiTask(br, devid, cmdrid, "timeout")
			} else {
				hiUpdateWifiTask(br, devid, cmdrid, "done")
			}
			go hiExecWifiTask(br, devid)
		}
	}(cmdr.ID, devid)

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

	cmdConfig := hi.Base64Encode(cmdr.Cmd)

	// cmd := fmt.Sprintf("curl -sSL -4 %s/hi/other/cmdr/%s | bash", br.cfg.HiApiUrl, cmdr.Token)
	cmd := fmt.Sprintf("echo %s | base64 -d > /tmp/%s && bash /tmp/%s && rm /tmp/%s", cmdConfig, token, token, token)
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

	//go hiPushCmdrStart(cmdr)

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
	defer closeDB(db)
	var cmdr hi.CmdrModel
	db.Table("hi_cmdr").Where(map[string]interface{}{
		"token": hir.token,
	}).First(&cmdr)

	cmdr.Result = hir.result
	cmdr.EndTime = uint32(time.Now().Unix())
	db.Table("hi_cmdr").Save(&cmdr)
	go hiPushCmdrResult(hir.db, &cmdr)
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

// hiReport 上报控制中心，typ=online|offline|network_speed|restarted
func hiReport(br *broker, device hi.DeviceModel, typ, content string) {
	if device.ID == 0 || device.BindOpenid == "" || device.ReportUrl == "" {
		return
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	defer closeDB(db)
	var userData *hi.UserModel
	db.Table("hi_user").Where(map[string]interface{}{
		"openid": device.BindOpenid,
	}).Last(&userData)
	if userData.ID == 0 {
		return
	}

	// 上线后，判断是否需要重新下发wg配置
	if typ == "online" {
		var wg hi.WgModel
		db.Table("hi_wg").Where(map[string]interface{}{
			"status": "use",
			"devid":  device.Devid,
		}).Last(&wg)
		onlineData := map[string]interface{}{
			"reset_wg": wg.ID > 0 && wg.Onlyid == "",
		}
		tmpBytes, _ := json.Marshal(onlineData)
		content = string(tmpBytes)
	}

	// about encrypt
	//bs, err := json.Marshal(map[string]interface{}{
	//	"ip":   device.IP,
	//	"type": typ,
	//	"data": content,
	//})
	//if err != nil {
	//	return
	//}
	//
	//data := xrsa.Encrypt(string(bs), userData.Public)
	_, _ = gohttp.NewRequest().JSON(map[string]interface{}{
		"devid": device.Devid,
		//"data":  data,
		"ip":   device.IP,
		"type": typ,
		"data": content,
	}).Post(device.ReportUrl)
}

func hiUpdateWifiTask(br *broker, devid string, cmdrid uint32, status string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	defer closeDB(db)
	var runningTask hi.WifiTaskModel
	db.Table("hi_wifi_task").Where(map[string]interface{}{
		"devid":  devid,
		"cmdrid": cmdrid,
		"status": "running",
	}).First(&runningTask)
	if runningTask.ID != 0 {
		runningTask.Status = status
		db.Table("hi_wifi_task").Save(&runningTask)
	}
}

func hiExecWifiTask(br *broker, devid string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	defer closeDB(db)

	onlyid := devidGetOnlyid(br, devid)
	if len(onlyid) == 0 {
		return
	}

	var runningTask, pendingTask hi.WifiTaskModel
	where := map[string]interface{}{
		"devid":  devid,
		"onlyid": onlyid,
	}
	where["status"] = "running"
	db.Table("hi_wifi_task").Where(where).First(&runningTask)
	if runningTask.ID != 0 {
		if runningTask.UpdatedAt+60 < uint32(time.Now().Unix()) { // 超时
			var cmdr hi.CmdrModel
			db.Table("hi_cmdr").Where(map[string]interface{}{"id": runningTask.Cmdrid}).Find(&cmdr)
			if cmdr.ID != 0 {
				cmdr.Result = hiExecCallback(cmdr.Token, runningTask.CallbackUrl, true)
				cmdr.EndTime = uint32(time.Now().Unix())
				db.Table("hi_cmdr").Save(&cmdr)
			}

			runningTask.Status = "timeout"
			db.Table("hi_wifi_task").Save(&runningTask)
		} else {
			return
		}
	}
	where["status"] = "pending"
	db.Table("hi_wifi_task").Where(where).First(&pendingTask)
	if pendingTask.ID == 0 {
		return
	}

	var cmdr hi.CmdrModel
	db.Table("hi_cmdr").Where(map[string]interface{}{
		"id": pendingTask.Cmdrid,
	}).Find(&cmdr)
	if cmdr.ID == 0 {
		pendingTask.Status = "error"
		db.Table("hi_wifi_task").Save(&pendingTask)
		return
	}
	pendingTask.Status = "running"
	db.Table("hi_wifi_task").Save(&pendingTask)

	token := hiExecCommand(br, &cmdr, pendingTask.CallbackUrl, devid)
	if token != cmdr.Token { // 离线
		pendingTask.Status = "pending"
		db.Table("hi_wifi_task").Save(&pendingTask)
	}
}

// hiDeviceSaveVersion 保存版本信息
func hiDeviceSaveVersion(br *broker, devid, ver, webVer, rttyVer string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	if err != nil {
		return
	}
	defer closeDB(db)
	var deviceData hi.DeviceModel
	db.Table("hi_device").Where(map[string]interface{}{
		"devid": devid,
	}).Last(&deviceData)
	if deviceData.ID != 0 {
		if ver != "" {
			deviceData.Version = ver
		}
		if webVer != "" {
			deviceData.WebVersion = webVer
		}
		if rttyVer != "" {
			deviceData.RttyVersion = rttyVer
		}
		db.Table("hi_device").Save(&deviceData)
	}
}

// hiPushMsg 推送消息
func hiPushMsg(msg string) {
	if config.BotUrl == "" {
		return
	}
	_, _ = gohttp.NewRequest().Headers(map[string]string{
		"version": config.BotVersion,
		"token":   config.BotToken,
	}).FormData(map[string]string{
		"dialog_id": config.BotDialogId,
		"text":      msg,
		"silence":   config.BotSilence,
	}).Post(config.BotUrl)
}

// hiSaveMessage 保存到消息表
func hiSaveMessage(dbCfg string, devid, action, token, errMsg string, timeout bool) {
	if _, ok := dictionary[action]; ok {
		db, err := hi.InstanceDB(dbCfg)
		if err != nil {
			return
		}
		defer closeDB(db)

		status := StatusSuccess
		if timeout { // 超时
			status = StatusTimeout
		}
		if errMsg != "" { // 执行失败
			status = StatusFail
		}

		today := time.Now()
		startTime := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location()).Unix()
		endTime := time.Date(today.Year(), today.Month(), today.Day(), 23, 59, 59, 0, today.Location()).Unix()
		var lastMsg hi.MessageModel
		db.Table("hi_messages").Where(map[string]interface{}{
			"devid":  devid,
			"action": action,
			"status": status,
		}).Where("created_at BETWEEN ? AND ?", startTime, endTime).Last(&lastMsg)
		message := hi.MessageModel{
			Devid:       devid,
			Action:      action,
			Token:       token,
			ErrMsg:      errMsg,
			Status:      uint32(status),
			CreatedAt:   uint32(today.Unix()),
			NumberIndex: 1,
		}
		if lastMsg.ID > 0 {
			message.NumberIndex = lastMsg.NumberIndex + 1
		}
		db.Table("hi_messages").Save(&message)
	}
}

// hiPushMessages 定时发送消息
func hiPushMessages(dbCfg string) {
	db, err := hi.InstanceDB(dbCfg)
	if err != nil {
		return
	}
	defer closeDB(db)

	ts := time.Now().Unix()
	var messages []hi.MessageModel
	tx := db.Table("hi_messages").Where("pushed_at = 0")
	tx.Order("id asc").Find(&messages)

	if len(messages) == 0 {
		return
	}

	groupMessages := make(map[string][]hi.MessageModel)
	for _, message := range messages {
		key := fmt.Sprintf("%s_%s_%d", message.Devid, message.Action, message.Status)
		if message.Action == "connected" || message.Action == "disconnected" {
			key = fmt.Sprintf("%s_%s", message.Devid, "connect_status")
		}
		groupMessages[key] = append(groupMessages[key], message)
	}

	for _, groupMessage := range groupMessages {
		var msgs []string
		for _, pushingMsg := range groupMessage {
			timeString := time.Unix(int64(pushingMsg.CreatedAt), 0).Format("2006-01-02 15:04:05")
			if pushingMsg.Action == Connected || pushingMsg.Action == Disconnected {
				msgs = append(msgs, fmt.Sprintf("设备[%s]%s（时间：%s，今日第%d次）", pushingMsg.Devid, dictionary[pushingMsg.Action], timeString, pushingMsg.NumberIndex))
			} else if pushingMsg.Status == StatusTimeout {
				msgs = append(msgs, fmt.Sprintf("设备[%s]%s，执行超时，token=%s（时间：%s）", pushingMsg.Devid, dictionary[pushingMsg.Action], pushingMsg.Token, timeString))
			} else if pushingMsg.Status == StatusFail {
				msgs = append(msgs, fmt.Sprintf("设备[%s]%s，执行失败，token=%s, 原因：%s（时间：%s）", pushingMsg.Devid, dictionary[pushingMsg.Action], pushingMsg.Token, pushingMsg.ErrMsg, timeString))
			}
		}
		if len(msgs) > 0 {
			hiPushMsg(strings.Join(msgs, "\n"))
		}
	}

	tx.Updates(map[string]interface{}{
		"updated_at": ts,
		"pushed_at":  ts,
	})
}

// hiPushCmdrResult 推送命令结果
func hiPushCmdrResult(db string, cmdr *hi.CmdrModel) {
	var m map[string]interface{}
	err := json.Unmarshal([]byte(cmdr.Result), &m)
	if err != nil {
		return
	}

	ret := 0
	if v, ok := m["ret"].(float64); ok {
		ret = int(v)
	}
	msg := ""
	if v, ok := m["msg"].(string); ok {
		msg = v
	}

	if ret == 1 {
		//hiPushCmdrSuccessMsg(cmdr.Devid, cmdr.Action)
	} else if msg == "overtime" {
		hiSaveMessage(db, cmdr.Devid, cmdr.Action, cmdr.Token, "", true)
	} else {
		stderr := ""
		if md, ok := m["data"].(map[string]interface{}); ok {
			if v, ok2 := md["stderr"]; ok2 {
				if value, ok3 := v.(string); ok3 && value != "" {
					decodeString, _ := base64.StdEncoding.DecodeString(value)
					stderr = string(decodeString)
				}
			}
		}
		hiSaveMessage(db, cmdr.Devid, cmdr.Action, cmdr.Token, stderr, false)
	}
}

// hiTimingPushMessages 定时2分钟推送消息
func hiTimingPushMessages(cfg *config.Config) {
	hiPushMessages(cfg.DB)
	t := time.NewTicker(2 * time.Minute)
	for {
		select {
		case <-t.C:
			hiPushMessages(cfg.DB)
		}
	}
}

// hiTimingDeleteData 定时2小时删除数据
func hiTimingDeleteData(cfg *config.Config) {
	t := time.NewTicker(2 * time.Hour)
	for {
		select {
		case <-t.C:
			hiDeleteCmdr14DaysBefore(cfg.DB)
		}
	}
}

// hiDeleteCmdr14DaysBefore 删除14天前的cmdr
func hiDeleteCmdr14DaysBefore(dbCfg string) {
	db, err := hi.InstanceDB(dbCfg)
	if err != nil {
		return
	}
	defer closeDB(db)
	db.Table("hi_cmdr").
		Where("start_time < ?", time.Now().Add(-14*24*time.Hour).Unix()).
		Delete(&hi.CmdrModel{})
}

// hiDeleteDHCP14DaysBefore 删除14天前dhcp信息
func hiDeleteDHCP14DaysBefore(dbCfg string, devid string) {
	db, err := hi.InstanceDB(dbCfg)
	if err != nil {
		return
	}
	defer closeDB(db)
	db.Table("hi_info").Where(map[string]string{"devid": devid, "type": "dhcp"}).
		Where("time < ?", time.Now().Add(-14*24*time.Hour).Unix()).
		Delete(&hi.InfoModel{})
}
