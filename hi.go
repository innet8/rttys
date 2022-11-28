package main

import (
	"context"
	"fmt"
	"net"
	"rttys/hi"
	"rttys/hi/xrsa"
	"rttys/version"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gopkg.in/errgo.v2/fmt/errors"
	"gorm.io/gorm"

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
	defer closeDB(db)
	if err != nil {
		return
	}
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
	go hiInitCommand(br, devid, "")
	go hiSynchWireguardConf(br, devid, "")
	go hiSynchShuntConf(br, devid, "")
	go hiSyncVersion(br, deviceData.BindOpenid, devid)
	go hiReport(br, deviceData, "online", "")
	go hiExecWifiTask(br, devid)
}

func deviceOffline(br *broker, devid string) {
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return
	}
	var deviceData hi.DeviceModel
	db.Table("hi_device").Where(map[string]interface{}{
		"devid": devid,
	}).Last(&deviceData)
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

// 初始化执行
func hiInitCommand(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return ""
	}
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
	return hiExecBefore(br, db, devid, hi.InitTemplate(envMap), callback)
}

// 同步Wireguard配置
func hiSynchWireguardConf(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return ""
	}
	//
	var wg hi.WgModel
	db.Table("hi_wg").Where(map[string]interface{}{
		"status": "use",
		"devid":  devid,
		"onlyid": devidGetOnlyid(br, devid),
	}).Last(&wg)
	return hiExecBefore(br, db, devid, hi.WireguardCmd(wg), callback)
}

// 同步分流配置
func hiSynchShuntConf(br *broker, devid, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return ""
	}
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
	return hiExecBefore(br, db, devid, hi.GetCmdBatch(br.cfg.HiApiUrl, shunts), callback)
}

// 同步版本
func hiSyncVersion(br *broker, openid, devid string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return ""
	}

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
		hiExecBefore(br, db, device.Devid, hi.SyncVersionCmd(versions, device.Description), "")
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
	defer closeDB(db)
	if err != nil {
		return ""
	}
	return hiExecBefore(br, db, devid, "#!/bin/sh\nreboot", "")
}

// 固件升级
func hiDeviceFirmwareUpgrade(br *broker, devid string, path string, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return ""
	}
	return hiExecBefore(br, db, devid, hi.FirmwareUpgradeCmd(path), callback)
}

// ipk软件升级
func hiDeviceIpkUpgrade(br *broker, devid string, path string, callback string) string {
	if len(br.cfg.HiApiUrl) == 0 {
		log.Info().Msgf("api url is empty")
		return ""
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return ""
	}
	return hiExecBefore(br, db, devid, hi.IpkUpgradeCmd(path), callback)
}

// 执行之前
func hiExecBefore(br *broker, db *gorm.DB, devid, cmd, callback string) string {
	onlyid := devidGetOnlyid(br, devid)
	cmdr, err := hi.CreateCmdr(db, devid, onlyid, cmd)
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

	commands.Store(token, req)
	go func(cmdr *hi.CmdrModel, devid string) {
		isWifiTask := devid != ""
		duration := commandTimeout
		if isWifiTask {
			duration = 60 // wifi任务60秒超时
		}
		tmr := time.NewTimer(time.Second * time.Duration(duration))
		select {
		case <-tmr.C:
			hiExecCallback(token, callurl, true)
			hiExecOvertime(token)
			if isWifiTask {
				hiUpdateWifiTask(br, devid, cmdr.ID, "timeout")
				go hiExecWifiTask(br, devid)
			}
			commands.Delete(token)
		case <-ctx.Done():
			hiExecCallback(token, callurl, false)
			if isWifiTask {
				hiUpdateWifiTask(br, devid, cmdr.ID, "done")
				go hiExecWifiTask(br, devid)
			}
		}
	}(cmdr, devid)

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
	defer closeDB(db)
	if err != nil {
		return
	}
	db.Table("hi_cmdr").Where(map[string]interface{}{
		"token": hir.token,
	}).Updates(map[string]interface{}{
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

// hiReport 上报控制中心，typ=online|offline|network_speed|restarted
func hiReport(br *broker, device hi.DeviceModel, typ, content string) {
	if device.ID == 0 || device.BindOpenid == "" || device.ReportUrl == "" {
		return
	}
	db, err := hi.InstanceDB(br.cfg.DB)
	defer closeDB(db)
	if err != nil {
		return
	}
	var userData *hi.UserModel
	db.Table("hi_user").Where(map[string]interface{}{
		"openid": device.BindOpenid,
	}).Last(&userData)
	if userData.ID == 0 {
		return
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
		if runningTask.CreatedAt+60 < uint32(time.Now().Unix()) { // 运行的任务超时
			var cmdr hi.CmdrModel
			db.Table("hi_cmdr").Where(map[string]interface{}{"id": runningTask.Cmdrid}).Find(&cmdr)
			if cmdr.ID != 0 {
				result := hiExecCallback(cmdr.Token, runningTask.CallbackUrl, true)
				cmdr.Result = result
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

	go hiExecCommand(br, &cmdr, pendingTask.CallbackUrl, devid)
}
