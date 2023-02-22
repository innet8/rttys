package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
	"github.com/nahid/gohttp"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"net/http"
	"rttys/hi"
	"rttys/utils"
	"strconv"
	"strings"
	"time"
)

const (
	AddBlock        = "add_block"
	DelBlock        = "del_block"
	EditWifi        = "edit_wifi"
	AddWifi         = "add_wifi"
	DelWifi         = "del_wifi"
	UpdateStaticIp  = "update_static_ip"
	Reboot          = "reboot"
	SpeedTest       = "speed_test"
	UpgradeFirmware = "upgrade_firmware"
	UpgradeIpk      = "upgrade_ipk"
	SyncShuntConf   = "sync_shunt_conf"
	SyncVersion     = "sync_version"
	Diagnosis       = "diagnosis"
	SyncKey         = "sync_key"
	Init            = "init"
	SyncWireguard   = "sync_wireguard"
	ClearCustomWifi = "clear_custom_wifi"
	GetVersion      = "get_version"
	Connected       = "connected"
	Disconnected    = "disconnected"
	FetchLog        = "fetch_log"
	Qos             = "qos"
)

var (
	dictionary = map[string]string{
		AddBlock:        "禁用终端网络",
		DelBlock:        "启用终端网络",
		EditWifi:        "修改WiFi",
		AddWifi:         "添加WiFi",
		DelWifi:         "删除WiFi",
		UpdateStaticIp:  "更新静态IP绑定",
		Reboot:          "重启",
		SpeedTest:       "测速",
		UpgradeFirmware: "升级固件",
		UpgradeIpk:      "升级软件",
		SyncShuntConf:   "同步分流配置",
		SyncVersion:     "同步版本",
		Diagnosis:       "诊断网络",
		SyncKey:         "同步签名秘钥",
		Init:            "初始化命令",
		SyncWireguard:   "同步wireguard配置",
		ClearCustomWifi: "清空自定义WiFi",
		GetVersion:      "获取版本",
		Connected:       "上线",
		Disconnected:    "已下线",
		FetchLog:        "手动获取日志",
		Qos:             "限速",
	}
)

const (
	StatusStart = iota
	StatusSuccess
	StatusTimeout
	StatusFail
)

// createUser 创建用户
func createUser(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		data := &hi.UserModel{
			Openid: hi.RandString(32),
			Public: strings.TrimSpace(jsoniter.Get(content, "public").ToString()),
			Time:   uint32(time.Now().Unix()),
		}
		result := db.Table("hi_user").Create(&data)
		if result.Error != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "创建失败",
				"data": gin.H{
					"error": result.Error.Error(),
				},
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"openid": data.Openid,
					"time":   data.Time,
				},
			})
		}
	}
}

// baseCmd 路由器获取命令：dhcp、wifi、static_leases、wireguard_script、wrtbwmon_script、detection_device_script、readDB_awk
func baseCmd(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")

		if !hi.InArray(action, []string{"dhcp", "wifi", "static_leases", "wireguard_script", "wrtbwmon_script", "detection_device_script", "readDB_awk", "router_log"}) {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		if !hiVerifySign(br, c) {
			c.Status(http.StatusBadRequest)
			return
		}

		if action == "dhcp" {
			var envMap = make(map[string]interface{})
			envMap["requestUrl"] = "http://127.0.0.1/cgi-bin/api/client/list"
			envMap["requestType"] = "clients"
			envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/dhcp", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.ApiReportTemplate(envMap))
		} else if action == "wifi" {
			var envMap = make(map[string]interface{})
			envMap["requestUrl"] = "http://127.0.0.1/cgi-bin/api/ap/config"
			envMap["requestType"] = "apconfig"
			envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/wifi", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.ApiReportTemplate(envMap))
		} else if action == "static_leases" {
			var envMap = make(map[string]interface{})
			envMap["requestType"] = "static_leases"
			envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/static_leases", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.ApiReportTemplate(envMap))
		} else if action == "wireguard_script" {
			var envMap = make(map[string]interface{})
			envMap["requestType"] = "wireguard_script"
			c.String(http.StatusOK, hi.WireguardScriptTemplate(envMap))
		} else if action == "wrtbwmon_script" {
			var envMap = make(map[string]interface{})
			envMap["requestType"] = "wrtbwmon_script"
			c.String(http.StatusOK, hi.WrtbwmonScriptTemplate(envMap))
		} else if action == "detection_device_script" {
			var envMap = make(map[string]interface{})
			envMap["requestType"] = "detection_device_script"
			c.String(http.StatusOK, hi.DetectionDeviceScriptTemplate(envMap))
		} else if action == "readDB_awk" {
			var envMap = make(map[string]interface{})
			envMap["requestType"] = "readDB_awk"
			c.String(http.StatusOK, hi.ReadDBAWKTemplate(envMap))
		} else if action == "router_log" {
			var envMap = make(map[string]interface{})
			envMap["logUrl"] = fmt.Sprintf("%s/hi/other/upload-log", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.RouterLogUploadTemplate(envMap))
		}
	}
}

// baseReport 路由器上报数据：dhcp、wifi、static_leases、restarted、webpwd、version、rtty_error
func baseReport(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")

		if !hi.InArray(action, []string{"dhcp", "wifi", "static_leases", "restarted", "webpwd", "version", "rtty_error"}) {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		resultContent := jsoniter.Get(content, "content").ToString()
		result := hi.ApiResultCheck(hi.Base64Decode(resultContent))
		devid := jsoniter.Get(content, "sn").ToString()
		rtime := jsoniter.Get(content, "time").ToUint32()
		// 上报重启
		if action == "rtty_error" {
			var deviceData hi.DeviceModel
			db.Table("hi_device").Where(map[string]interface{}{
				"devid": devid,
			}).Last(&deviceData)
			hiReport(br, deviceData, "rtty_error", "")
			c.String(http.StatusOK, "success")
			return
		}

		if !hiVerifySign(br, c) {
			c.Status(http.StatusBadRequest)
			return
		}

		// 更新固件、web、rtty版本信息
		if action == "dhcp" || action == "version" {
			ver := jsoniter.Get(content, "ver").ToString()
			webVer := jsoniter.Get(content, "webVer").ToString()
			rttyVer := jsoniter.Get(content, "rttyVer").ToString()
			hiDeviceSaveVersion(br, devid, ver, webVer, rttyVer)
		}
		// web密码
		if action == "webpwd" {
			webpwd := jsoniter.Get(content, "webpwd").ToString()
			if webpwd != "" {
				var deviceData hi.DeviceModel
				db.Table("hi_device").Where(map[string]interface{}{
					"devid": devid,
				}).Last(&deviceData)
				if deviceData.ID != 0 {
					deviceData.Password = webpwd
					db.Table("hi_device").Save(&deviceData)
				}
			}
		}
		// 上报重启
		if action == "restarted" {
			var deviceData hi.DeviceModel
			db.Table("hi_device").Where(map[string]interface{}{
				"devid": devid,
			}).Last(&deviceData)
			hiReport(br, deviceData, "restarted", "")
		}

		token := c.Query("token")
		// 修改wifi上报最新WiFi 信息时，如果带有token，则修改命令状态
		if action == "wifi" && token != "" {
			var wifiTask hi.WifiTaskModel
			db.Table("hi_wifi_task").Where(map[string]interface{}{
				"devid":  devid,
				"token":  token,
				"status": "running",
			}).Find(&wifiTask)
			if wifiTask.ID != 0 {
				var cmdr hi.CmdrModel
				db.Table("hi_cmdr").Where(map[string]interface{}{"id": wifiTask.Cmdrid}).Find(&cmdr)
				if cmdr.ID != 0 {
					if req, ok := commands.Load(cmdr.Token); ok {
						res := req.(*commandReq)
						res.h.result = `{"ret":1,"msg":"done","data":{}}`
						res.cancel()
					}
				}
			}
		}

		if len(result) > 0 {
			var count int64
			db.Table("hi_info").Where(map[string]interface{}{
				"type":  action,
				"devid": devid,
			}).Where("time > ?", rtime).Count(&count)
			if count == 0 {
				createInfo := false
				if action == "dhcp" {
					var dhcp hi.InfoModel
					db.Table("hi_info").Where(map[string]interface{}{
						"type":  action,
						"devid": devid,
					}).Last(&dhcp)
					// 数据库中不存在dhcp信息，或者最新一条是一个小时前的，或者和新上报不一样，则添加
					if dhcp.ID == 0 || dhcp.Time < rtime-3600 || !hi.SameDHCPMacAndIPs(dhcp.Result, result) {
						createInfo = true
					} else {
						dhcp.Result = result
						dhcp.Time = rtime
						db.Table("hi_info").Save(&dhcp)
					}
					go hiDeleteDHCP14DaysBefore(br.cfg.DB, devid)
				}
				if action != "dhcp" || createInfo {
					db.Table("hi_info").Create(&hi.InfoModel{
						Devid:  devid,
						Onlyid: devidGetOnlyid(br, devid),
						Type:   action,
						Result: result,
						Time:   rtime,
					})
				}
			}

			// 上报网速等信息
			if action == "dhcp" {
				var deviceData hi.DeviceModel
				db.Table("hi_device").Where(map[string]interface{}{
					"devid": devid,
				}).Last(&deviceData)

				hiReport(br, deviceData, "network_speed", resultContent)
			}
		}
		c.String(http.StatusOK, "success")
	}
}

// baseGet 查询路由器信息：dhcp、wifi、static_leases
func baseGet(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")

		if !hi.InArray(action, []string{"dhcp", "wifi", "static_leases"}) {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		var info hi.InfoModel
		db.Table("hi_info").Where(map[string]interface{}{
			"type":  action,
			"devid": devid,
		}).Last(&info)
		if info.ID == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "当前没有配置",
				"data": nil,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"ret":  1,
				"msg":  "success",
				"data": info,
			})
		}
	}
}

// baseSet 修改在线设备WiFi、启用禁用客户端、绑定静态IP、限速
func baseSet(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		if len(onlyid) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "设备不在线",
				"data": nil,
			})
			return
		}

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		if action == "blocked" {
			list := jsoniter.Get(content, "list").ToString()
			action := jsoniter.Get(content, "action").ToString()
			var data []string
			if ok := json.Unmarshal([]byte(list), &data); ok == nil {
				typ := AddBlock
				if action == "delBlocked" {
					typ = DelBlock
				}
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.BlockedCmd(data, action, br.cfg.HiApiUrl), typ)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建执行任务失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
				} else {
					hiExecRequest(br, c, cmdr)
				}
				return
			}
		}
		if action == "wifi" {
			var wifi hi.WifiModel
			if err := json.Unmarshal(content, &wifi); err == nil {
				report := fmt.Sprintf("%s/hi/base/report/wifi", br.cfg.HiApiUrl)
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.EditWifiCmd(wifi, report, ""), EditWifi)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
					return
				}
				hiExecRequest(br, c, cmdr)
				return
			}
		}
		if action == "static_leases" {
			list := jsoniter.Get(content, "list").ToString()
			var data []hi.StaticLeasesModel
			if ok := json.Unmarshal([]byte(list), &data); ok == nil {
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.StaticLeasesCmd(data), UpdateStaticIp)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建执行任务失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
				} else {
					hiExecRequest(br, c, cmdr)
				}
				return
			}
		}
		if action == "qos" {
			list := jsoniter.Get(content, "list").ToString()
			action := jsoniter.Get(content, "action").ToString()
			var data []hi.QosModal
			if ok := json.Unmarshal([]byte(list), &data); ok == nil {
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.ClientQosCmd(data, action), Qos)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建执行任务失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
				} else {
					hiExecRequest(br, c, cmdr)
				}
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"ret":  0,
			"msg":  "设置失败",
			"data": nil,
		})
	}
}

// deviceList 设备列表
func deviceList(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		authUser, authErr := userAuth(c, db, "")
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		var devicds []hi.DeviceApiModel

		result := db.Table("hi_device").Where(map[string]interface{}{
			"bind_openid": authUser.Openid,
		}).Order("bind_time desc").Find(&devicds)
		if result.Error != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "获取失败",
				"data": gin.H{
					"error": result.Error.Error(),
				},
			})
			return
		}

		for k, v := range devicds {
			if _, ok := br.devices[v.Devid]; ok {
				devicds[k].IsOnline = true
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"ret":  1,
			"msg":  "success",
			"data": devicds,
		})
	}
}

// deviceAction 设备绑定、解绑、重启、获取版本、连接
func deviceAction(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		var authUser *hi.UserModel
		var authErr error
		if action == "bind" {
			authUser, authErr = userAuth(c, db, "")
		} else {
			authUser, authErr = userAuth(c, db, devid)
		}
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		var deviceData hi.DeviceModel
		db.Table("hi_device").Where(map[string]interface{}{
			"devid": devid,
		}).Last(&deviceData)

		msg := "操作成功"
		if action == "bind" {
			if deviceData.ID == 0 {
				// 添加
				deviceData.Devid = devid
				deviceData.BindOpenid = authUser.Openid
				deviceData.BindTime = uint32(time.Now().Unix())
				deviceData.ReportUrl = c.Query("report_url")
				db.Table("hi_device").Create(&deviceData)
				msg = "添加绑定成功"
			} else if len(deviceData.BindOpenid) == 0 {
				// 绑定
				deviceData.Devid = devid
				deviceData.BindOpenid = authUser.Openid
				deviceData.BindTime = uint32(time.Now().Unix())
				deviceData.ReportUrl = c.Query("report_url")
				db.Table("hi_device").Save(&deviceData)
				msg = "绑定成功"
			} else {
				// 已被绑定
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "设备已被绑定",
					"data": nil,
				})
				return
			}
		} else if action == "unbind" {
			// 取消绑定
			db.Table("hi_wg").Where(map[string]interface{}{"devid": devid}).Update("status", "unbind")
			db.Table("hi_shunt").Where(map[string]interface{}{"devid": devid}).Update("status", "unbind")
			// 清空自定义WiFi
			if cmdr, err := hi.CreateCmdr(db, devid, deviceData.Onlyid, hi.DelAllCustomWifi, ClearCustomWifi); err == nil {
				_, err = hi.CreateWifiTask(db, cmdr, "", devid, deviceData.Onlyid, action, "", "")
				go hiExecWifiTask(br, deviceData.Devid)
			}

			deviceData.BindOpenid = ""
			db.Table("hi_device").Save(&deviceData)
			msg = "取消绑定成功"
		} else if action == "reboot" {
			// 重启设备
			onlyid := devidGetOnlyid(br, devid)
			if len(onlyid) == 0 {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "设备不在线",
					"data": nil,
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"ret": 1,
					"msg": "success",
					"data": gin.H{
						"token": hiRebootDevice(br, devid),
					},
				})
			}
			return
		} else if action == "version" {
			// 获取版本
			name := c.Query("name")
			onlyid := devidGetOnlyid(br, devid)
			if len(onlyid) == 0 {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "设备不在线",
					"data": nil,
				})
			} else {
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.VersionCmd(name), GetVersion)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建执行任务失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
				} else {
					hiExecRequest(br, c, cmdr)
				}
			}
			return
		} else if action == "connect" {
			// 连接设备
			if c.GetHeader("Upgrade") != "websocket" {
				c.JSON(http.StatusOK, gin.H{
					"ret":  1,
					"msg":  "success",
					"data": nil,
				})
			} else {
				serveUser(br, c)
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ret":  1,
			"msg":  msg,
			"data": deviceData,
		})

		go hiSyncWireguardConf(br, devid, "")
		go hiSyncShuntConf(br, devid, "")
	}
}

// deviceUpgrade 设备升级：固件、软件
func deviceUpgrade(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		if len(onlyid) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "设备不在线",
				"data": nil,
			})
			return
		}

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		callUrl := jsoniter.Get(content, "call_url").ToString()
		path := jsoniter.Get(content, "path").ToString()
		if action == "ipk" {
			report := fmt.Sprintf("%s/hi/base/report/version", br.cfg.HiApiUrl)
			cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.IpkUpgradeCmd(path, report), UpgradeIpk)
			if terr != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "创建执行任务失败",
					"data": gin.H{
						"error": terr.Error(),
					},
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"ret": 1,
					"msg": "success",
					"data": gin.H{
						"token": hiExecCommand(br, cmdr, callUrl, ""),
					},
				})
			}
			return
		}
		if action == "firmware" {
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"token": hiDeviceFirmwareUpgrade(br, devid, path, callUrl),
				},
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ret":  0,
			"msg":  "action error",
			"data": nil,
		})
	}
}

// wireguard 设置、取消、获取 wireguard
func wireguard(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		callUrl := jsoniter.Get(content, "call_url").ToString()
		if action == "set" {
			// 设置
			var wg hi.WgModel
			wg.Devid = devid
			wg.Onlyid = devidGetOnlyid(br, devid)
			wg.Conf = jsoniter.Get(content, "conf").ToString()
			wg.LanIp = jsoniter.Get(content, "lan_ip").ToString()
			wg.DnsServer = jsoniter.Get(content, "dns_server").ToString()
			wg.Status = "use"
			if !strings.Contains(wg.Conf, "config proxy") || !strings.Contains(wg.Conf, "config peers") {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "配置格式错误，请参考示例",
					"data": gin.H{
						"example": hi.WireguardConfExample,
					},
				})
				return
			}
			result := db.Table("hi_wg").Create(&wg)
			if result.Error != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "创建失败",
					"data": gin.H{
						"error": result.Error.Error(),
					},
				})
			} else {
				db.Table("hi_wg").Where("id != ? AND devid = ? AND status = ?", wg.ID, devid, "use").Update("status", "cancel")
				c.JSON(http.StatusOK, gin.H{
					"ret": 1,
					"msg": "success",
					"data": gin.H{
						"token": hiSyncWireguardConf(br, devid, callUrl),
						"wg":    wg,
					},
				})
			}
		} else if action == "cancel" {
			// 取消
			db.Table("hi_wg").Where(map[string]interface{}{
				"status": "use",
				"devid":  devid,
			}).Update("status", "cancel")
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"token": hiSyncWireguardConf(br, devid, callUrl),
				},
			})
		} else if action == "get" {
			// 当前配置
			var wg hi.WgModel
			db.Table("hi_wg").Where(map[string]interface{}{
				"status": "use",
				"devid":  devid,
			}).Last(&wg)
			if wg.ID == 0 {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "当前没有配置",
					"data": nil,
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"ret": 1,
					"msg": "success",
					"data": gin.H{
						"wg": wg,
					},
				})
			}
		} else {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "参数错误",
				"data": nil,
			})
		}
	}
}

// shuntList 分流列表
func shuntList(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		devid := c.Param("devid")
		onlyid := c.GetHeader("onlyid") // 路由器web

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		if onlyid == "" {
			_, authErr := userAuth(c, db, devid)
			if authErr != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "Authentication failed",
					"data": gin.H{
						"error": authErr.Error(),
					},
				})
				return
			}
		} else {
			var deviceData hi.DeviceModel
			db.Table("hi_device").Where(map[string]interface{}{
				"devid":  devid,
				"onlyid": onlyid,
			}).Order("bind_time desc").Last(&deviceData)
			if deviceData.ID == 0 {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "Authentication failed",
					"data": gin.H{
						"error": "Device not found",
					},
				})
				return
			}
		}

		var shunts []hi.ShuntModel

		result := db.Table("hi_shunt").Select([]string{
			"id",
			"devid",
			"onlyid",
			"source",
			"prio",
			"out_ip",
			"rule",
			"source_remark",
			"rule_remark",
			"out_remark",
		}).Where(map[string]interface{}{
			"status": "use",
			"devid":  devid,
		}).Find(&shunts)
		if result.Error != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "获取失败",
				"data": gin.H{
					"error": result.Error.Error(),
				},
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"ret":  1,
			"msg":  "success",
			"data": shunts,
		})
	}
}

// shuntModify 添加、修改分流
func shuntModify(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		devid := c.Param("devid")
		shuntId, _ := strconv.Atoi(c.Param("sid"))

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		callUrl := jsoniter.Get(content, "call_url").ToString()

		var shunt hi.ShuntModel
		if shuntId > 0 {
			db.Table("hi_shunt").Where(map[string]interface{}{
				"id":     shuntId,
				"status": "use",
				"devid":  devid,
			}).Last(&shunt)
			if shunt.ID == 0 {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "分流不存在",
					"data": nil,
				})
				return
			}
			shunt.Onlyid = devidGetOnlyid(br, devid)
			shunt.Source = jsoniter.Get(content, "source").ToString()
			shunt.Rule = jsoniter.Get(content, "rule").ToString()
			shunt.Prio = jsoniter.Get(content, "prio").ToUint32()
			shunt.OutIp = jsoniter.Get(content, "out_ip").ToString()
			shunt.SourceRemark = jsoniter.Get(content, "source_remark").ToString()
			shunt.RuleRemark = jsoniter.Get(content, "rule_remark").ToString()
			shunt.OutRemark = jsoniter.Get(content, "out_remark").ToString()
			shunt.Status = "use"
			result := db.Table("hi_shunt").Save(&shunt)
			if result.Error != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "更新失败",
					"data": gin.H{
						"error": result.Error.Error(),
					},
				})
				return
			}
		} else {
			shunt.Devid = devid
			shunt.Onlyid = devidGetOnlyid(br, devid)
			shunt.Source = jsoniter.Get(content, "source").ToString()
			shunt.Rule = jsoniter.Get(content, "rule").ToString()
			shunt.Prio = jsoniter.Get(content, "prio").ToUint32()
			shunt.OutIp = jsoniter.Get(content, "out_ip").ToString()
			shunt.SourceRemark = jsoniter.Get(content, "source_remark").ToString()
			shunt.RuleRemark = jsoniter.Get(content, "rule_remark").ToString()
			shunt.OutRemark = jsoniter.Get(content, "out_remark").ToString()
			shunt.Status = "use"
			result := db.Table("hi_shunt").Create(&shunt)
			if result.Error != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "创建失败",
					"data": gin.H{
						"error": result.Error.Error(),
					},
				})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"ret": 1,
			"msg": "success",
			"data": gin.H{
				"token": hiSyncShuntConf(br, devid, callUrl),
				"shunt": shunt,
			},
		})
	}
}

// shuntAction 获取分流信息、删除分流、获取分流命令、获取分流域名
func shuntAction(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		shuntId, _ := strconv.Atoi(c.Param("sid"))
		callUrl := c.Query("call_url")

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		var shunt hi.ShuntModel
		db.Table("hi_shunt").Where(map[string]interface{}{
			"id":     shuntId,
			"status": "use",
		}).Last(&shunt)

		if shunt.ID == 0 {
			c.Status(http.StatusNotFound)
			return
		}

		if hi.InArray(action, []string{"info", "delete"}) {
			_, authErr := userAuth(c, db, shunt.Devid)
			if authErr != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "Authentication failed",
					"data": gin.H{
						"error": authErr.Error(),
					},
				})
				return
			}
		}

		if action == "info" {
			// 规则详情
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"shunt": shunt,
				},
			})
		} else if action == "delete" {
			// 删除
			db.Table("hi_shunt").Where(map[string]interface{}{
				"id": shunt.ID,
			}).Update("status", "delete")
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"token": hiSyncShuntConf(br, shunt.Devid, callUrl),
					"shunt": shunt,
				},
			})
		} else if action == "cmd" {
			// 命令
			c.String(http.StatusOK, hi.GetCmd(br.cfg.HiApiUrl, shunt))
		} else if action == "domain" {
			// 域名命令
			c.String(http.StatusOK, hi.GetDomain(shunt))
		} else {
			// 参数错误
			c.Status(http.StatusForbidden)
		}
	}
}

// otherCmdr 根据token获取命令
func otherCmdr(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Param("token")

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		if !hiVerifySign(br, c) {
			c.Status(http.StatusBadRequest)
			return
		}

		var cmdr hi.CmdrModel
		db.Table("hi_cmdr").Where(map[string]interface{}{
			"token": token,
		}).Last(&cmdr)
		if cmdr.ID > 0 {
			c.String(http.StatusOK, cmdr.Cmd)
		} else {
			c.Status(http.StatusBadRequest)
		}
	}
}

// syncVersion 同步版本到路由器
func syncVersion(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		user, authErr := userAuth(c, db, "")
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		versionType := jsoniter.Get(content, "type").ToString()
		description := jsoniter.Get(content, "description").ToString()

		if !hi.InArray(versionType, []string{"firmware", "ipk", "rtty"}) {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "版本类型错误",
				"data": gin.H{},
			})
			return
		}
		var version hi.VersionModel
		db.Table("hi_version").Where(map[string]interface{}{
			"openid":      user.Openid,
			"description": description,
			"type":        versionType,
		}).Last(&version)

		version.Version = jsoniter.Get(content, "version").ToString()
		version.Notes = jsoniter.Get(content, "notes").ToString()
		version.Url = jsoniter.Get(content, "url").ToString()
		version.Size = jsoniter.Get(content, "size").ToInt()
		version.Md5 = jsoniter.Get(content, "md5").ToString()

		if version.ID != 0 {
			result := db.Table("hi_version").Save(&version)
			if result.Error != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "更新失败",
					"data": gin.H{
						"error": result.Error.Error(),
					},
				})
				return
			}
		} else {
			version.Openid = user.Openid
			version.Type = versionType
			version.Description = description
			result := db.Table("hi_version").Create(&version)
			if result.Error != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "创建失败",
					"data": gin.H{
						"error": result.Error.Error(),
					},
				})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"ret": 1,
			"msg": "success",
			"data": gin.H{
				"token":   hiSyncVersion(br, user.Openid, ""),
				"version": version,
			},
		})
	}
}

// otherWiFi 创建删除 WiFi
func otherWiFi(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)
		//执行校验
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}
		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		report := fmt.Sprintf("%s/hi/base/report/wifi", br.cfg.HiApiUrl)
		//根据action执行不同的动作
		if action == "create" { //新增wifi命令
			var addWifi hi.AddWifiModel
			if err := json.Unmarshal(content, &addWifi); err == nil {
				addWifis := []hi.AddWifiModel{
					addWifi,
				}
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.AddWifiCmd(addWifis, report, ""), AddWifi)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
					return
				}
				hiExecRequest(br, c, cmdr)
				return
			}
		} else if action == "delete" { //执行删除wifi命令
			var deleteWifi hi.DeleteWifiModal
			err := json.Unmarshal(content, &deleteWifi)
			if err != nil || len(deleteWifi.Wifinets) < 1 {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "参数错误",
					"data": gin.H{},
				})
				return
			}

			cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.DelWifiCmd(deleteWifi.Wifinets, report, ""), DelWifi)
			if terr != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "创建失败",
					"data": gin.H{
						"error": terr.Error(),
					},
				})
				return
			}
			hiExecRequest(br, c, cmdr)
			return
		}
		c.Status(http.StatusBadRequest)
	}
}

// otherWiFi2 队列创建删除修改 WiFi
func otherWiFi2(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)
		if action != "create" && action != "delete" && action != "edit" {
			c.Status(http.StatusBadRequest)
			return
		}
		if len(onlyid) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "设备不在线",
				"data": nil,
			})
			return
		}
		//执行校验
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)
		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}
		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		token := utils.GenUniqueID(action)
		report := fmt.Sprintf("%s/hi/base/report/wifi", br.cfg.HiApiUrl)
		callbackUrl := jsoniter.Get(content, "call_url").ToString()

		var cmdr *hi.CmdrModel
		var terr error
		//根据action执行不同的动作
		if action == "create" { //新增wifi命令
			wifiContent := jsoniter.Get(content, "wifis").ToString()
			var addWifis []hi.AddWifiModel
			err := json.Unmarshal([]byte(wifiContent), &addWifis)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "参数错误",
					"data": gin.H{},
				})
				return
			}
			cmdr, terr = hi.CreateCmdr(db, devid, onlyid, hi.AddWifiCmd(addWifis, report, token), AddWifi)
			if terr != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "添加失败",
					"data": gin.H{
						"error": terr.Error(),
					},
				})
				return
			}

		} else if action == "delete" { //执行删除wifi命令
			var deleteWifi hi.DeleteWifiModal
			err := json.Unmarshal(content, &deleteWifi)
			if err != nil || len(deleteWifi.Wifinets) < 1 {
				c.JSON(http.StatusOK, gin.H{
					"ret":  0,
					"msg":  "参数错误",
					"data": gin.H{},
				})
				return
			}
			cmdr, terr = hi.CreateCmdr(db, devid, onlyid, hi.DelWifiCmd(deleteWifi.Wifinets, report, token), DelWifi)
			if terr != nil {
				c.JSON(http.StatusOK, gin.H{
					"ret": 0,
					"msg": "删除失败",
					"data": gin.H{
						"error": terr.Error(),
					},
				})
				return
			}
		} else { //修改wifi命令
			var wifi hi.WifiModel
			if err := json.Unmarshal(content, &wifi); err == nil {
				cmdr, terr = hi.CreateCmdr(db, devid, onlyid, hi.EditWifiCmd(wifi, report, token), EditWifi)
				if terr != nil {
					c.JSON(http.StatusOK, gin.H{
						"ret": 0,
						"msg": "创建失败",
						"data": gin.H{
							"error": terr.Error(),
						},
					})
					return
				}
			}
		}
		_, err = hi.CreateWifiTask(db, cmdr, token, devid, onlyid, action, string(content), callbackUrl)
		msg := "添加失败"
		successMsg := "添加成功"
		if action == "delete" {
			msg = "删除失败"
			successMsg = "删除成功"
		} else if action == "edit" {
			msg = "修改失败"
			successMsg = "修改成功"
		}
		if terr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": msg,
				"data": gin.H{
					"error": terr.Error(),
				},
			})
			return
		}
		go hiExecWifiTask(br, devid)
		c.JSON(http.StatusOK, gin.H{
			"ret":  1,
			"msg":  successMsg,
			"data": gin.H{},
		})
	}
}

// otherDiagnosis 网络诊断
func otherDiagnosis(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		typ := c.Param("type")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)
		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}
		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		callbackUrl := jsoniter.Get(content, "callback_url").ToString()
		batch := jsoniter.Get(content, "batch").ToString()
		ip := jsoniter.Get(content, "ip").ToString()
		cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.DiagnosisCmd(callbackUrl, typ, batch, ip), Diagnosis)
		if terr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "创建失败",
				"data": gin.H{
					"error": terr.Error(),
				},
			})
			return
		}
		hiExecRequest(br, c, cmdr)
	}
}

// checkIsBound 设备是否已经被绑定
func checkIsBound(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		devid := c.Param("devid")
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)
		var deviceData hi.DeviceModel
		db.Table("hi_device").Where(map[string]interface{}{
			"devid": devid,
		}).Last(&deviceData)
		c.JSON(http.StatusOK, gin.H{
			"ret": 1,
			"msg": "success",
			"data": gin.H{
				"is_bound": deviceData.BindOpenid != "",
			},
		})
	}
}

// verifyPassword 验证密码
func verifyPassword(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		devid := c.Param("devid")
		content, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}
		passwd := jsoniter.Get(content, "password").ToString()

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		var deviceData hi.DeviceModel
		db.Table("hi_device").Where(map[string]interface{}{
			"devid": devid,
		}).Last(&deviceData)

		hash := hi.StringMd5(fmt.Sprintf("%s:%s", hi.StringMd5(fmt.Sprintf("admin:%s", passwd)), devid))
		pass := hash == deviceData.Password
		retCode := 0
		msg := "Verification failed"
		if pass {
			retCode = 1
			msg = "Verification successful"
		}
		c.JSON(http.StatusOK, gin.H{
			"ret": retCode,
			"msg": msg,
			"data": gin.H{
				"pass": pass,
			},
		})
	}
}

// uploadLog 上传日志
func uploadLog(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {

		if !hiVerifySign(br, c) {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		devid := c.Param("devid")
		isManual := c.Query("is_manual")
		adminId := c.Query("admin_id")
		logType := c.Query("log_type")
		var deviceData hi.DeviceModel
		db.Table("hi_device").Where("devid = ?", devid).First(&deviceData)
		if deviceData.BindOpenid == "" || deviceData.ReportUrl == "" {
			c.Status(http.StatusBadRequest)
			return
		}

		file, err := c.FormFile("file")
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		f, err := file.Open()
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		defer f.Close()

		// 上传到控制中心
		_, _ = gohttp.NewRequest().
			UploadFromReader(gohttp.MultipartParam{FieldName: "file", FileName: file.Filename, FileBody: f}).
			Post(deviceData.ReportUrl + fmt.Sprintf("?devid=%s&type=%s&is_manual=%s&admin_id=%s&log_type=%s", deviceData.Devid, "upload_log", isManual, adminId, logType))
		c.Status(http.StatusOK)
	}
}

// fetchLog 手动获取日志
func fetchLog(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {
		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)

		devid := c.Param("devid")
		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}

		onlyid := devidGetOnlyid(br, devid)
		if len(onlyid) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"ret":  0,
				"msg":  "设备不在线",
				"data": nil,
			})
			return
		}

		url := fmt.Sprintf("%s/hi/other/upload-log/%s", br.cfg.HiApiUrl, devid)
		cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.FetchLogCmd(url, "yes", c.Query("admin_id")), FetchLog)
		if terr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "创建执行任务失败",
				"data": gin.H{
					"error": terr.Error(),
				},
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"token": hiExecCommand(br, cmdr, "", ""),
				},
			})
		}
	}
}

// getCmdrLog 获取执行命令日志
func getCmdrLog(br *broker) gin.HandlerFunc {
	return func(c *gin.Context) {

		db, err := hi.InstanceDB(br.cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer closeDB(db)
		devid := c.Param("devid")
		_, authErr := userAuth(c, db, devid)
		if authErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "Authentication failed",
				"data": gin.H{
					"error": authErr.Error(),
				},
			})
			return
		}
		startTime := c.Query("start_time")
		endTime := c.Query("end_time")

		page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "params error",
			})
			return
		}
		pageSize, err := strconv.Atoi(c.DefaultQuery("pagesize", "10"))
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"ret": 0,
				"msg": "params error",
			})
			return
		}

		action := c.Query("action")
		where := map[string]interface{}{
			"devid": devid,
		}
		if action != "" {
			where["action"] = action
		}

		type cmd struct {
			ID        uint32 `json:"id"`
			Action    string `json:"action"`
			Cmd       string `json:"cmd"`
			Result    string `json:"result"`
			StartTime uint32 `json:"start_time"`
			EndTime   uint32 `json:"end_time"`
		}
		var cmds []cmd
		tx := db.Table("hi_cmdr").Where(where)
		if startTime != "" && endTime != "" {
			tx.Where("start_time between ? and ?", startTime, endTime)
		}
		tx.Limit(pageSize).Offset(pageSize * (page - 1)).Order("id desc").Find(&cmds)

		totalTx := db.Table("hi_cmdr").Where(where)
		if startTime != "" && endTime != "" {
			tx.Where("start_time between ? and ?", startTime, endTime)
		}
		var total, over int64
		totalTx.Count(&total)
		if total%int64(pageSize) > 0 {
			over = 1
		}

		c.JSON(http.StatusOK, gin.H{
			"ret": 1,
			"msg": "success",
			"data": gin.H{
				"last_page": total/int64(pageSize) + over,
				"page":      page,
				"pagesize":  pageSize,
				"total":     total,
				"data":      cmds,
			},
		})
	}
}
