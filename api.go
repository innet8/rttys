package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"rttys/hi"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"rttys/cache"
	"rttys/config"
	"rttys/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var httpSessions *cache.Cache

//go:embed ui/dist
var staticFs embed.FS

func allowOrigin(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("content-type", "application/json")
}

func httpLogin(cfg *config.Config, creds *credentials) bool {
	if creds.Username == "" || creds.Password == "" {
		return false
	}

	db, err := instanceDB(cfg.DB)
	if err != nil {
		log.Error().Msg(err.Error())
		return false
	}
	defer db.Close()

	cnt := 0

	db.QueryRow("SELECT COUNT(*) FROM account WHERE username = ? AND password = ?", creds.Username, creds.Password).Scan(&cnt)

	return cnt != 0
}

func authorizedDev(devid string, cfg *config.Config) bool {
	if cfg.WhiteList == nil {
		return true
	}

	_, ok := cfg.WhiteList[devid]
	return ok
}

func isLocalRequest(c *gin.Context) bool {
	addr, _ := net.ResolveTCPAddr("tcp", c.Request.RemoteAddr)
	return addr.IP.IsLoopback()
}

func httpAuth(cfg *config.Config, c *gin.Context) bool {
	if !cfg.LocalAuth && isLocalRequest(c) {
		return true
	}

	cookie, err := c.Cookie("sid")
	if err != nil || !httpSessions.Have(cookie) {
		return false
	}

	httpSessions.Active(cookie, 0)

	return true
}

func isAdminUsername(cfg *config.Config, username string) bool {
	if username == "" {
		return false
	}

	db, err := instanceDB(cfg.DB)
	if err != nil {
		log.Error().Msg(err.Error())
		return false
	}
	defer db.Close()

	isAdmin := false

	if db.QueryRow("SELECT admin FROM account WHERE username = ?", username).Scan(&isAdmin) == sql.ErrNoRows {
		return false
	}

	return isAdmin
}

func getLoginUsername(c *gin.Context) string {
	cookie, err := c.Cookie("sid")
	if err != nil {
		return ""
	}

	username, ok := httpSessions.Get(cookie)
	if ok {
		return username.(string)
	}

	return ""
}

func apiStart(br *broker) {
	cfg := br.cfg

	httpSessions = cache.New(30*time.Minute, 5*time.Second)

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	r.Use(gin.Recovery())

	authorized := r.Group("/", func(c *gin.Context) {
		devid := c.Param("devid")
		if devid != "" && authorizedDev(devid, cfg) {
			return
		}

		if !httpAuth(cfg, c) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	authorized.GET("/fontsize", func(c *gin.Context) {
		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer db.Close()

		value := "16"

		db.QueryRow("SELECT value FROM config WHERE name = 'FontSize'").Scan(&value)

		FontSize, _ := strconv.Atoi(value)

		c.JSON(http.StatusOK, gin.H{"size": FontSize})
	})

	authorized.POST("/fontsize", func(c *gin.Context) {
		data := make(map[string]int)

		err := c.BindJSON(&data)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		size, ok := data["size"]
		if !ok {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer db.Close()

		if size < 12 {
			size = 12
		}

		_, err = db.Exec("DELETE FROM config WHERE name = 'FontSize'")
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO config values('FontSize',?)", fmt.Sprintf("%d", size))
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusOK)
	})

	authorized.GET("/connect/:devid", func(c *gin.Context) {
		if c.GetHeader("Upgrade") != "websocket" {
			c.Redirect(http.StatusFound, "/rtty/"+c.Param("devid"))
			return
		}
		serveUser(br, c)
	})

	authorized.GET("/devs", func(c *gin.Context) {
		type DeviceInfo struct {
			ID          string `json:"id"`
			Connected   uint32 `json:"connected"`
			Uptime      uint32 `json:"uptime"`
			Description string `json:"description"`
			Bound       bool   `json:"bound"`
			Online      bool   `json:"online"`
		}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer db.Close()

		sql := "SELECT id, description, username FROM device"

		if cfg.LocalAuth || !isLocalRequest(c) {
			username := getLoginUsername(c)
			if username == "" {
				c.Status(http.StatusUnauthorized)
				return
			}

			if !isAdminUsername(cfg, username) {
				sql += fmt.Sprintf(" WHERE username = '%s'", username)
			}
		}

		devs := make([]DeviceInfo, 0)

		rows, err := db.Query(sql)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		for rows.Next() {
			id := ""
			desc := ""
			username := ""

			err := rows.Scan(&id, &desc, &username)
			if err != nil {
				log.Error().Msg(err.Error())
				break
			}

			di := DeviceInfo{
				ID:          id,
				Description: desc,
				Bound:       username != "",
			}

			if dev, ok := br.devices[id]; ok {
				dev := dev.(*device)
				di.Connected = uint32(time.Now().Unix() - dev.timestamp)
				di.Uptime = dev.uptime
				di.Online = true
			}

			devs = append(devs, di)
		}

		allowOrigin(c.Writer)

		c.JSON(http.StatusOK, devs)
	})

	authorized.POST("/cmd/:devid", func(c *gin.Context) {
		allowOrigin(c.Writer)

		handleCmdReq(br, c)
	})

	r.Any("/web/:devid/:addr/*path", func(c *gin.Context) {
		httpProxyRedirect(br, c)
	})

	r.GET("/authorized/:devid", func(c *gin.Context) {
		authorized := authorizedDev(c.Param("devid"), cfg) || httpAuth(cfg, c)
		c.JSON(http.StatusOK, gin.H{
			"authorized": authorized,
		})
	})

	r.POST("/signin", func(c *gin.Context) {
		var creds credentials

		err := c.BindJSON(&creds)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		if httpLogin(cfg, &creds) {
			sid := utils.GenUniqueID("http")
			httpSessions.Set(sid, creds.Username, 0)

			c.SetCookie("sid", sid, 0, "", "", false, true)

			c.JSON(http.StatusOK, gin.H{
				"sid":      sid,
				"username": creds.Username,
			})
			return
		}

		c.Status(http.StatusForbidden)
	})

	r.GET("/alive", func(c *gin.Context) {
		if !httpAuth(cfg, c) {
			c.AbortWithStatus(http.StatusUnauthorized)
		} else {
			c.Status(http.StatusOK)
		}
	})

	r.GET("/signout", func(c *gin.Context) {
		cookie, err := c.Cookie("sid")
		if err != nil || !httpSessions.Have(cookie) {
			return
		}

		httpSessions.Del(cookie)

		c.Status(http.StatusOK)
	})

	r.POST("/signup", func(c *gin.Context) {
		var creds credentials

		err := c.BindJSON(&creds)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer db.Close()

		isAdmin := 0

		cnt := 0
		db.QueryRow("SELECT COUNT(*) FROM account").Scan(&cnt)
		if cnt == 0 {
			isAdmin = 1
		}

		db.QueryRow("SELECT COUNT(*) FROM account WHERE username = ?", creds.Username).Scan(&cnt)
		if cnt > 0 {
			c.Status(http.StatusForbidden)
			return
		}

		_, err = db.Exec("INSERT INTO account values(?,?,?)", creds.Username, creds.Password, isAdmin)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusOK)
	})

	r.GET("/isadmin", func(c *gin.Context) {
		isAdmin := true

		if cfg.LocalAuth || !isLocalRequest(c) {
			isAdmin = isAdminUsername(cfg, getLoginUsername(c))
		}

		c.JSON(http.StatusOK, gin.H{"admin": isAdmin})
	})

	r.GET("/users", func(c *gin.Context) {
		loginUsername := getLoginUsername(c)
		isAdmin := isAdminUsername(cfg, loginUsername)

		if cfg.LocalAuth || !isLocalRequest(c) {
			if !isAdmin {
				c.Status(http.StatusUnauthorized)
				return
			}
		}

		users := []string{}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}
		defer db.Close()

		rows, err := db.Query("SELECT username FROM account")
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

		for rows.Next() {
			username := ""
			err := rows.Scan(&username)
			if err != nil {
				log.Error().Msg(err.Error())
				break
			}

			if isAdmin && username == loginUsername {
				continue
			}

			users = append(users, username)
		}

		c.JSON(http.StatusOK, gin.H{"users": users})
	})

	r.POST("/bind", func(c *gin.Context) {
		if cfg.LocalAuth || !isLocalRequest(c) {
			username := getLoginUsername(c)
			if !isAdminUsername(cfg, username) {
				c.Status(http.StatusUnauthorized)
				return
			}
		}

		type binddata struct {
			Username string   `json:"username"`
			Devices  []string `json:"devices"`
		}

		data := binddata{}

		err := c.BindJSON(&data)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}
		defer db.Close()

		isAdmin := false

		if db.QueryRow("SELECT admin FROM account WHERE username = ?", data.Username).Scan(&isAdmin) == sql.ErrNoRows || isAdmin {
			c.Status(http.StatusOK)
			return
		}

		for _, devid := range data.Devices {
			db.Exec("UPDATE device SET username = ? WHERE id = ?", data.Username, devid)
		}

		c.Status(http.StatusOK)
	})

	r.POST("/unbind", func(c *gin.Context) {
		if cfg.LocalAuth || !isLocalRequest(c) {
			username := getLoginUsername(c)
			if !isAdminUsername(cfg, username) {
				c.Status(http.StatusUnauthorized)
				return
			}
		}

		type binddata struct {
			Devices []string `json:"devices"`
		}

		data := binddata{}

		err := c.BindJSON(&data)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}
		defer db.Close()

		for _, devid := range data.Devices {
			db.Exec("UPDATE device SET username = '' WHERE id = ?", devid)
		}

		c.Status(http.StatusOK)
	})

	r.POST("/delete", func(c *gin.Context) {
		type deldata struct {
			Devices []string `json:"devices"`
		}

		data := deldata{}

		err := c.BindJSON(&data)
		if err != nil {
			c.Status(http.StatusBadRequest)
			return
		}

		db, err := instanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			return
		}
		defer db.Close()

		username := ""
		if cfg.LocalAuth || !isLocalRequest(c) {
			username = getLoginUsername(c)
			if isAdminUsername(cfg, username) {
				username = ""
			}
		}

		for _, devid := range data.Devices {
			if _, ok := br.devices[devid]; !ok {
				sql := fmt.Sprintf("DELETE FROM device WHERE id = '%s'", devid)

				if username != "" {
					sql += fmt.Sprintf(" AND username = '%s'", username)
				}

				db.Exec(sql)
			}
		}

		c.Status(http.StatusOK)
	})

	r.GET("/file/:sid", func(c *gin.Context) {
		sid := c.Param("sid")
		if fp, ok := br.fileProxy.Load(sid); ok {
			fp := fp.(*fileProxy)
			s := br.sessions[sid]
			fp.Ack(s.dev, sid)

			defer func() {
				if err := recover(); err != nil {
					if ne, ok := err.(*net.OpError); ok {
						if se, ok := ne.Err.(*os.SyscallError); ok {
							if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
								fp.reader.Close()
							}
						}
					}
				}
			}()

			c.DataFromReader(http.StatusOK, -1, "application/octet-stream", fp.reader, nil)
			br.fileProxy.Delete(sid)
		}
	})

	/**************************************************************************************************/
	/***********************************************HI*************************************************/
	/**************************************************************************************************/

	// 创建用户 action=create
	r.POST("/hi/user/:action", func(c *gin.Context) {
		action := c.Param("action")

		if action == "create" {
			db, err := hi.InstanceDB(cfg.DB)
			if err != nil {
				log.Error().Msg(err.Error())
				c.Status(http.StatusInternalServerError)
				return
			}

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
		c.Status(http.StatusForbidden)
	})

	// 基础命令 action=dhcp|wifi|static_leases
	r.GET("/hi/base/cmd/:action", func(c *gin.Context) {
		action := c.Param("action")
		if action == "dhcp" {
			var envMap = make(map[string]interface{})
			envMap["requestUrl"] = "http://127.0.0.1/cgi-bin/api/client/list"
			envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/dhcp", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.ApiReportTemplate(envMap))
			return
		}
		if action == "wifi" {
			var envMap = make(map[string]interface{})
			envMap["requestUrl"] = "http://127.0.0.1/cgi-bin/api/ap/config"
			envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/wifi", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.ApiReportTemplate(envMap))
			return
		}
		if action == "static_leases" {
			var envMap = make(map[string]interface{})
			envMap["requestUrl"] = "static_leases"
			envMap["reportUrl"] = fmt.Sprintf("%s/hi/base/report/static_leases", br.cfg.HiApiUrl)
			c.String(http.StatusOK, hi.ApiReportTemplate(envMap))
			return
		}
		c.Status(http.StatusBadRequest)
	})

	// 上报接口 action=dhcp|wifi|static_leases
	r.POST("/hi/base/report/:action", func(c *gin.Context) {
		action := c.Param("action")

		if action == "dhcp" || action == "wifi" || action == "static_leases" {
			db, err := hi.InstanceDB(cfg.DB)
			if err != nil {
				log.Error().Msg(err.Error())
				c.Status(http.StatusInternalServerError)
				return
			}

			content, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				c.Status(http.StatusBadRequest)
				return
			}

			result := hi.ApiResultCheck(hi.Base64Decode(jsoniter.Get(content, "content").ToString()))
			devid := jsoniter.Get(content, "sn").ToString()
			rtime := jsoniter.Get(content, "time").ToUint32()
			if len(result) > 0 {
				var count int64
				db.Table("hi_info").Where(map[string]interface{}{
					"type":  action,
					"devid": devid,
				}).Where("time > ?", rtime).Count(&count)
				if count == 0 {
					db.Table("hi_info").Create(&hi.InfoModel{
						Devid:  devid,
						Onlyid: devidGetOnlyid(br, devid),
						Type:   action,
						Result: result,
						Time:   rtime,
					})
				}
			}
			c.String(http.StatusOK, "success")
			return
		}
		c.Status(http.StatusBadRequest)
	})

	// 查询信息 action=dhcp|wifi|static_leases	devid=设备id
	r.GET("/hi/base/get/:action/:devid", func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")

		if action == "dhcp" || action == "wifi" || action == "static_leases" {
			db, err := hi.InstanceDB(cfg.DB)
			if err != nil {
				log.Error().Msg(err.Error())
				c.Status(http.StatusInternalServerError)
				return
			}

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
		c.Status(http.StatusBadRequest)
	})

	// 设置信息（需要设备在线才可以设置） action=dhcp|wifi|static_leases	devid=设备id
	r.POST("/hi/base/set/:action/:devid", func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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

		if action == "dhcp" {
			// todo
		}
		if action == "wifi" {
			// cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.EditWifiTemplate(content))
			// if terr != nil {
			// 	c.JSON(http.StatusOK, gin.H{
			// 		"ret": 0,
			// 		"msg": "创建失败",
			// 		"data": gin.H{
			// 			"error": terr.Error(),
			// 		},
			// 	})
			// 	return
			// }
			// hiExecRequest(br, c, cmdr)
			// return
		}
		if action == "static_leases" {
			list := jsoniter.Get(content, "list").ToString()
			var data []hi.StaticLeasesModel
			if ok := json.Unmarshal([]byte(list), &data); ok == nil {
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.StaticLeasesCmd(data))
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
	})

	// 设备
	r.GET("/hi/device/list", func(c *gin.Context) {
		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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

		var devicds []hi.DeviceModel

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
	})

	// 设备 action=bind|unbind|reboot|version|connect  devid=设备id
	r.GET("/hi/device/:action/:devid", func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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
				db.Table("hi_device").Create(&deviceData)
				msg = "添加绑定成功"
			} else if len(deviceData.BindOpenid) == 0 {
				// 绑定
				deviceData.Devid = devid
				deviceData.BindOpenid = authUser.Openid
				deviceData.BindTime = uint32(time.Now().Unix())
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
				cmdr, terr := hi.CreateCmdr(db, devid, onlyid, hi.VersionCmd(name))
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
				c.Status(http.StatusForbidden)
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

		go hiSynchWireguardConf(br, devid, "")
		go hiSynchShuntConf(br, devid, "")
	})

	// 设备固件/软件升级（需要设备在线） action=ipk|firmware	devid=设备id
	r.POST("/hi/device/upgrade/:action/:devid", func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")
		onlyid := devidGetOnlyid(br, devid)

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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
			c.JSON(http.StatusOK, gin.H{
				"ret": 1,
				"msg": "success",
				"data": gin.H{
					"token": hiDeviceIpkUpgrade(br, devid, path, callUrl),
				},
			})
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
	})

	// WG action=set|cancel|get  devid=设备id
	r.POST("/hi/wg/:action/:devid", func(c *gin.Context) {
		action := c.Param("action")
		devid := c.Param("devid")

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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
				db.Table("hi_wg").Where("id != ? AND status = ?", wg.ID, "use").Update("status", "cancel")
				c.JSON(http.StatusOK, gin.H{
					"ret": 1,
					"msg": "success",
					"data": gin.H{
						"token": hiSynchWireguardConf(br, devid, callUrl),
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
					"token": hiSynchWireguardConf(br, devid, callUrl),
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
	})

	// 分流 devid=设备id
	r.GET("/hi/shunt/list/:devid", func(c *gin.Context) {
		devid := c.Param("devid")

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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

		var shunts []hi.ShuntModel

		result := db.Table("hi_shunt").Select([]string{
			"id",
			"devid",
			"onlyid",
			"source",
			"prio",
			"out_ip",
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
	})

	// 分流 devid=设备id  sid=分流id（0表示添加）
	r.POST("/hi/shunt/modify/:devid/:sid", func(c *gin.Context) {
		devid := c.Param("devid")
		shuntId, _ := strconv.Atoi(c.Param("sid"))

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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
				"token": hiSynchShuntConf(br, devid, callUrl),
				"shunt": shunt,
			},
		})
	})

	// 分流 action=info|delete|cmd|domain  sid=分流id
	r.GET("/hi/shunt/:action/:sid", func(c *gin.Context) {
		action := c.Param("action")
		shuntId, _ := strconv.Atoi(c.Param("sid"))
		callUrl := c.Query("call_url")

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
			return
		}

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
					"token": hiSynchShuntConf(br, shunt.Devid, callUrl),
					"shunt": shunt,
				},
			})
		} else if action == "cmd" {
			// 命令
			c.String(http.StatusOK, hi.GetCmd(cfg.HiApiUrl, shunt))
		} else if action == "domain" {
			// 域名命令
			c.String(http.StatusOK, hi.GetDomain(shunt))
		} else {
			// 参数错误
			c.Status(http.StatusForbidden)
		}
	})

	// 查询执行命令 token=命令token
	r.GET("/hi/other/cmdr/:token", func(c *gin.Context) {
		token := c.Param("token")

		db, err := hi.InstanceDB(cfg.DB)
		if err != nil {
			log.Error().Msg(err.Error())
			c.Status(http.StatusInternalServerError)
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
	})

	/**************************************************************************************************/
	/***********************************************HI*************************************************/
	/**************************************************************************************************/

	r.NoRoute(func(c *gin.Context) {
		fs, _ := fs.Sub(staticFs, "ui/dist")

		path := c.Request.URL.Path

		if path != "/" {
			f, err := fs.Open(path[1:])
			if err != nil {
				c.Request.URL.Path = "/"
				r.HandleContext(c)
				return
			}

			if strings.Contains(c.Request.Header.Get("Accept-Encoding"), "gzip") {
				if strings.HasSuffix(path, "css") || strings.HasSuffix(path, "js") {
					magic := make([]byte, 2)
					f.Read(magic)
					if magic[0] == 0x1f && magic[1] == 0x8b {
						c.Writer.Header().Set("Content-Encoding", "gzip")
					}
				}
			}

			f.Close()
		}

		http.FileServer(http.FS(fs)).ServeHTTP(c.Writer, c.Request)
	})

	go func() {
		var err error

		if cfg.SslCert != "" && cfg.SslKey != "" {
			log.Info().Msgf("Listen user on: %s SSL on", cfg.AddrUser)
			err = r.RunTLS(cfg.AddrUser, cfg.SslCert, cfg.SslKey)
		} else {
			log.Info().Msgf("Listen user on: %s SSL off", cfg.AddrUser)
			err = r.Run(cfg.AddrUser)
		}

		log.Fatal().Err(err)
	}()
}
