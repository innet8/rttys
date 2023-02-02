package main

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

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

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
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

	// 创建用户
	r.POST("/hi/user/create", createUser(br))

	// 基础命令 action=dhcp|wifi|static_leases|wireguard_script|wrtbwmon_script|detection_device_script|readDB_awk
	r.GET("/hi/base/cmd/:action", baseCmd(br))

	// 上报接口 action=dhcp|wifi|static_leases|restarted|webpwd|version|rtty_error
	r.POST("/hi/base/report/:action", baseReport(br))

	// 查询信息 action=dhcp|wifi|static_leases	devid=设备id
	r.GET("/hi/base/get/:action/:devid", baseGet(br))

	// 设置信息（需要设备在线才可以设置） action=wifi|static_leases|blocked	devid=设备id
	r.POST("/hi/base/set/:action/:devid", baseSet(br))

	// 设备
	r.GET("/hi/device/list", deviceList(br))

	// 设备 action=bind|unbind|reboot|version|connect|speedtest  devid=设备id
	r.GET("/hi/device/:action/:devid", deviceAction(br))

	// 设备固件/软件升级（需要设备在线） action=ipk|firmware	devid=设备id
	r.POST("/hi/device/upgrade/:action/:devid", deviceUpgrade(br))

	// WG action=set|cancel|get  devid=设备id
	r.POST("/hi/wg/:action/:devid", wireguard(br))

	// 分流 devid=设备id
	r.GET("/hi/shunt/list/:devid", shuntList(br))

	// 分流 devid=设备id  sid=分流id（0表示添加）
	r.POST("/hi/shunt/modify/:devid/:sid", shuntModify(br))

	// 分流 action=info|delete|cmd|domain  sid=分流id
	r.GET("/hi/shunt/:action/:sid", shuntAction(br))

	// 查询执行命令 token=命令token
	r.GET("/hi/other/cmdr/:token", otherCmdr(br))

	// 同步版本
	r.POST("/hi/sync-version", syncVersion(br))

	// wifi设置 action=create|delete  devid=设备id create by weiguowang 2022/10/18
	r.POST("/hi/other/wifi/:action/:devid", otherWiFi(br))

	// wifi设置 action=create|delete|edit
	r.POST("/hi/other/wifi2/:action/:devid", otherWiFi2(br))

	r.POST("/hi/other/diagnosis/:type/:devid", otherDiagnosis(br))

	// 设备是否已经被绑定
	r.GET("/hi/other/is-bound/:devid", checkIsBound(br))

	// 验证密码
	r.POST("/hi/other/verify-password/:devid", verifyPassword(br))

	// 上传日志
	r.POST("/hi/other/upload-log/:devid", uploadLog(br))

	// 手动获取日志
	r.GET("/hi/other/fetch-log/:devid", fetchLog(br))

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
