package hi

import (
	"database/sql/driver"
	"encoding/json"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"strings"
	"time"
)

type Array []string

type UserModel struct {
	ID     uint32 `json:"id"`
	Openid string `json:"openid"`
	Public string `json:"public"`
	Time   uint32 `json:"time"`
}

type DeviceModel struct {
	ID          uint32 `json:"id"`
	Devid       string `json:"devid"`
	Onlyid      string `json:"onlyid"`
	Description string `json:"description"`
	Version     string `json:"version"`
	WebVersion  string `json:"web_version"`
	Online      uint32 `json:"online"`
	BindOpenid  string `json:"bind_openid"`
	ReportUrl   string `json:"report_url"`
	BindTime    uint32 `json:"bind_time"`
}

type DeviceApiModel struct {
	DeviceModel
	IsOnline bool `json:"is_online"`
}

type InfoModel struct {
	ID     uint32 `json:"id"`
	Type   string `json:"type"`
	Devid  string `json:"devid"`
	Onlyid string `json:"onlyid"`
	Result string `json:"result"`
	Time   uint32 `json:"time"`
}

type ShuntModel struct {
	ID     uint32 `json:"id"`
	Devid  string `json:"devid"`
	Onlyid string `json:"onlyid"`
	Source string `json:"source"`
	Rule   string `json:"rule"`
	Prio   uint32 `json:"prio"`
	OutIp  string `json:"out_ip"`
	Status string `json:"status"`
}

type VersionModel struct {
	ID      uint32 `json:"id"`
	Devid   string `json:"devid"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Notes   string `json:"notes"`
	Url     string `json:"url"`
}

type WgModel struct {
	ID        uint32 `json:"id"`
	Devid     string `json:"devid"`
	Onlyid    string `json:"onlyid"`
	Conf      string `json:"conf"`
	LanIp     string `json:"lan_ip"`
	DnsServer string `json:"dns_server"`
	Status    string `json:"status"`
}

type CmdrModel struct {
	ID        uint32 `json:"id"`
	Devid     string `json:"devid"`
	Onlyid    string `json:"onlyid"`
	Token     string `json:"token"`
	Cmd       string `json:"cmd"`
	Result    string `json:"result"`
	StartTime uint32 `json:"start_time"`
	EndTime   uint32 `json:"end_time"`
}

func InstanceDB(str string) (*gorm.DB, error) {
	sp := strings.Split(str, "://")
	dbType := "sqlite"
	dbPath := str
	if len(sp) == 2 {
		dbType = strings.ToLower(sp[0])
		dbPath = sp[1]
	}
	if dbType == "mysql" {
		return gorm.Open(mysql.Open(dbPath), &gorm.Config{})
	} else {
		return gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	}
}

func (t *Array) Scan(value string) error {
	return json.Unmarshal([]byte(value), t)
}

func (t Array) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func String2Array(value string) Array {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		if len(value) > 0 {
			return []string{value}
		}
		return []string{}
	}
	var arr Array
	err := arr.Scan(value)
	if err != nil {
		return nil
	}
	return arr
}

func Array2String(array Array) string {
	marshal, err := json.Marshal(array)
	if err != nil {
		return ""
	}
	return string(marshal)
}

func CreateCmdr(db *gorm.DB, devid, onlyid, cmd string) (*CmdrModel, error) {
	cmdr := &CmdrModel{
		Devid:     devid,
		Onlyid:    onlyid,
		Token:     RandString(32),
		Cmd:       strings.TrimSpace(cmd),
		StartTime: uint32(time.Now().Unix()),
	}
	result := db.Table("hi_cmdr").Create(&cmdr)
	if result.Error != nil {
		return nil, result.Error
	}
	return cmdr, nil
}
