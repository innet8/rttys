package hi

import (
	"database/sql/driver"
	"encoding/json"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"strings"
)

type Array []string

type ShuntInfo struct {
	ID     uint32 `json:"id"`
	Devid  string `json:"devid"`
	Source string `json:"source"`
	Rule   string `json:"rule"`
	Prio   uint32 `json:"prio"`
	Out    string `json:"out"`
}

type WgInfo struct {
	ID     uint32 `json:"id"`
	Devid  string `json:"devid"`
	Conf   string `json:"conf"`
	LanIp  string `json:"lan_ip"`
	Status string `json:"status"`
}

func InstanceDB(str string) (*gorm.DB, error) {
	sp := strings.Split(str, "://")
	if len(sp) == 2 {
		return gorm.Open(sqlite.Open(sp[1]), &gorm.Config{})
	} else {
		return gorm.Open(mysql.Open(sp[1]), &gorm.Config{})
	}
}

func (t *Array) Scan(value string) error {
	return json.Unmarshal([]byte(value), t)
}

func (t Array) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func String2Array(value string) Array {
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
