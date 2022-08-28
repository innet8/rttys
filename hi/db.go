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
	Out    string `json:"out"`
}

type WgModel struct {
	ID     uint32 `json:"id"`
	Devid  string `json:"devid"`
	Onlyid string `json:"onlyid"`
	Conf   string `json:"conf"`
	LanIp  string `json:"lan_ip"`
	Status string `json:"status"`
}

type CmdRecordModel struct {
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

func CreateCmdRecord(db *gorm.DB, devid, onlyid, cmd string) (*CmdRecordModel, error) {
	cmdRecord := &CmdRecordModel{
		Devid:     devid,
		Onlyid:    onlyid,
		Token:     RandString(24),
		Cmd:       strings.TrimSpace(cmd),
		StartTime: uint32(time.Now().Unix()),
	}
	result := db.Table("hi_cmd_record").Create(&cmdRecord)
	if result.Error != nil {
		return nil, result.Error
	}
	return cmdRecord, nil
}
