package cmd

import (
	"gorm.io/gorm"
	"rttys/cmd/model"
	"time"
)

const Off = "disconnected"
const On = "connected"
const DaySeconds = 86400

var (
	rttysDB        string
	db             *gorm.DB
	layoutDate     = "2006-01-02"
	layoutDatetime = "2006-01-02 15:04:05"
	allRecords     map[string]model.StatisticsStatus
	loc, _         = time.LoadLocation("Local")
)

func updateMap(devID string, date string, status string, end uint32, start uint32) {
	key := devID + ":" + date
	var (
		online  uint32
		offline uint32
	)
	if status == Off {
		offline = end - start
	} else {
		online = end - start
	}

	if v, ok := allRecords[key]; ok {
		v.Offline += offline
		v.Online += online
		v.LastAction = status
		allRecords[key] = v
	} else {
		allRecords[key] = model.StatisticsStatus{
			Devid:      devID,
			Date:       date,
			Online:     online,
			Offline:    offline,
			LastAction: status,
		}
	}
}
