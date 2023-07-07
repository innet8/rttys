package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"rttys/cmd/model"
	"rttys/hi"
	"runtime"
	"time"
)

func init() {
	rootCmd.AddCommand(allCmd)
}

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Summary statistic status by all time",
	Long:  "Summary statistic status by all time",
	PreRun: func(cmd *cobra.Command, args []string) {
		rttysDB = os.Getenv("RTTYS_DB")
		if rttysDB == "" {
			log.Fatal("env RTTYS_DB is required")
		}
		var err error
		db, err = hi.InstanceDB(rttysDB)
		if err != nil {
			log.Fatal("init db occurred error")
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		defer func() {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			fmt.Printf("本次运行总共分配内存：%d\n", mem.Alloc)
		}()
		handle()
	},
}

func handle() {
	var msgs []model.Message
	var devIDs []string
	db.Table("hi_messages").Where("action in ?", []string{Off, On}).Order("created_at asc").Find(&msgs)
	for _, msg := range msgs {
		if !hi.InArray(msg.Devid, devIDs) {
			devIDs = append(devIDs, msg.Devid)
		}
	}

	// 清空所有
	db.Exec("TRUNCATE TABLE hi_statistics_status")

	for _, devID := range devIDs {
		// 初始化map
		allRecords = make(map[string]model.StatisticsStatus, 1)
		var deviceMsgs []model.Message
		for _, msg := range msgs {
			if msg.Devid == devID {
				deviceMsgs = append(deviceMsgs, msg)
			}
		}
		// hack: 最后添加一条不一样的状态，方便计算
		lastMsg := deviceMsgs[len(deviceMsgs)-1]
		tmpAction := Off
		if lastMsg.Action == Off {
			tmpAction = On
		}
		deviceMsgs = append(deviceMsgs, model.Message{
			ID:        0,
			Devid:     devID,
			Action:    tmpAction,
			CreatedAt: uint32(time.Now().Unix()),
		})

		handleMessages(devID, deviceMsgs)

		var statistic []model.StatisticsStatus
		for _, item := range allRecords {
			statistic = append(statistic, item)
		}
		// 批量插入
		db.Table("hi_statistics_status").Create(&statistic)
	}
}

func handleMessages(devId string, messages []model.Message) {
	// 连续相同动作，保留第一条
	var handledMessages []model.Message
	var lastMessage model.Message
	for i, message := range messages {
		if i == 0 {
			lastMessage = message
			handledMessages = append(handledMessages, message)
			continue
		}
		if message.Action != lastMessage.Action {
			handledMessages = append(handledMessages, message)
		}
		lastMessage = message
	}

	for i, message := range handledMessages {
		if i == 0 {
			lastMessage = message
			continue
		}

		lastMsgEndSec := time.Unix(int64(lastMessage.CreatedAt), 0).Format(layoutDate) + " 23:59:59"
		lastMsgDayEnd, err := time.ParseInLocation(layoutDatetime, lastMsgEndSec, loc)
		if err != nil {
			panic(err)
		}
		lastMsgDate := time.Unix(int64(lastMessage.CreatedAt), 0).Format(layoutDate)
		msgDate := time.Unix(int64(message.CreatedAt), 0).Format(layoutDate)
		if lastMsgDate != msgDate { // 不是同一天，分多段
			updateMap(devId, lastMsgDate, lastMessage.Action, uint32(lastMsgDayEnd.Unix())+1, lastMessage.CreatedAt)
			// 跨度大于 ( 1 天 + 上个记录日期剩余秒数 )
			if message.CreatedAt > (uint32(lastMsgDayEnd.Unix()) + DaySeconds) {
				days := (message.CreatedAt - lastMessage.CreatedAt) / DaySeconds
				for i2 := 0; i2 < int(days); i2++ {
					tmpDate := time.Unix(int64(lastMessage.CreatedAt)+int64(DaySeconds*(i2+1)), 0).Format(layoutDate)
					if tmpDate != msgDate {
						updateMap(devId, tmpDate, lastMessage.Action, DaySeconds, 0)
					}
				}
			}
			recordStartSec := msgDate + " 00:00:00"
			recordDayStart, err := time.ParseInLocation(layoutDatetime, recordStartSec, loc)
			if err != nil {
				panic(err)
			}
			updateMap(devId, msgDate, lastMessage.Action, message.CreatedAt, uint32(recordDayStart.Unix()))
		} else { // 同一天
			updateMap(devId, msgDate, lastMessage.Action, message.CreatedAt, lastMessage.CreatedAt)
		}
		lastMessage = message
	}
}
