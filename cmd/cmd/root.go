package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"rttys/cmd/model"
	"rttys/hi"
	"time"
)

var specifiedDay string

var rootCmd = &cobra.Command{
	Use:   "statistic-status",
	Short: "Summary statistic status by day",
	Long:  "Summary statistic status by day",
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

		if specifiedDay != "" {
			_, err := time.ParseInLocation(layoutDate, specifiedDay, loc)
			if err != nil {
				log.Fatal("specified day error")
			}
		}
	},
	Run: func(cmd *cobra.Command, args []string) {

		var theDay string
		if specifiedDay != "" {
			theDay = specifiedDay
		} else {
			theDay = time.Now().Add(-DaySeconds * time.Second).Format(layoutDate)
		}
		theDayStartStr := theDay + " 00:00:00"
		theDayStartTime, err := time.ParseInLocation(layoutDatetime, theDayStartStr, loc)
		if err != nil {
			log.Fatal("parse time error:" + err.Error())
		}
		theDayStart := theDayStartTime.Unix()
		nextDayStart := theDayStart + DaySeconds
		dayBeforeTheDay := time.Unix(theDayStart, 0).Add(-DaySeconds).Format(layoutDate)

		var (
			ss            []model.StatisticsStatus
			msgs          []model.Message
			yesterdayMsgs []model.Message
		)
		allRecords = make(map[string]model.StatisticsStatus, 1)
		// 前一天的数据
		db.Table("hi_statistics_status").Where("date = ?", dayBeforeTheDay).Find(&ss)
		// 当天的数据
		db.Table("hi_messages").Where("action in ?", []string{Off, On}).
			Where("created_at between ? and ?", theDayStart, theDayStart+DaySeconds).
			Order("created_at asc").Find(&yesterdayMsgs)

		for _, s := range ss {
			msgs = append(msgs, model.Message{
				ID:        0,
				Devid:     s.Devid,
				Action:    s.LastAction,
				CreatedAt: uint32(theDayStart),
			})
		}
		for _, yesterdayMsg := range yesterdayMsgs {
			msgs = append(msgs, yesterdayMsg)
		}
		var devIDs []string
		for _, msg := range msgs {
			if !hi.InArray(msg.Devid, devIDs) {
				devIDs = append(devIDs, msg.Devid)
			}
		}
		// 按设备分组
		for _, devID := range devIDs {
			var deviceMsgs []model.Message
			for _, msg := range msgs {
				if msg.Devid == devID {
					deviceMsgs = append(deviceMsgs, msg)
				}
			}
			// hack: 最后添加一条不一样的状态，方便计算
			endMsg := deviceMsgs[len(deviceMsgs)-1]
			tmpAction := Off
			if endMsg.Action == Off {
				tmpAction = On
			}
			deviceMsgs = append(deviceMsgs, model.Message{
				ID:        0,
				Devid:     devID,
				Action:    tmpAction,
				CreatedAt: uint32(nextDayStart),
			})

			handleMessagesByDay(devID, theDay, deviceMsgs)
		}

		db.Table("hi_statistics_status").Where("date = ?", theDay).Delete(&model.StatisticsStatus{})
		var statistic []model.StatisticsStatus
		for _, item := range allRecords {
			statistic = append(statistic, item)
		}
		// 批量插入
		db.Table("hi_statistics_status").Create(&statistic)
	},
}

func handleMessagesByDay(devID string, msgDate string, msgs []model.Message) {
	// 连续相同动作，保留第一条
	var handledMessages []model.Message
	var lastMessage model.Message
	for i, msg := range msgs {
		if i == 0 {
			lastMessage = msg
			handledMessages = append(handledMessages, msg)
			continue
		}
		if msg.Action != lastMessage.Action {
			handledMessages = append(handledMessages, msg)
		}
		lastMessage = msg
	}

	for i, message := range handledMessages {
		if i == 0 {
			lastMessage = message
			continue
		}
		updateMap(devID, msgDate, lastMessage.Action, message.CreatedAt, lastMessage.CreatedAt)
		lastMessage = message
	}
}

func Execute() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().StringVar(&specifiedDay, "day", "", "specified day, eg: 2020-02-02")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
