package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"rttys/utils"

	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
)

const commandTimeout = 30 // second

const (
	rttyCmdErrInvalid = 1001
	rttyCmdErrOffline = 1002
	rttyCmdErrTimeout = 1003
)

var cmdErrMsg = map[int]string{
	rttyCmdErrInvalid: "invalid format",
	rttyCmdErrOffline: "device offline",
	rttyCmdErrTimeout: "timeout",
}

type commandInfo struct {
	Cmd      string `json:"cmd"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type commandReq struct {
	cancel context.CancelFunc
	c      *gin.Context
	devid  string
	data   []byte
	h      *hiReq
}

type commandRes struct {
	Code   int32  `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

type hiReq struct {
	db     string
	token  string
	result string
}

var commands sync.Map

func handleCmdResp(data []byte) {
	token := jsoniter.Get(data, "token").ToString()

	if req, ok := commands.Load(token); ok {
		res := req.(*commandReq)
		attrs := jsoniter.Get(data, "attrs").ToString()
		if res.h != nil && len(res.h.token) > 0 {
			res.h.result = fmt.Sprintf(`{"ret":1,"msg":"","data":%s}`, attrs)
			var d commandRes
			if o := json.Unmarshal([]byte(attrs), &d); o == nil {
				if d.Code != 0 {
					res.h.result = fmt.Sprintf(`{"ret":0,"msg":"","data":%s}`, attrs)
				}
			}
			go hiExecResult(res.h)
			if res.c != nil {
				res.c.String(http.StatusOK, res.h.result)
			}
		} else {
			if res.c != nil {
				res.c.String(http.StatusOK, attrs)
			}
		}
		res.cancel()
	}
}

func cmdErrReply(err int, req *commandReq) {
	req.c.JSON(http.StatusOK, gin.H{
		"err": err,
		"msg": cmdErrMsg[err],
	})
	req.cancel()
}

func handleCmdReq(br *broker, c *gin.Context) {
	devid := c.Param("devid")

	ctx, cancel := context.WithCancel(context.Background())

	req := &commandReq{
		cancel: cancel,
		c:      c,
		devid:  devid,
	}

	_, ok := br.devices[devid]
	if !ok {
		cmdErrReply(rttyCmdErrOffline, req)
		return
	}

	content, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	cmdInfo := commandInfo{}
	err = jsoniter.Unmarshal(content, &cmdInfo)
	if err != nil || cmdInfo.Cmd == "" {
		cmdErrReply(rttyCmdErrInvalid, req)
		return
	}

	token := utils.GenUniqueID("cmd")

	params := jsoniter.Get(content, "params")

	data := make([]string, 5)

	data[0] = jsoniter.Get(content, "username").ToString()
	data[1] = jsoniter.Get(content, "password").ToString()
	data[2] = jsoniter.Get(content, "cmd").ToString()
	data[3] = token
	data[4] = string(byte(params.Size()))

	msg := []byte(strings.Join(data, string(byte(0))))

	for i := 0; i < params.Size(); i++ {
		msg = append(msg, params.Get(i).ToString()...)
		msg = append(msg, 0)
	}

	req.data = msg
	br.cmdReq <- req

	waitTime := commandTimeout

	wait := c.Query("wait")
	if wait != "" {
		waitTime, _ = strconv.Atoi(wait)
	}

	if waitTime == 0 {
		c.Status(http.StatusOK)
		return
	}

	commands.Store(token, req)

	if waitTime < 0 || waitTime > commandTimeout {
		waitTime = commandTimeout
	}

	tmr := time.NewTimer(time.Second * time.Duration(waitTime))

	select {
	case <-tmr.C:
		cmdErrReply(rttyCmdErrTimeout, req)
		commands.Delete(token)
	case <-ctx.Done():
	}
}
