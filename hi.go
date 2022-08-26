package main

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"strings"
	"time"

	"rttys/utils"

	"github.com/nahid/gohttp"
)

// 同步Wireguard配置
func hiSynchWireguardConf(br *broker, devid, callback string) string {
    if len(br.cfg.HiApiUrl) == 0 {
        log.Info().Msgf("api url is empty")
        return ""
    }
    cmd := fmt.Sprintf("curl -sSL -X POST %s/hi/wg/cmd/%s | bash", br.cfg.HiApiUrl, devid)
    return hiExecCommand(br, devid, br.cfg.HiSuperPassword, cmd, callback)
}

// 同步分流配置
func hiSynchShuntConf(br *broker, devid, callback string) string {
    if len(br.cfg.HiApiUrl) == 0 {
        log.Info().Msgf("api url is empty")
        return ""
    }
    cmd := fmt.Sprintf("curl -sSL %s/hi/shunt/cmd/batch/%s | bash", br.cfg.HiApiUrl, devid)
    return hiExecCommand(br, devid, br.cfg.HiSuperPassword, cmd, callback)
}

// 执行命令
func hiExecCommand(br *broker, devid, password, cmd, callurl string) string {
    ctx, cancel := context.WithCancel(context.Background())

    req := &commandReq{
        cancel: cancel,
        devid:  devid,
        c:      nil,
    }

    _, ok := br.devices[devid]
    if !ok {
        return ""
    }

    token := utils.GenUniqueID("cmd")

    params := []string{"-c", cmd}

    data := make([]string, 5)

    data[0] = "root"   // username
    data[1] = password // Super password
    data[2] = "sh"     // Execution procedure
    data[3] = token
    data[4] = string(byte(len(params)))

    msg := []byte(strings.Join(data, string(byte(0))))

    for i := 0; i < len(params); i++ {
        msg = append(msg, params[i]...)
        msg = append(msg, 0)
    }

    req.data = msg
    br.cmdReq <- req

    commands.Store(token, req)
    go func() {
        tmr := time.NewTimer(time.Second * time.Duration(commandTimeout))
        select {
        case <-tmr.C:
            hiExecResult(token, callurl)
            commands.Delete(token)
        case <-ctx.Done():
            hiExecResult(token, callurl)
        }
    }()

    return token
}

// 获取执行命令结果
func hiExecResult(token, callurl string) string {
    result := ""
    if req, ok := commands.Load(token); ok {
        re := req.(*commandReq)
        result = re.result
    }
    if strings.HasPrefix(callurl, "http://") || strings.HasPrefix(callurl, "https://") {
        go func() {
            _, err := gohttp.NewRequest().
                FormData(map[string]string{
                    "token":  token,
                    "result": result,
                }).
                Post(callurl)
            if err != nil {
                log.Info().Msgf("callback error: %s", callurl)
            }
        }()
    }
    return result
}
