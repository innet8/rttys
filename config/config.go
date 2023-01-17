package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/kylelemons/go-gypsy/yaml"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var (
	BotUrl      = ""
	BotVersion  = ""
	BotToken    = ""
	BotDialogId = ""
	BotSilence  = ""

	RedisHost     = ""
	RedisPort     = ""
	RedisPassword = ""
)

// Config struct
type Config struct {
	AddrDev           string
	AddrUser          string
	AddrHttpProxy     string
	HttpProxyRedirURL string
	HttpProxyPort     int
	SslCert           string
	SslKey            string
	SslCacert         string // mTLS for device
	Token             string
	WhiteList         map[string]bool
	DB                string
	LocalAuth         bool
	HiApiUrl          string
	HiSuperPassword   string
}

func getConfigOpt(yamlCfg *yaml.File, name string, opt interface{}) {
	val, err := yamlCfg.Get(name)
	if err != nil {
		return
	}

	switch opt := opt.(type) {
	case *string:
		*opt = val
	case *int:
		*opt, _ = strconv.Atoi(val)
	}
}

// Parse config
func Parse(c *cli.Context) *Config {
	cfg := &Config{
		AddrDev:           c.String("addr-dev"),
		AddrUser:          c.String("addr-user"),
		AddrHttpProxy:     c.String("addr-http-proxy"),
		HttpProxyRedirURL: c.String("http-proxy-redir-url"),
		SslCert:           c.String("ssl-cert"),
		SslKey:            c.String("ssl-key"),
		SslCacert:         c.String("ssl-cacert"),
		Token:             c.String("token"),
		DB:                c.String("db"),
		LocalAuth:         c.Bool("local-auth"),
		HiApiUrl:          c.String("hi-api-url"),
		HiSuperPassword:   c.String("hi-super-password"),
	}

	cfg.WhiteList = make(map[string]bool)

	whiteList := c.String("white-list")

	if whiteList == "*" {
		cfg.WhiteList = nil
	} else {
		for _, id := range strings.Fields(whiteList) {
			cfg.WhiteList[id] = true
		}
	}

	yamlCfg, err := yaml.ReadFile(c.String("conf"))
	if err == nil {
		getConfigOpt(yamlCfg, "addr-dev", &cfg.AddrDev)
		getConfigOpt(yamlCfg, "addr-user", &cfg.AddrUser)
		getConfigOpt(yamlCfg, "addr-http-proxy", &cfg.AddrHttpProxy)
		getConfigOpt(yamlCfg, "http-proxy-redir-url", &cfg.HttpProxyRedirURL)
		getConfigOpt(yamlCfg, "ssl-cert", &cfg.SslCert)
		getConfigOpt(yamlCfg, "ssl-key", &cfg.SslKey)
		getConfigOpt(yamlCfg, "ssl-cacert", &cfg.SslCacert)
		getConfigOpt(yamlCfg, "token", &cfg.Token)
		getConfigOpt(yamlCfg, "db", &cfg.DB)
		getConfigOpt(yamlCfg, "hi-api-url", &cfg.HiApiUrl)
		getConfigOpt(yamlCfg, "hi-super-password", &cfg.HiSuperPassword)

		// 推送消息机器人
		getConfigOpt(yamlCfg, "bot-url", &BotUrl)
		getConfigOpt(yamlCfg, "bot-version", &BotVersion)
		getConfigOpt(yamlCfg, "bot-token", &BotToken)
		getConfigOpt(yamlCfg, "bot-dialog_id", &BotDialogId)
		getConfigOpt(yamlCfg, "bot-silence", &BotSilence)

		getConfigOpt(yamlCfg, "redis-host", &RedisHost)
		getConfigOpt(yamlCfg, "redis-port", &RedisPort)
		getConfigOpt(yamlCfg, "redis-password", &RedisPassword)

		val, err := yamlCfg.Get("white-list")
		if err == nil {
			if val == "*" || val == "\"*\"" {
				cfg.WhiteList = nil
			} else {
				for _, id := range strings.Fields(val) {
					cfg.WhiteList[id] = true
				}
			}
		}
	}

	if cfg.SslCert != "" && cfg.SslKey != "" {
		_, err := os.Lstat(cfg.SslCert)
		if err != nil {
			log.Error().Msg(err.Error())
			cfg.SslCert = ""
		}

		_, err = os.Lstat(cfg.SslKey)
		if err != nil {
			log.Error().Msg(err.Error())
			cfg.SslKey = ""
		}
	}

	return cfg
}
