package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"rttys/config"
	"rttys/utils"
	"rttys/version"

	xlog "rttys/log"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func initDb(cfg *config.Config) error {
	db, err := instanceDB(cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()

	autoIncrement := "AUTOINCREMENT"
	if strings.HasPrefix(strings.ToLower(cfg.DB), "mysql") {
		autoIncrement = "AUTO_INCREMENT"
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS config(name VARCHAR(512) PRIMARY KEY NOT NULL, value TEXT NOT NULL)")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS account(username VARCHAR(512) PRIMARY KEY NOT NULL, password TEXT NOT NULL, admin INT NOT NULL)")
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS device(id VARCHAR(512) PRIMARY KEY NOT NULL, description TEXT NOT NULL, online DATETIME NOT NULL, username TEXT NOT NULL)")
	if err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hi_info(id integer NOT NULL PRIMARY KEY %s, devid TEXT NOT NULL, onlyid TEXT NOT NULL, type TEXT NOT NULL, result TEXT NOT NULL, time integer NOT NULL)`, autoIncrement))
	if err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hi_shunt(id integer NOT NULL PRIMARY KEY %s, devid VARCHAR(100) NOT NULL, onlyid VARCHAR(100) NOT NULL, source TEXT NOT NULL, rule TEXT NOT NULL, prio INT NOT NULL, out_ip VARCHAR(100) NOT NULL, status VARCHAR(20) NOT NULL)`, autoIncrement))
	if err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hi_wg(id integer NOT NULL PRIMARY KEY %s, devid VARCHAR(100) NOT NULL, onlyid VARCHAR(100) NOT NULL, conf TEXT NOT NULL, lan_ip VARCHAR(100) NOT NULL, status VARCHAR(20) NOT NULL)`, autoIncrement))
	if err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hi_cmdr(id integer NOT NULL PRIMARY KEY %s, devid VARCHAR(100) NOT NULL, onlyid VARCHAR(100) NOT NULL, token VARCHAR(100) NOT NULL, cmd TEXT NOT NULL, result TEXT NOT NULL, start_time integer NOT NULL, end_time integer NOT NULL)`, autoIncrement))
	if err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hi_user(id integer NOT NULL PRIMARY KEY %s, openid VARCHAR(100) NOT NULL, public TEXT NOT NULL, time integer NOT NULL)`, autoIncrement))
	if err != nil {
		return err
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hi_device(id integer NOT NULL PRIMARY KEY %s, devid VARCHAR(100) NOT NULL, onlyid VARCHAR(100) NOT NULL, description VARCHAR(255) NOT NULL, online integer NOT NULL, bind_openid VARCHAR(100) NOT NULL, bind_time integer NOT NULL)`, autoIncrement))
	if err != nil {
		return err
	}

	return nil
}

func runRttys(c *cli.Context) {
	xlog.SetPath(c.String("log"))

	if c.Bool("verbose") {
		xlog.Verbose()
	}

	cfg := config.Parse(c)

	log.Info().Msg("Go Version: " + runtime.Version())
	log.Info().Msgf("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)

	log.Info().Msg("Rttys Version: " + version.Version())

	gitCommit := version.GitCommit()
	buildTime := version.BuildTime()

	if gitCommit != "" {
		log.Info().Msg("Git Commit: " + version.GitCommit())
	}

	if buildTime != "" {
		log.Info().Msg("Build Time: " + version.BuildTime())
	}

	err := initDb(cfg)
	if err != nil {
		log.Error().Msg("Init database fail:" + err.Error())
		return
	}

	if cfg.HiApiUrl != "" {
		log.Info().Msgf("Hi api url: %s", cfg.HiApiUrl)
	}

	if cfg.HiSuperPassword != "" {
		log.Info().Msgf("Hi super password: %s", cfg.HiSuperPassword)
	}

	br := newBroker(cfg)
	go br.run()

	listenDevice(br)
	listenHttpProxy(br)
	apiStart(br)

	select {}
}

func main() {
	defaultLogPath := "/var/log/rttys.log"
	if runtime.GOOS == "windows" {
		defaultLogPath = "rttys.log"
	}

	app := &cli.App{
		Name:    "rttys",
		Usage:   "The server side for rtty",
		Version: version.Version(),
		Commands: []*cli.Command{
			{
				Name:  "run",
				Usage: "Run rttys",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "log",
						Value: defaultLogPath,
						Usage: "log file path",
					},
					&cli.StringFlag{
						Name:    "conf",
						Aliases: []string{"c"},
						Value:   "./rttys.conf",
						Usage:   "config file to load",
					},
					&cli.StringFlag{
						Name:  "addr-dev",
						Value: ":5912",
						Usage: "address to listen device",
					},
					&cli.StringFlag{
						Name:  "addr-user",
						Value: ":5913",
						Usage: "address to listen user",
					},
					&cli.StringFlag{
						Name:  "addr-http-proxy",
						Value: "",
						Usage: "address to listen for HTTP proxy (default auto)",
					},
					&cli.StringFlag{
						Name:  "http-proxy-redir-url",
						Value: "",
						Usage: "url to redirect for HTTP proxy",
					},
					&cli.StringFlag{
						Name:  "ssl-cert",
						Value: "",
						Usage: "ssl cert file Path",
					},
					&cli.StringFlag{
						Name:  "ssl-key",
						Value: "",
						Usage: "ssl key file Path",
					},
					&cli.StringFlag{
						Name:  "ssl-cacert",
						Value: "",
						Usage: "mtls CA storage in PEM file Path",
					},
					&cli.StringFlag{
						Name:    "token",
						Aliases: []string{"t"},
						Value:   "",
						Usage:   "token to use",
					},
					&cli.StringFlag{
						Name:  "white-list",
						Value: "",
						Usage: "white list(device IDs separated by spaces or *)",
					},
					&cli.StringFlag{
						Name:  "db",
						Value: "sqlite://rttys.db",
						Usage: "database source",
					},
					&cli.BoolFlag{
						Name:  "local-auth",
						Usage: "need auth for local",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"V"},
						Usage:   "more detailed output",
					},
					&cli.StringFlag{
						Name:  "hi-api-url",
						Value: os.Getenv("API_URL"),
						Usage: "Api Url",
					},
					&cli.StringFlag{
						Name:  "hi-super-password",
						Value: os.Getenv("ROUTER_SUPER_PASSWORD"),
						Usage: "Super password",
					},
				},
				Action: func(c *cli.Context) error {
					runRttys(c)
					return nil
				},
			},
			{
				Name:  "token",
				Usage: "Generate a token",
				Action: func(c *cli.Context) error {
					utils.GenToken()
					return nil
				},
			},
		},
		Action: func(c *cli.Context) error {
			c.App.Command("run").Run(c)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
