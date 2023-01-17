package hi

import (
	"errors"
	"github.com/go-redis/redis"
	"rttys/config"
)

func RedisCli() (redisCli *redis.Client, err error) {
	if config.RedisHost == "" {
		return nil, errors.New("redis host error")
	}
	addr := config.RedisHost
	if config.RedisPort != "" {
		addr = addr + ":" + config.RedisPort
	}
	redisCli = redis.NewClient(&redis.Options{Addr: addr, Password: config.RedisPassword, DB: 0})
	err = redisCli.Ping().Err()
	return
}
