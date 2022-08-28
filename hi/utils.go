package hi

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Cmd 执行命令
func Cmd(arg ...string) (string, error) {
	output, err := exec.Command("/bin/sh", arg...).CombinedOutput()
	return string(output), err
}

// IsIp 判断是否ip
func IsIp(ip string) bool {
	address := net.ParseIP(ip)
	if address == nil {
		return false
	} else {
		return true
	}
}

// IsCidr 判断是否ip或掩码ip
func IsCidr(cidr string) bool {
	ip := cidr
	if strings.Contains(cidr, "/") {
		cidrArr := strings.Split(cidr, `/`)
		ip = cidrArr[0]
		r, _ := strconv.Atoi(cidrArr[1])
		if r < 0 || r > 32 {
			return false
		}
	}
	return IsIp(ip)
}

// IsDomain 判断是否域名
func IsDomain(domain string) bool {
	IsLine := "^(?:[A-za-z0-9-]+\\.)+[A-za-z]{2,4}(?:[\\/\\?#][\\/=\\?%\\-&~`@[\\]\\':+!\\.#\\w]*)?$"
	match, _ := regexp.MatchString(IsLine, domain)
	return match
}

// RegexpReplace 正则替换
func RegexpReplace(rege, src, repl string) string {
	sampleRegexp := regexp.MustCompile(rege)
	result := sampleRegexp.ReplaceAllString(src, repl)
	return result
}

// Base64Encode Base64加密
func Base64Encode(data string) string {
	sEnc := base64.StdEncoding.EncodeToString([]byte(data))
	return fmt.Sprintf(sEnc)
}

// Base64Decode Base64解密
func Base64Decode(data string) string {
	uDec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(uDec)
}

// RandString 生成随机字符串
func RandString(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	var result []byte
	rand.Seed(time.Now().UnixNano() + int64(rand.Intn(100)))
	for i := 0; i < length; i++ {
		result = append(result, bytes[rand.Intn(len(bytes))])
	}
	return string(result)
}

// StringMd5 MD5
func StringMd5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// InArray 元素是否存在数组中
func InArray(item string, items []string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
