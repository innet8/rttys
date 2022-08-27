package hi

import (
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
