package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"github.com/cihub/seelog"
	"io"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/snluu/uuid"
)

// Md5 计算字符串的md5值
func Md5(source string) string {
	md5h := md5.New()
	md5h.Write([]byte(source))
	return hex.EncodeToString(md5h.Sum(nil))
}

func Truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func Len(s string) int {
	return len([]rune(s))
}

func UUID() string {
	return uuid.Rand().Hex()
}

func GetCurrentTime() time.Time {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	return time.Now().In(loc)
}

func GetCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0])) // 获取当前绝对目录
	if err != nil {
		seelog.Critical(err)
	}
	return strings.Replace(dir, "\\", "/", -1) // 将反斜杠替换为斜杠
}

func SendToMail(user, password, host, to, subject, body, mailType string) error {
	hp := strings.Split(host, ":")
	auth := smtp.PlainAuth("", user, password, hp[0])
	var contentType string
	if mailType == "html" {
		contentType = "Content-Type: text/" + mailType + "; charset=UTF-8"
	} else {
		contentType = "Content-Type: text/plain" + "; charset=UTF-8"
	}
	msg := []byte("To: " + to + "\r\nFrom: " + user + "\r\nSubject: " + subject + "\r\n" + contentType + "\r\n\r\n" + body)
	sendTo := strings.Split(to, ";")
	return smtp.SendMail(host, auth, user, sendTo, msg)
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
    // 创建AES密码块
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    // 创建GCM实例
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // 检查密文长度是否小于Nonce长度
    if len(ciphertext) < gcm.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }

    // 分离Nonce和实际的密文
    nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

    // 使用GCM进行解密
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

func Encrypt(plaintext, key []byte) ([]byte, error) {
    // 创建AES密码块
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    // 创建GCM实例
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // 创建随机的Nonce，GCM标准推荐长度为12字节
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    // 使用GCM进行加密并附加认证标签
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}
