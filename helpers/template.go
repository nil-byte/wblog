package helpers

import (
	"strings"
	"time"

	"github.com/wangsongyan/wblog/models"
)

// DateFormat 格式化时间
func DateFormat(date time.Time, layout string) string {
	return date.Format(layout)
}

// Substring 截取字符串
func Substring(source string, start, end int) string {
	// 字符串是以字节（byte）序列的形式存储的，每个字符可能由一个或多个字节组成，特别是在处理包含非 ASCII 字符（如中文）的字符串
	//直接对字符串进行切片操作可能导致截断字符，产生乱码或错误
	rs := []rune(source) 
	length := len(rs)
	if start < 0 {
		start = 0
	}
	if end > length {
		end = length
	}
	return string(rs[start:end])
}

// IsOdd 判断数字是否是奇数
func IsOdd(number int) bool {
	return !IsEven(number)
}

// IsEven 判断数字是否是偶数
func IsEven(number int) bool {
	return number%2 == 0
}

func Add(a1, a2 int) int {
	return a1 + a2
}

func Minus(a1, a2 int) int {
	return a1 - a2
}

func ListTag() string {
	tags, err := models.ListTag()
	if err != nil {
		return ""
	}
	tagNames := make([]string, 0)
	for _, tag := range tags {
		tagNames = append(tagNames, tag.Name)
	}
	return strings.Join(tagNames, ",")
}
