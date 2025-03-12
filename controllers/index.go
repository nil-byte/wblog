package controllers

import (
	"github.com/cihub/seelog"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"
	"github.com/russross/blackfriday"
	"github.com/wangsongyan/wblog/models"
	"github.com/wangsongyan/wblog/system"
)

func IndexGet(c *gin.Context) {
	var (
		pageIndex int // 页码
		pageSize  = system.GetConfiguration().PageSize // 每页显示数量
		total     int // 总数
		page      string // 页码
		err       error // 错误
		posts     []*models.Post // 文章
		policy    *bluemonday.Policy // 安全策略
	)
	page = c.Query("page") // 从查询参数中获取页码
	pageIndex, _ = strconv.Atoi(page)
	if pageIndex <= 0 {
		pageIndex = 1
	}
	posts, err = models.ListPublishedPost("", pageIndex, pageSize) // 获取文章列表
	if err != nil {
		seelog.Errorf("models.ListPublishedPost err: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	total, err = models.CountPostByTag("") // 获取文章总数（按标签/全部）
	if err != nil {
		seelog.Errorf("models.CountPostByTag err: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	policy = bluemonday.StrictPolicy() // 创建严格的HTML过滤策略
	for _, post := range posts {
		post.Tags, _ = models.ListTagByPostId(post.ID) // 获取文章标签（按文章id）
		// 将Markdown格式转换为HTML,并过滤不安全的HTML标签
		post.Body = policy.Sanitize(string(blackfriday.MarkdownCommon([]byte(post.Body))))
	}  
	user, _ := c.Get(ContextUserKey) // 获取当前登录用户
	c.HTML(http.StatusOK, "index/index.html", gin.H{
		"posts":           posts, // 文章列表
		"tags":            models.MustListTag(), // 标签列表
		"archives":        models.MustListPostArchives(), // 文章归档
		"links":           models.MustListLinks(), // 友情链接
		"user":            user, // 当前登录用户
		"pageIndex":       pageIndex, // 当前页码
		"totalPage":       int(math.Ceil(float64(total) / float64(pageSize))), // 总页数
		"path":            c.Request.URL.Path, // 当前路径
		"maxReadPosts":    models.MustListMaxReadPost(), // 阅读最多的文章
		"maxCommentPosts": models.MustListMaxCommentPost(), // 评论最多的文章
		"cfg":             system.GetConfiguration(), // 配置
	})
}

func AdminIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/index.html", gin.H{
		"pageCount":    models.CountPage(),
		"postCount":    models.CountPost(),
		"tagCount":     models.CountTag(),
		"commentCount": models.CountComment(),
		"user":         c.MustGet(ContextUserKey),
		"comments":     models.MustListUnreadComment(),
		"cfg":          system.GetConfiguration(),
	})
}
