package main

import (
	"flag"
	"time"

	"github.com/cihub/seelog"

	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron"  // 定时任务
	// "github.com/claudiu/gocron" // 不再活跃
	"github.com/wangsongyan/wblog/controllers"
	"github.com/wangsongyan/wblog/helpers"
	"github.com/wangsongyan/wblog/models"
	"github.com/wangsongyan/wblog/system"
)

func main() {

	configFilePath := flag.String("C", "conf/conf.toml", "config file path")
	logConfigPath := flag.String("L", "conf/seelog.xml", "log config file path")
	generate := flag.Bool("g", false, "generate sample config file")
	flag.Parse()

	if *generate {
		system.Generate()
		os.Exit(0)
	}

	// 解析seelog.xml配置文件，初始化日志 
	logger, err := seelog.LoggerFromConfigAsFile(*logConfigPath)
	if err != nil {
		seelog.Critical("err parsing seelog config file", err)
		return
	}
	seelog.ReplaceLogger(logger) // 替换日志记录器
	defer seelog.Flush() // 刷新日志

	// 加载配置文件
	if err := system.LoadConfiguration(*configFilePath); err != nil {
		seelog.Critical("err parsing config log file", err)
		return
	}

	// 初始化数据库
	err = models.InitDB()
	if err != nil {
		seelog.Critical("err open databases", err)
		return
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	setTemplate(router) // 设置模板
	setSessions(router) // 设置会话
	router.Use(SharedData()) // 共享数据

	//Periodic tasks 定时任务
	s := gocron.NewScheduler(time.Local) // 创建一个调度器
	s.Every(1).Day().Do(controllers.CreateXMLSitemap)   // 搜索引擎优化
	s.Every(7).Days().Do(controllers.Backup) // 备份数据库
	s.StartAsync() // 启动定时任务

	router.Static("/static", filepath.Join(helpers.GetCurrentDirectory(), system.GetConfiguration().PublicDir))

	router.NoRoute(controllers.Handle404)
	router.GET("/", controllers.IndexGet)
	router.GET("/index", controllers.IndexGet)
	router.GET("/rss", controllers.RssGet)

	if system.GetConfiguration().SignupEnabled {
		router.GET("/signup", controllers.SignupGet)
		router.POST("/signup", controllers.SignupPost)
	}
	// user signin and logout
	router.GET("/signin", controllers.SigninGet)
	router.POST("/signin", controllers.SigninPost)
	router.GET("/logout", controllers.LogoutGet)
	router.GET("/oauth2callback", controllers.Oauth2Callback)
	router.GET("/auth/:authType", controllers.AuthGet)

	// captcha
	router.GET("/captcha", controllers.CaptchaGet)

	visitor := router.Group("/visitor")
	visitor.Use(AuthRequired(false))
	{
		visitor.POST("/new_comment", controllers.CommentPost)
		visitor.POST("/comment/:id/delete", controllers.CommentDelete)
	}

	// subscriber
	router.GET("/subscribe", controllers.SubscribeGet)
	router.POST("/subscribe", controllers.Subscribe)
	router.GET("/active", controllers.ActiveSubscriber)
	router.GET("/unsubscribe", controllers.UnSubscribe)

	router.GET("/page/:id", controllers.PageGet)
	router.GET("/post/:id", controllers.PostGet)
	router.GET("/tag/:tag", controllers.TagGet)
	router.GET("/archives/:year/:month", controllers.ArchiveGet)

	router.GET("/link/:id", controllers.LinkGet)

	authorized := router.Group("/admin")
	authorized.Use(AuthRequired(true))
	{
		// index
		authorized.GET("/index", controllers.AdminIndex)

		// image upload
		authorized.POST("/upload", controllers.Upload)

		// page
		authorized.GET("/page", controllers.PageIndex)
		authorized.GET("/new_page", controllers.PageNew)
		authorized.POST("/new_page", controllers.PageCreate)
		authorized.GET("/page/:id/edit", controllers.PageEdit)
		authorized.POST("/page/:id/edit", controllers.PageUpdate)
		authorized.POST("/page/:id/publish", controllers.PagePublish)
		authorized.POST("/page/:id/delete", controllers.PageDelete)

		// post
		authorized.GET("/post", controllers.PostIndex)
		authorized.GET("/new_post", controllers.PostNew)
		authorized.POST("/new_post", controllers.PostCreate)
		authorized.GET("/post/:id/edit", controllers.PostEdit)
		authorized.POST("/post/:id/edit", controllers.PostUpdate)
		authorized.POST("/post/:id/publish", controllers.PostPublish)
		authorized.POST("/post/:id/delete", controllers.PostDelete)

		// tag
		authorized.POST("/new_tag", controllers.TagCreate)

		//
		authorized.GET("/user", controllers.UserIndex)
		authorized.POST("/user/:id/lock", controllers.UserLock)

		// profile
		authorized.GET("/profile", controllers.ProfileGet)
		authorized.POST("/profile", controllers.ProfileUpdate)
		authorized.POST("/profile/email/bind", controllers.BindEmail)
		authorized.POST("/profile/email/unbind", controllers.UnbindEmail)
		authorized.POST("/profile/github/unbind", controllers.UnbindGithub)

		// subscriber
		authorized.GET("/subscriber", controllers.SubscriberIndex)
		authorized.POST("/subscriber", controllers.SubscriberPost)

		// link
		authorized.GET("/link", controllers.LinkIndex)
		authorized.POST("/new_link", controllers.LinkCreate)
		authorized.POST("/link/:id/edit", controllers.LinkUpdate)
		authorized.POST("/link/:id/delete", controllers.LinkDelete)

		// comment
		authorized.POST("/comment/:id", controllers.CommentRead)
		authorized.POST("/read_all", controllers.CommentReadAll)

		// backup
		authorized.POST("/backup", controllers.BackupPost)
		authorized.POST("/restore", controllers.RestorePost)

		// mail
		authorized.POST("/new_mail", controllers.SendMail)
		authorized.POST("/new_batchmail", controllers.SendBatchMail)
	}

	err = router.Run(system.GetConfiguration().Addr)
	if err != nil {
		seelog.Critical(err)
	}
}

func setTemplate(engine *gin.Engine) {

	funcMap := template.FuncMap{
		"dateFormat": helpers.DateFormat,
		"substring":  helpers.Substring,
		"isOdd":      helpers.IsOdd,
		"isEven":     helpers.IsEven,
		"truncate":   helpers.Truncate,
		"length":     helpers.Len,
		"add":        helpers.Add,
		"minus":      helpers.Minus,
		"listtag":    helpers.ListTag,
	}   

	engine.SetFuncMap(funcMap)
	engine.LoadHTMLGlob(filepath.Join(helpers.GetCurrentDirectory(), system.GetConfiguration().ViewDir))
}

// setSessions initializes sessions & csrf middlewares
func setSessions(router *gin.Engine) {
	config := system.GetConfiguration()
	//https://github.com/gin-gonic/contrib/tree/master/sessions
	store := cookie.NewStore([]byte(config.SessionSecret))
	store.Options(sessions.Options{HttpOnly: true, MaxAge: 7 * 86400, Path: "/"}) //Also set Secure: true if using SSL, you should though
	router.Use(sessions.Sessions("gin-session", store))
	//https://github.com/utrack/gin-csrf
	/*router.Use(csrf.Middleware(csrf.Options{
		Secret: config.SessionSecret,
		ErrorFunc: func(c *gin.Context) {
			c.String(400, "CSRF token mismatch")
			c.Abort()
		},
	}))*/
}

//+++++++++++++ middlewares +++++++++++++++++++++++

// SharedData fills in common data, such as user info, etc...
// 确认用户是否登录，如果登录，则将用户信息设置到上下文中
func SharedData() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		if uID := session.Get(controllers.SessionKey); uID != nil {
			user, err := models.GetUser(uID)
			if err == nil {
				c.Set(controllers.ContextUserKey, user)
			}
		}
		if system.GetConfiguration().SignupEnabled {
			c.Set("SignupEnabled", true)
		}
		c.Next()
	}
}

// AuthRequired grants access to authenticated users
func AuthRequired(adminScope bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if user, _ := c.Get(controllers.ContextUserKey); user != nil {
			if u, ok := user.(*models.User); ok && (!adminScope || u.IsAdmin) {
				c.Next()
				return
			}
		}
		seelog.Warnf("User not authorized to visit %s", c.Request.RequestURI)
		c.HTML(http.StatusForbidden, "errors/error.html", gin.H{
			"message": "Forbidden!",
		})
		c.Abort()
	}
}
