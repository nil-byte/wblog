package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	oauth "github.com/alimoeeny/gooauth2"
	"github.com/cihub/seelog"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/wangsongyan/wblog/helpers"
	"github.com/wangsongyan/wblog/models"
	"github.com/wangsongyan/wblog/system"
	"golang.org/x/crypto/bcrypt"
)

type GithubUserInfo struct {
	AvatarURL         string      `json:"avatar_url"`
	Bio               interface{} `json:"bio"`
	Blog              string      `json:"blog"`
	Company           interface{} `json:"company"`
	CreatedAt         string      `json:"created_at"`
	Email             interface{} `json:"email"`
	EventsURL         string      `json:"events_url"`
	Followers         int         `json:"followers"`
	FollowersURL      string      `json:"followers_url"`
	Following         int         `json:"following"`
	FollowingURL      string      `json:"following_url"`
	GistsURL          string      `json:"gists_url"`
	GravatarID        string      `json:"gravatar_id"`
	Hireable          interface{} `json:"hireable"`
	HTMLURL           string      `json:"html_url"`
	ID                int         `json:"id"`
	Location          interface{} `json:"location"`
	Login             string      `json:"login"`
	Name              interface{} `json:"name"`
	OrganizationsURL  string      `json:"organizations_url"`
	PublicGists       int         `json:"public_gists"`
	PublicRepos       int         `json:"public_repos"`
	ReceivedEventsURL string      `json:"received_events_url"`
	ReposURL          string      `json:"repos_url"`
	SiteAdmin         bool        `json:"site_admin"`
	StarredURL        string      `json:"starred_url"`
	SubscriptionsURL  string      `json:"subscriptions_url"`
	Type              string      `json:"type"`
	UpdatedAt         string      `json:"updated_at"`
	URL               string      `json:"url"`
}

func SigninGet(c *gin.Context) {
	c.HTML(http.StatusOK, "auth/signin.html", gin.H{
		"cfg": system.GetConfiguration(),
	})
}

// SignupGet 注册页面
func SignupGet(c *gin.Context) {
	c.HTML(http.StatusOK, "auth/signup.html", gin.H{
		"cfg": system.GetConfiguration(),
	})
}

// LogoutGet 注销
func LogoutGet(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	s.Save()
	c.Redirect(http.StatusSeeOther, "/signin")
}

// SignupPost 注册
func SignupPost(c *gin.Context) {
	email := c.DefaultPostForm("email", "")
	telephone := c.DefaultPostForm("telephone", "")
	password := c.DefaultPostForm("password", "")
	// 校验邮箱格式
	emailPattern := `^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`
	matched, _ := regexp.MatchString(emailPattern, email)
	if !matched || len(password) < 8 {
		c.HTML(http.StatusOK, "auth/signup.html", gin.H{
			"message": "Invalid email format or password too short",
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusOK, "auth/signup.html", gin.H{
			"message": "Error while hashing password",
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	user := &models.User{
		Email:     email,
		Telephone: telephone,
		Password:  string(hashedPassword),
		IsAdmin:   true,
		LockState: false,
	}

	if err := user.Insert(); err != nil {
		c.HTML(http.StatusOK, "auth/signup.html", gin.H{
			"message": "Email already exists",
			"cfg":     system.GetConfiguration(),
		})
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/signin")
}

// SigninPost 登录
func SigninPost(c *gin.Context) {
	var (
		err  error
		user *models.User
	)
	username := c.PostForm("username")
	password := c.PostForm("password")
	if username == "" || password == "" {
		c.HTML(http.StatusOK, "auth/signin.html", gin.H{
			"message": "username or password cannot be null",
			"cfg":     system.GetConfiguration(),
		})
		return
	}
	user, err = models.GetUserByUsername(username)
	if err != nil {
		c.HTML(http.StatusOK, "auth/signin.html", gin.H{
			"message": "invalid username or password",
			"cfg":     system.GetConfiguration(),
		})
		return
	}

	// 首先尝试 bcrypt 验证
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		// bcrypt 验证失败，尝试 md5 验证
		if user.Password == helpers.Md5(password) {
			// md5 验证成功，更新为 bcrypt 密码
			hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			user.Password = string(hashedPassword)
			user.UpdatePassword()
			err = nil // 清除 bcrypt 验证失败的错误
		}
	}
	if err == nil {
		if user.LockState {
			c.HTML(http.StatusOK, "auth/signin.html", gin.H{
				"message": "Your account have been locked!",
				"cfg":     system.GetConfiguration(),
			})
			return
		}
		s := sessions.Default(c)
		s.Clear()
		s.Set(SessionKey, user.ID)
		s.Save()
		if user.IsAdmin {
			c.Redirect(http.StatusMovedPermanently, "/admin/index")
		} else {
			c.Redirect(http.StatusMovedPermanently, "/")
		}
		return
	} else {
		c.HTML(http.StatusOK, "auth/signin.html", gin.H{
			"message": "Invalid username or password.",
			"cfg":     system.GetConfiguration(),
		})
		return
	}
}

// Oauth2Callback 回调
func Oauth2Callback(c *gin.Context) {
	var (
		userInfo *GithubUserInfo
		user     *models.User
	)
	code := c.Query("code")
	state := c.Query("state")

	// validate state
	session := sessions.Default(c)
	if len(state) == 0 || state != session.Get(SessionGithubState) {
		c.Abort()
		return
	}
	// remove state from session
	session.Delete(SessionGithubState)
	session.Save()

	// exchange accesstoken by code
	token, err := exchangeTokenByCode(code)
	if err != nil {
		seelog.Errorf("exchangeTokenByCode err: %v", err)
		c.Redirect(http.StatusMovedPermanently, "/signin")
		return
	}

	//get github userinfo by accesstoken
	userInfo, err = getGithubUserInfoByAccessToken(token)
	if err != nil {
		seelog.Errorf("getGithubUserInfoByAccessToken err: %v", err)
		c.Redirect(http.StatusMovedPermanently, "/signin")
		return
	}

	sessionUser, exists := c.Get(ContextUserKey)
	if exists { // 已登录
		user = sessionUser.(*models.User)
		if _, e := models.IsGithubIdExists(userInfo.Login, user.ID); e != nil { // 未绑定
			if user.IsAdmin {
				user.GithubLoginId = userInfo.Login
			}
			user.AvatarUrl = userInfo.AvatarURL
			user.GithubUrl = userInfo.HTMLURL
			err = user.UpdateGithubUserInfo()
		} else {
			err = errors.New("this github loginId has bound another account.")
		}
	} else {
		user = &models.User{
			GithubLoginId: userInfo.Login,
			AvatarUrl:     userInfo.AvatarURL,
			GithubUrl:     userInfo.HTMLURL,
		}
		user, err = user.FirstOrCreate()
		if err == nil {
			if user.LockState {
				err = errors.New("Your account have been locked.")
				HandleMessage(c, err.Error())
				return
			}
		}
	}

	if err == nil {
		s := sessions.Default(c)
		s.Clear()
		s.Set(SessionKey, user.ID)
		s.Save()
		if user.IsAdmin {
			c.Redirect(http.StatusMovedPermanently, "/admin/index")
		} else {
			c.Redirect(http.StatusMovedPermanently, "/")
		}
		return
	}
}

func exchangeTokenByCode(code string) (accessToken string, err error) {
	var (
		transport *oauth.Transport
		token     *oauth.Token
		cfg       = system.GetConfiguration()
	)
	transport = &oauth.Transport{Config: &oauth.Config{
		ClientId:     cfg.Github.ClientId,
		ClientSecret: cfg.Github.ClientSecret,
		RedirectURL:  cfg.Github.RedirectURL,
		TokenURL:     cfg.Github.TokenUrl,
		Scope:        cfg.Github.Scope,
	}}
	token, err = transport.Exchange(code)
	if err != nil {
		return
	}
	accessToken = token.AccessToken
	// cache token
	tokenCache := oauth.CacheFile("./request.token")
	if err := tokenCache.PutToken(token); err != nil {
		seelog.Errorf("tokenCache.PutToken err: %v", err)
	}
	return
}

func getGithubUserInfoByAccessToken(token string) (*GithubUserInfo, error) {
	var (
		resp *http.Response
		req  *http.Request
		body []byte
		err  error
	)
	req, err = http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var userInfo GithubUserInfo
	err = json.Unmarshal(body, &userInfo)
	return &userInfo, err
}

func ProfileGet(c *gin.Context) {
	c.HTML(http.StatusOK, "admin/profile.html", gin.H{
		"user":     c.MustGet(ContextUserKey),
		"comments": models.MustListUnreadComment(),
		"cfg":      system.GetConfiguration(),
	})
}

func ProfileUpdate(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	avatarUrl := c.PostForm("avatarUrl")
	nickName := c.PostForm("nickName")
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	err = user.UpdateProfile(avatarUrl, nickName)
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
	res["user"] = models.User{AvatarUrl: avatarUrl, NickName: nickName}
}

func BindEmail(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	email := c.PostForm("email")
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	if len(user.Email) > 0 {
		res["message"] = "email have bound"
		return
	}
	_, err = models.GetUserByUsername(email)
	if err == nil {
		res["message"] = "email have be registered"
		return
	}
	err = user.UpdateEmail(email)
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}

func UnbindEmail(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	if user.Email == "" {
		res["message"] = "email haven't bound"
		return
	}
	err = user.UpdateEmail("")
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}

func UnbindGithub(c *gin.Context) {
	var (
		err error
		res = gin.H{}
	)
	defer writeJSON(c, res)
	sessionUser, _ := c.Get(ContextUserKey)
	user := sessionUser.(*models.User)
	if user.GithubLoginId == "" {
		res["message"] = "github haven't bound"
		return
	}
	user.GithubLoginId = ""
	err = user.UpdateGithubUserInfo()
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}

func UserIndex(c *gin.Context) {
	users, _ := models.ListUsers()
	c.HTML(http.StatusOK, "admin/user.html", gin.H{
		"users":    users,
		"user":     c.MustGet(ContextUserKey),
		"comments": models.MustListUnreadComment(),
		"cfg":      system.GetConfiguration(),
	})
}

func UserLock(c *gin.Context) {
	var (
		err  error
		id   uint
		res  = gin.H{}
		user *models.User
	)
	defer writeJSON(c, res)
	id, err = ParamUint(c, "id")
	if err != nil {
		res["message"] = err.Error()
		return
	}
	user, err = models.GetUser(id)
	if err != nil {
		res["message"] = err.Error()
		return
	}
	user.LockState = !user.LockState
	err = user.Lock()
	if err != nil {
		res["message"] = err.Error()
		return
	}
	res["succeed"] = true
}
