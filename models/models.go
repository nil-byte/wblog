package models

import (
	"database/sql"
	"fmt"
	"html/template"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/microcosm-cc/bluemonday"
	"github.com/russross/blackfriday"
	"github.com/wangsongyan/wblog/system"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// I don't need soft delete,so I use customized BaseModel instead gorm.Model
type BaseModel struct {
	ID        uint `gorm:"primary_key"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// table pages 页面信息
type Page struct {
	BaseModel
	Title       string `gorm:"type:text"`     // title 标题
	Body        string `gorm:"type:longtext"` // body 内容
	View        int    // view count 浏览次数
	IsPublished bool   // published or not 是否发布
}

// table posts 文章信息
type Post struct {
	BaseModel
	Title        string     `gorm:"type:text"`     // title 标题
	Body         string     `gorm:"type:longtext"` // body 内容
	View         int        // view count 浏览次数
	IsPublished  bool       // published or not 是否发布
	Tags         []*Tag     `gorm:"-"`  // tags of post 文章标签
	Comments     []*Comment `gorm:"-"`  // comments of post 文章评论
	CommentTotal int        `gorm:"->"` // count of comment 评论总数
}

// table tags 标签信息
type Tag struct {
	BaseModel
	Name  string // tag name 标签名称
	Total int    `gorm:"->"` // count of post 使用该标签的文章总数
}

// table post_tags 文章标签关系
type PostTag struct {
	BaseModel
	PostId uint `gorm:"uniqueIndex:uk_post_tag"` // post id 文章id
	TagId  uint `gorm:"uniqueIndex:uk_post_tag"` // tag id 标签id
}

// table users 用户信息
type User struct {
	gorm.Model
	Email         string    `gorm:"uniqueIndex;default:null"` //邮箱
	Telephone     string    `gorm:"uniqueIndex;default:null"` //手机号码
	Password      string    `gorm:"default:null"`             //密码
	VerifyState   string    `gorm:"default:'0'"`              //邮箱验证状态
	SecretKey     string    `gorm:"default:null"`             //密钥
	OutTime       time.Time //过期时间
	GithubLoginId string    `gorm:"uniqueIndex;default:null"` // github唯一标识
	GithubUrl     string    //github地址
	IsAdmin       bool      //是否是管理员
	AvatarUrl     string    // 头像链接
	NickName      string    // 昵称
	LockState     bool      `gorm:"default:false"` //锁定状态
}

// table comments 评论信息
type Comment struct {
	BaseModel
	UserID    uint   // 用户id
	Content   string `gorm:"type:text"` // 内容
	PostID    uint   // 文章id
	ReadState bool   `gorm:"default:false"` // 阅读状态
	//Replies []*Comment // 评论
	NickName  string `gorm:"-"` // 昵称
	AvatarUrl string `gorm:"-"` // 头像链接
	GithubUrl string `gorm:"-"` // github地址
}

// table subscribe 订阅信息
type Subscriber struct {
	gorm.Model
	Email          string    `gorm:"type:varchar(255);uniqueIndex"` //邮箱
	VerifyState    bool      `gorm:"default:false"`                 //验证状态
	SubscribeState bool      `gorm:"default:true"`                  //订阅状态
	OutTime        time.Time //过期时间
	SecretKey      string    // 秘钥
	Signature      string    //签名
}

// table link 友情链接
type Link struct {
	gorm.Model
	Name string //名称
	Url  string //地址
	Sort int    `gorm:"default:0"` //排序
	View int    //访问次数
}

// query result 归档查询结果
type QrArchive struct {
	ArchiveDate time.Time //time 时间
	Total       int       //total 总数
	Year        int       // year 年份
	Month       int       // month 月份
}

// SmmsFile 文件存储表
type SmmsFile struct {
	BaseModel
	FileName  string `json:"filename"`  //文件名
	StoreName string `json:"storename"` //存储名
	Size      int    `json:"size"`      //文件大小 （字节）
	Width     int    `json:"width"`     //图片宽度
	Height    int    `json:"height"`    //图片高度
	Hash      string `json:"hash"`      //文件哈希值
	Delete    string `json:"delete"`    //删除链接
	Url       string `json:"url"`       //访问链接
	Path      string `json:"path"`      //本地存储路径
}

var DB *gorm.DB //数据库实例
func InitDB() (err error) {
	cfg := system.GetConfiguration()

	switch cfg.Database.Dialect {
	case "sqlite":
		DB, err = gorm.Open(sqlite.Open(cfg.Database.DSN), &gorm.Config{})
	case "mysql":
		DB, err = gorm.Open(mysql.Open(cfg.Database.DSN), &gorm.Config{})
	default:
		return fmt.Errorf("unsupported database dialect: %s", cfg.Database.Dialect)
	}
	if err != nil {
		return err
	}
	//db.LogMode(true)
	sqlDb, err := DB.DB() // (无需手动关闭，已经使用连接池来管理数据库连接，会自动关闭)
	if err != nil {
		return err
	}
	sqlDb.SetMaxIdleConns(10)                                                                                      // 设置最大空闲连接数
	sqlDb.SetMaxOpenConns(100)                                                                                     // 设置最大打开连接数
	sqlDb.SetConnMaxLifetime(time.Hour)                                                                            // 设置连接最大生命周期
	DB.AutoMigrate(&Page{}, &Post{}, &Tag{}, &PostTag{}, &User{}, &Comment{}, &Subscriber{}, &Link{}, &SmmsFile{}) //自动迁移表结构
	return nil
}

// Page
func (page *Page) Insert() error {
	return DB.Create(page).Error
}

func (page *Page) Update() error {
	return DB.Model(page).Updates(map[string]interface{}{
		"title":        page.Title,
		"body":         page.Body,
		"is_published": page.IsPublished,
	}).Error
}

func (page *Page) UpdateView() error {
	return DB.Model(page).Updates(map[string]interface{}{
		"view": page.View,
	}).Error
}

func (page *Page) Delete() error {
	return DB.Delete(page).Error
}

func GetPageById(id uint) (*Page, error) {
	var page Page
	err := DB.First(&page, "id = ?", id).Error
	return &page, err
}

func ListPublishedPage() ([]*Page, error) {
	return _listPage(true)
}

func ListAllPage() ([]*Page, error) {
	return _listPage(false)
}

func _listPage(published bool) ([]*Page, error) {
	var pages []*Page
	var err error
	if published {
		err = DB.Where("is_published = ?", true).Find(&pages).Error
	} else {
		err = DB.Find(&pages).Error
	}
	return pages, err
}

func CountPage() int64 {
	var count int64
	DB.Model(&Page{}).Count(&count)
	return count
}

// Post
func (post *Post) Insert() error {
	return DB.Create(post).Error
}

func (post *Post) Update() error {
	return DB.Model(post).Updates(map[string]interface{}{
		"title":        post.Title,
		"body":         post.Body,
		"is_published": post.IsPublished,
	}).Error
}

func (post *Post) UpdateView() error {
	return DB.Model(post).Updates(map[string]interface{}{
		"view": post.View,
	}).Error
}

func (post *Post) Delete() error {
	return DB.Delete(post).Error
}

// Excerpt 获取文章摘要
func (post *Post) Excerpt() template.HTML {
	//you can sanitize, cut it down, add images, etc
	policy := bluemonday.StrictPolicy() //remove all html tags
	sanitized := policy.Sanitize(string(blackfriday.MarkdownCommon([]byte(post.Body))))
	runes := []rune(sanitized)
	if len(runes) > 300 {
		sanitized = string(runes[:300])
	}
	excerpt := template.HTML(sanitized + "...")
	return excerpt
}

func ListPublishedPost(tag string, pageIndex, pageSize int) ([]*Post, error) {
	return _listPost(tag, true, pageIndex, pageSize)
}

func ListAllPost(tag string) ([]*Post, error) {
	return _listPost(tag, false, 0, 0)
}

// 获取文章列表（按标签/全部）
func _listPost(tagId string, published bool, pageIndex, pageSize int) ([]*Post, error) {
	var posts []*Post
	var err error
	if len(tagId) > 0 {
		var rows *sql.Rows
		if published {
			if pageIndex > 0 {
				rows, err = DB.Raw("select p.* from posts p inner join post_tags pt on p.id = pt.post_id where pt.tag_id = ? and p.is_published = ? order by created_at desc limit ? offset ?", tagId, true, pageSize, (pageIndex-1)*pageSize).Rows()
			} else {
				rows, err = DB.Raw("select p.* from posts p inner join post_tags pt on p.id = pt.post_id where pt.tag_id = ? and p.is_published = ? order by created_at desc", tagId, true).Rows()
			}
		} else {
			rows, err = DB.Raw("select p.* from posts p inner join post_tags pt on p.id = pt.post_id where pt.tag_id = ? order by created_at desc", tagId).Rows()
		}
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var post Post
			DB.ScanRows(rows, &post)
			posts = append(posts, &post)
		}
	} else {
		if published {
			if pageIndex > 0 {
				err = DB.Where("is_published = ?", true).Order("created_at desc").Limit(pageSize).Offset((pageIndex - 1) * pageSize).Find(&posts).Error
			} else {
				err = DB.Where("is_published = ?", true).Order("created_at desc").Find(&posts).Error
			}
		} else {
			err = DB.Order("created_at desc").Find(&posts).Error
		}
	}
	return posts, err
}

// 获取阅读最多的文章
func MustListMaxReadPost() (posts []*Post) {
	posts, _ = ListMaxReadPost()
	return
}

func ListMaxReadPost() (posts []*Post, err error) {
	err = DB.Where("is_published = ?", true).Order("view desc").Limit(5).Find(&posts).Error
	return
}

// 获取评论最多的文章
func MustListMaxCommentPost() (posts []*Post) {
	posts, _ = ListMaxCommentPost()
	return
}

func ListMaxCommentPost() (posts []*Post, err error) {
	var (
		rows *sql.Rows
	)
	rows, err = DB.Raw("select p.*,c.total comment_total from posts p inner join (select post_id,count(*) total from comments group by post_id) c on p.id = c.post_id order by c.total desc limit 5").Rows()
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var post Post
		DB.ScanRows(rows, &post)
		posts = append(posts, &post)
	}
	return
}

// 文章数量（按标签/全部）
func CountPostByTag(tagId string) (count int, err error) {
	if len(tagId) > 0 {
		err = DB.Raw("select count(*) from posts p inner join post_tags pt on p.id = pt.post_id where pt.tag_id = ? and p.is_published = ?", tagId, true).Row().Scan(&count)
	} else {
		err = DB.Raw("select count(*) from posts p where p.is_published = ?", true).Row().Scan(&count)
	}
	return
}

func CountPost() int64 {
	var count int64
	DB.Model(&Post{}).Count(&count)
	return count
}

func GetPostById(id uint) (*Post, error) {
	var post Post
	err := DB.First(&post, "id = ?", id).Error
	return &post, err
}

func MustListPostArchives() []*QrArchive {
	archives, _ := ListPostArchives()
	return archives
}

// 获取文章归档
func ListPostArchives() ([]*QrArchive, error) {
	var (
		archives []*QrArchive
		querySql string
	)
	switch DB.Dialector.Name() {
	case "mysql":
		querySql = `select date_format(created_at,'%Y-%m') as month,count(*) as total from posts where is_published = ? group by month order by month desc`
	case "sqlite":
		querySql = `select strftime('%Y-%m',created_at) as month,count(*) as total from posts where is_published = ? group by month order by month desc`
	}
	rows, err := DB.Raw(querySql, true).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var archive QrArchive
		var month string
		rows.Scan(&month, &archive.Total)
		//DB.ScanRows(rows, &archive)
		archive.ArchiveDate, _ = time.Parse("2006-01", month)
		archive.Year = archive.ArchiveDate.Year()
		archive.Month = int(archive.ArchiveDate.Month())
		archives = append(archives, &archive)
	}
	return archives, nil
}

func ListPostByArchive(year, month string, pageIndex, pageSize int) ([]*Post, error) {
	var (
		rows     *sql.Rows
		err      error
		querySql string
	)
	if len(month) == 1 {
		month = "0" + month
	}
	condition := fmt.Sprintf("%s-%s", year, month)
	if pageIndex > 0 {
		switch DB.Dialector.Name() {
		case "mysql":
			querySql = `select * from posts where date_format(created_at,'%Y-%m') = ? and is_published = ? order by created_at desc limit ? offset ?`
		case "sqlite":
			querySql = `select * from posts where strftime('%Y-%m',created_at) = ? and is_published = ? order by created_at desc limit ? offset ?`
		}
		rows, err = DB.Raw(querySql, condition, true, pageSize, (pageIndex-1)*pageSize).Rows()
	} else {
		switch DB.Dialector.Name() {
		case "mysql":
			querySql = `select * from posts where date_format(created_at,'%Y-%m') = ? and is_published = ? order by created_at desc`
		case "sqlite":
			querySql = `select * from posts where strftime('%Y-%m',created_at) = ? and is_published = ? order by created_at desc`
		}
		rows, err = DB.Raw(querySql, condition, true).Rows()
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	posts := make([]*Post, 0)
	for rows.Next() {
		var post Post
		DB.ScanRows(rows, &post)
		posts = append(posts, &post)
	}
	return posts, nil
}

func CountPostByArchive(year, month string) (count int, err error) {
	var querySql string
	if len(month) == 1 {
		month = "0" + month
	}
	condition := fmt.Sprintf("%s-%s", year, month)
	switch DB.Dialector.Name() {
	case "mysql":
		querySql = `select count(*) from posts where date_format(created_at,'%Y-%m') = ? and is_published = ?`
	case "sqlite":
		querySql = `select count(*) from posts where strftime('%Y-%m',created_at) = ? and is_published = ?`
	}
	err = DB.Raw(querySql, condition, true).Row().Scan(&count)
	return
}

// Tag
func (tag *Tag) Insert() error {
	return DB.FirstOrCreate(tag, "name = ?", tag.Name).Error
}

// 获取标签列表
func ListTag() ([]*Tag, error) {
	var tags []*Tag
	rows, err := DB.Raw(`
    SELECT t.*, COUNT(*) AS total
    FROM tags t
    INNER JOIN post_tags pt ON t.id = pt.tag_id
    INNER JOIN posts p ON pt.post_id = p.id
    WHERE p.is_published = ?
    GROUP BY pt.tag_id
`, true).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var tag Tag
		DB.ScanRows(rows, &tag)
		tags = append(tags, &tag)
	}
	return tags, nil
}

func MustListTag() []*Tag {
	tags, _ := ListTag()
	return tags
}

// 获取文章标签（按文章id）
func ListTagByPostId(id uint) ([]*Tag, error) {
	var tags []*Tag
	rows, err := DB.Raw("select t.* from tags t inner join post_tags pt on t.id = pt.tag_id where pt.post_id = ?", id).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var tag Tag
		DB.ScanRows(rows, &tag)
		tags = append(tags, &tag)
	}
	return tags, nil
}

func CountTag() int64 {
	var count int64
	DB.Model(&Tag{}).Count(&count)
	return count
}

/*func ListAllTag() ([]*Tag, error) {
	var tags []*Tag
	err := DB.Model(&Tag{}).Find(&tags).Error
	return tags, err
}*/

// post_tags
func (pt *PostTag) Insert() error {
	return DB.FirstOrCreate(pt, "post_id = ? and tag_id = ?", pt.PostId, pt.TagId).Error
}

func DeletePostTagByPostId(postId uint) error {
	return DB.Delete(&PostTag{}, "post_id = ?", postId).Error
}

// user
// insert user
func (user *User) Insert() error {
	return DB.Create(user).Error
}

// update user
func (user *User) Update() error {
	return DB.Save(user).Error
}

func GetUserByUsername(username string) (*User, error) {
	var user User
	err := DB.First(&user, "email = ?", username).Error
	return &user, err
}

func (user *User) FirstOrCreate() (*User, error) {
	err := DB.FirstOrCreate(user, "github_login_id = ?", user.GithubLoginId).Error
	return user, err
}

func IsGithubIdExists(githubId string, id uint) (*User, error) {
	var user User
	err := DB.First(&user, "github_login_id = ? and id != ?", githubId, id).Error
	return &user, err
}

func GetUser(id interface{}) (*User, error) {
	var user User
	err := DB.First(&user, id).Error
	return &user, err
}

func (user *User) UpdateProfile(avatarUrl, nickName string) error {
	return DB.Model(user).Updates(User{AvatarUrl: avatarUrl, NickName: nickName}).Error
}

func (user *User) UpdateEmail(email string) error {
	if len(email) > 0 {
		return DB.Model(user).Update("email", email).Error
	} else {
		return DB.Model(user).Update("email", gorm.Expr("NULL")).Error
	}
}

func (user *User) UpdateGithubUserInfo() error {
	var githubLoginId interface{}
	if len(user.GithubLoginId) == 0 {
		githubLoginId = gorm.Expr("NULL")
	} else {
		githubLoginId = user.GithubLoginId
	}
	return DB.Model(user).UpdateColumns(map[string]interface{}{
		"github_login_id": githubLoginId,
		"avatar_url":      user.AvatarUrl,
		"github_url":      user.GithubUrl,
	}).Error
}

func (user *User) Lock() error {
	return DB.Model(user).UpdateColumns(map[string]interface{}{
		"lock_state": user.LockState,
	}).Error
}

func ListUsers() ([]*User, error) {
	var users []*User
	err := DB.Find(&users, "is_admin = ?", false).Error
	return users, err
}

// Comment
func (comment *Comment) Insert() error {
	return DB.Create(comment).Error
}

func (comment *Comment) Update() error {
	return DB.Model(comment).UpdateColumn("read_state", true).Error
}

func SetAllCommentRead() error {
	return DB.Model(&Comment{}).Where("read_state = ?", false).Update("read_state", true).Error
}

func ListUnreadComment() ([]*Comment, error) {
	var comments []*Comment
	err := DB.Where("read_state = ?", false).Order("created_at desc").Find(&comments).Error
	return comments, err
}

func MustListUnreadComment() []*Comment {
	comments, _ := ListUnreadComment()
	return comments
}

func (comment *Comment) Delete() error {
	return DB.Delete(comment, "user_id = ?", comment.UserID).Error
}

func ListCommentByPostID(id uint) ([]*Comment, error) {
	var comments []*Comment
	rows, err := DB.Raw("select c.*,u.github_login_id nick_name,u.avatar_url,u.github_url from comments c inner join users u on c.user_id = u.id where c.post_id = ? order by created_at desc", id).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var comment Comment
		DB.ScanRows(rows, &comment)
		comments = append(comments, &comment)
	}
	return comments, err
}

/*func GetComment(id interface{}) (*Comment, error) {
	var comment Comment
	err := DB.First(&comment, id).Error
	return &comment, err
}*/

func CountComment() int64 {
	var count int64
	DB.Model(&Comment{}).Count(&count)
	return count
}

// Subscriber
func (s *Subscriber) Insert() error {
	return DB.FirstOrCreate(s, "email = ?", s.Email).Error
}

func (s *Subscriber) Update() error {
	return DB.Model(s).UpdateColumns(map[string]interface{}{
		"verify_state":    s.VerifyState,
		"subscribe_state": s.SubscribeState,
		"out_time":        s.OutTime,
		"signature":       s.Signature,
		"secret_key":      s.SecretKey,
	}).Error
}

func ListSubscriber(valid bool) ([]*Subscriber, error) {
	var subscribers []*Subscriber
	db := DB.Model(&Subscriber{})
	if valid {
		db.Where("verify_state = ? and subscribe_state = ?", true, true)
	}
	err := db.Find(&subscribers).Error
	return subscribers, err
}

func CountSubscriber() (int64, error) {
	var count int64
	err := DB.Model(&Subscriber{}).Where("verify_state = ? and subscribe_state = ?", true, true).Count(&count).Error
	return count, err
}

func GetSubscriberByEmail(mail string) (*Subscriber, error) {
	var subscriber Subscriber
	err := DB.First(&subscriber, "email = ?", mail).Error
	return &subscriber, err
}

func GetSubscriberBySignature(key string) (*Subscriber, error) {
	var subscriber Subscriber
	err := DB.First(&subscriber, "signature = ?", key).Error
	return &subscriber, err
}

func GetSubscriberById(id uint) (*Subscriber, error) {
	var subscriber Subscriber
	err := DB.First(&subscriber, id).Error
	return &subscriber, err
}

// Link
func (link *Link) Insert() error {
	return DB.FirstOrCreate(link, "url = ?", link.Url).Error
}

func (link *Link) Update() error {
	return DB.Save(link).Error
}

func (link *Link) Delete() error {
	return DB.Delete(link).Error
}

// 获取友情链接
func ListLinks() ([]*Link, error) {
	var links []*Link
	err := DB.Order("sort asc").Find(&links).Error
	return links, err
}

func MustListLinks() []*Link {
	links, _ := ListLinks()
	return links
}

func GetLinkById(id uint) (*Link, error) {
	var link Link
	err := DB.FirstOrCreate(&link, "id = ?", id).Error
	return &link, err
}

/*func GetLinkByUrl(url string) (*Link, error) {
	var link Link
	err := DB.Find(&link, "url = ?", url).Error
	return &link, err
}*/

func (sf SmmsFile) Insert() (err error) {
	err = DB.Create(&sf).Error
	return
}

// 更新用户密码
func (user *User) UpdatePassword() error {
	return DB.Model(user).Update("password", user.Password).Error
}
