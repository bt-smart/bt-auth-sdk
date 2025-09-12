package authclient

import (
	"crypto/rsa"
	"fmt"
	"github.com/bt-smart/btlog/btzap"
	"github.com/bt-smart/btutil/crypto"
	"github.com/bt-smart/btutil/httpclient"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// AuthClient 授权服务客户端
type AuthClient struct {
	baseURL      string                    // 基础URL
	AppId        string                    `json:"appId"`  // AppId
	Secret       string                    `json:"secret"` // 秘钥
	publicKeys   []PublicKey               // 原始公钥信息 PEM的字符串
	publicKeyMap map[string]*rsa.PublicKey // kid -> 公钥映射，用于验证
	lastUpdated  time.Time                 // 公钥最后更新时间
	mu           sync.RWMutex              // mu 用于保护共享资源的读写锁，确保并发安全访问。
	btlog        *btzap.Logger             // btlog 是用于日志记录的btzap.Logger实例。
	redisClient  *redis.Client             // redisClient 用于与Redis服务器进行交互的客户端实例。
	httpclient   *httpclient.Client        // http 客户端
	cron         *cron.Cron                // cron 用于定时任务调度的Cron实例，支持定时更新公钥等任务。
	cronID       cron.EntryID              // cronID 存储定时任务的唯一标识符，用于管理和操作特定的Cron任务。
}

// Result 通用响应
type Result[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

// NewAuthClient 使用外部注入的cron创建新的授权客户端
// baseURL 应为服务基础URL，例如：http://your-auth-service-url
// 注意：外部传入的cron实例需要由外部负责启动和停止
func NewAuthClient(baseURL, appId, secret string, redisClient *redis.Client, opts ...Option) *AuthClient {
	c := &AuthClient{
		baseURL:      baseURL,
		AppId:        appId,
		Secret:       secret,
		redisClient:  redisClient,
		publicKeys:   []PublicKey{},
		publicKeyMap: make(map[string]*rsa.PublicKey),
		lastUpdated:  time.Time{},
		mu:           sync.RWMutex{},
	}

	// 应用可选配置
	for _, opt := range opts {
		opt(c)
	}

	// 如果没有传 logger，就自己创建
	if c.btlog == nil {
		logger, err := newLogger()
		if err != nil {
			panic("创建btlog失败: " + err.Error())
		}
		c.btlog = logger
	}

	// 如果没有传 cron，就自己创建并启动
	if c.cron == nil {
		c.cron = cron.New()
		c.cron.Start()
	}

	// 如果没有传 httpclient 就自己创建
	if c.httpclient == nil {
		c.httpclient = httpclient.New(10)
	}

	// 立即获取一次公钥
	err := c.updatePublicKeys()
	if err != nil {
		c.btlog.Logger.Error("第一次获取公钥失败: ", zap.String("err", err.Error()))
	}

	// 设置每天早上八点更新公钥
	id, err := c.cron.AddFunc("0 8 * * *", func() {
		err = c.updatePublicKeys()
		if err != nil {
			c.btlog.Logger.Error("更新公钥失败: ", zap.String("err", err.Error()))
		}
	})
	if err != nil {
		c.btlog.Logger.Error("添加定时任务失败: ", zap.String("err", err.Error()))
	}
	c.cronID = id

	// 注意：不在此处启动cron，由外部负责启动

	return c
}

// GetPublicKeyByKid 根据kid获取公钥
// 返回对应kid的RSA公钥，如果未找到则返回错误
func (ac *AuthClient) GetPublicKeyByKid(kid string) (*rsa.PublicKey, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	pubKey, ok := ac.publicKeyMap[kid]
	return pubKey, ok
}

// updatePublicKeys 更新公钥列表
func (ac *AuthClient) updatePublicKeys() error {
	publicKeys, err := ac.getPublicKeys()
	if err != nil {
		return err
	}

	// 解析公钥并构建映射
	newPublicKeyMap := make(map[string]*rsa.PublicKey)
	for _, key := range publicKeys {
		pubKey, err := crypto.ParseRSAPublicKeyFromPEM(key.PEM)
		if err != nil {
			return fmt.Errorf("解析公钥失败 (kid=%s): %w", key.Kid, err)
		}
		newPublicKeyMap[key.Kid] = pubKey
	}

	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.publicKeys = publicKeys
	ac.publicKeyMap = newPublicKeyMap
	ac.lastUpdated = time.Now()

	return nil
}

func newLogger() (*btzap.Logger, error) {
	// 创建共享的 HTTP 客户端
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
	}

	cfg := &btzap.Config{
		EnableConsole: true,              // 是否启用控制台日志输出
		EnableFile:    false,             // 是否启用文件日志输出
		EnableLoki:    true,              // 是否启用Loki日志输出
		ConsoleLevel:  zapcore.InfoLevel, // 控制台输出的最小日志级别
		FileLevel:     zapcore.InfoLevel, // 文件输出的最小日志级别
		LokiLevel:     zapcore.InfoLevel, // loki输出的最小日志级别
		EnableCaller:  true,              // 是否记录调用方信息
		FilePath:      "./logs/app.log",  // 日志文件路径
		MaxSize:       100,               // 日志文件最大大小(MB)
		MaxBackups:    3,                 // 保留旧文件的最大个数
		MaxAge:        28,                // 保留旧文件的最大天数
		Compress:      true,              // 是否压缩旧文件
		LokiConfig: btzap.LokiConfig{ // Loki配置
			URL:        "http://192.168.98.214:3100",
			BatchSize:  100,
			Labels:     map[string]string{"service_name": "btlog-demo-dev"},
			HTTPClient: httpClient,
		},
	}

	logger, err := btzap.NewLogger(cfg)
	if err != nil {
		return nil, err
	}
	return logger, nil
}
