package btauth

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bt-smart/btlog/btzap"
	"github.com/bt-smart/btutil/crypto"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// AuthClient 授权服务客户端
type AuthClient struct {
	baseURL      string                    // 基础URL
	publicKeys   []PublicKey               // 原始公钥信息
	publicKeyMap map[string]*rsa.PublicKey // kid -> 公钥映射，用于验证
	lastUpdated  time.Time
	mu           sync.RWMutex
	btlog        *btzap.Logger
	cron         *cron.Cron
	cronID       cron.EntryID
}

// PublicKey 公钥信息
type PublicKey struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	PEM string `json:"pem"`
}

// PublicKeyResponse 公钥接口响应
type PublicKeyResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data []PublicKey `json:"data"`
}

// NewAuthClient 创建新的授权客户端
// baseURL 应为服务基础URL，例如：http://your-auth-service-url
func NewAuthClient(baseURL string, btlog *btzap.Logger) *AuthClient {
	cronInstance := cron.New()
	c := NewAuthClientWithCron(baseURL, cronInstance, btlog)

	// 启动内部创建的cron实例
	cronInstance.Start()

	return c
}

// NewAuthClientWithCron 使用外部注入的cron创建新的授权客户端
// baseURL 应为服务基础URL，例如：http://your-auth-service-url
// 注意：外部传入的cron实例需要由外部负责启动和停止
func NewAuthClientWithCron(baseURL string, cronInstance *cron.Cron, btlog *btzap.Logger) *AuthClient {
	if btlog == nil {
		logger, err := newLogger()
		if err != nil {
			panic("创建btlog失败: " + err.Error())
		}
		btlog = logger
	}

	c := &AuthClient{
		baseURL:      baseURL,
		publicKeys:   []PublicKey{},
		publicKeyMap: make(map[string]*rsa.PublicKey),
		lastUpdated:  time.Time{},
		btlog:        btlog,
		mu:           sync.RWMutex{},
		cron:         cronInstance,
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
func (c *AuthClient) GetPublicKeyByKid(kid string) (*rsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pubKey, ok := c.publicKeyMap[kid]
	return pubKey, ok
}

// updatePublicKeys 更新公钥列表
func (c *AuthClient) updatePublicKeys() error {
	resp, err := http.Get(c.baseURL + "/auth/public-key")
	if err != nil {
		return fmt.Errorf("获取公钥失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取公钥失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	var response PublicKeyResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}

	if response.Code != 0 {
		return fmt.Errorf("获取公钥失败: %s", response.Msg)
	}

	if len(response.Data) == 0 {
		return errors.New("获取公钥失败: 公钥列表为空")
	}

	// 解析公钥并构建映射
	newPublicKeyMap := make(map[string]*rsa.PublicKey)
	for _, key := range response.Data {
		pubKey, err := crypto.ParseRSAPublicKeyFromPEM(key.PEM)
		if err != nil {
			return fmt.Errorf("解析公钥失败 (kid=%s): %w", key.Kid, err)
		}
		newPublicKeyMap[key.Kid] = pubKey
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.publicKeys = response.Data
	c.publicKeyMap = newPublicKeyMap
	c.lastUpdated = time.Now()

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
