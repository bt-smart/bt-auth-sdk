package bt_auth_sdk

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bt-smart/btutil/crypto"
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
func NewAuthClient(baseURL string) *AuthClient {
	cronInstance := cron.New()
	c := NewAuthClientWithCron(baseURL, cronInstance)

	// 启动内部创建的cron实例
	cronInstance.Start()

	return c
}

// NewAuthClientWithCron 使用外部注入的cron创建新的授权客户端
// baseURL 应为服务基础URL，例如：http://your-auth-service-url
// 注意：外部传入的cron实例需要由外部负责启动和停止
func NewAuthClientWithCron(baseURL string, cronInstance *cron.Cron) *AuthClient {
	c := &AuthClient{
		baseURL:      baseURL,
		publicKeys:   []PublicKey{},
		publicKeyMap: make(map[string]*rsa.PublicKey),
		lastUpdated:  time.Time{},
		mu:           sync.RWMutex{},
		cron:         cronInstance,
	}

	// 立即获取一次公钥
	_ = c.updatePublicKeys()

	// 设置每天凌晨2点更新公钥
	id, _ := c.cron.AddFunc("0 8 * * *", func() {
		_ = c.updatePublicKeys()
	})
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
