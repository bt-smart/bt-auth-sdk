package authclient

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/bt-smart/btlog/btzap"
	"github.com/bt-smart/btutil/crypto"
	"github.com/bt-smart/btutil/httpclient"
	"github.com/redis/go-redis/v9"
	"sync"
	"time"
)

// AuthClient 授权服务客户端
type AuthClient struct {
	baseURL      string                    // 基础URL
	AppId        string                    `json:"appId"`  // AppId
	Secret       string                    `json:"secret"` // 秘钥
	publicKeys   []PublicKey               // 原始公钥信息 PEM的字符串
	publicKeyMap map[string]*rsa.PublicKey // kid -> 公钥映射，用于验证
	token        *TokenResponse            // 客户端访问token
	lastUpdated  time.Time                 // 公钥最后更新时间
	mu           sync.RWMutex              // mu 用于保护共享资源的读写锁，确保并发安全访问。
	btlog        *btzap.Logger             // btlog 是用于日志记录的btzap.Logger实例。
	redisClient  *redis.Client             // redisClient 用于与Redis服务器进行交互的客户端实例。
	httpclient   *httpclient.Client        // http 客户端

	// 嵌入子模块-------------------------------------------
	User *UserClient // 用户模块
}

// Result 通用响应
type Result[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

// NewAuthClient 创建授权客户端
// baseURL 应为服务基础URL，例如：http://localhost:7080/auth
func NewAuthClient(baseURL, appId, secret string, redisClient *redis.Client, logger *btzap.Logger, opts ...Option) (*AuthClient, error) {
	ac := &AuthClient{
		baseURL:      baseURL,
		AppId:        appId,
		Secret:       secret,
		redisClient:  redisClient,
		publicKeys:   []PublicKey{},
		publicKeyMap: make(map[string]*rsa.PublicKey),
		lastUpdated:  time.Time{},
		mu:           sync.RWMutex{},
		btlog:        logger,
	}

	// 子模块
	ac.User = &UserClient{ac: ac}

	// 应用可选配置
	for _, opt := range opts {
		opt(ac)
	}

	// 如果没有传 logger 就报错
	if ac.btlog == nil {
		return nil, errors.New("logger == nil")
	}

	// 如果没有传 httpclient 就自己创建
	if ac.httpclient == nil {
		ac.httpclient = httpclient.New(10 * time.Second)
	}

	// 初始化 token
	err := ac.initToken()
	if err != nil {
		return nil, errors.New("初始化token失败: " + err.Error())
	}

	// 立即获取一次公钥
	err = ac.updatePublicKeys()
	if err != nil {
		return nil, errors.New("第一次获取公钥失败: " + err.Error())
	}

	return ac, nil
}

// RefreshPublicKeys 外部调度调用刷新
func (ac *AuthClient) RefreshPublicKeys() error {
	return ac.updatePublicKeys()
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
	publicKeys, err := ac.GetPublicKeys()
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

func (ac *AuthClient) initToken() error {
	ok, err := ac.checkHealth()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("健康检查失败")
	}

	_, err = ac.getToken()
	if err != nil {
		return err
	}

	return nil
}

func (ac *AuthClient) getAuthHeaders() (map[string]string, error) {
	tokenResp, err := ac.getToken() // 确保 token 有效
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"Authorization": "Bearer " + tokenResp.Token,
	}, nil
}
