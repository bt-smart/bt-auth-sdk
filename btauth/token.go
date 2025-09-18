package btauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TokenReq struct {
	AppId  string `json:"appId"`  // AppId
	Secret string `json:"secret"` // 秘钥
}

type TokenResponse struct {
	Token     string `json:"token"`     // jwt
	ExpiresAt int64  `json:"expiresAt"` // 过期时间
}

func (ac *AuthClient) getToken() (*TokenResponse, error) {
	// 第一次读锁，尝试直接返回缓存
	ac.mu.RLock()
	if ac.token != nil {
		t := time.Now().Unix()
		if ac.token.ExpiresAt-200 > t {
			token := ac.token
			ac.mu.RUnlock()
			return token, nil
		}
	}
	ac.mu.RUnlock()

	// 获取写锁，防止并发更新
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// 二次检查，可能别的 goroutine 已经刷新过 token 了
	if ac.token != nil {
		t := time.Now().Unix()
		if ac.token.ExpiresAt-200 > t {
			return ac.token, nil
		}
	}

	// 真的过期了，去请求新 token
	req := &TokenReq{
		AppId:  ac.AppId,
		Secret: ac.Secret,
	}
	resp, err := ac.httpclient.PostJSON(ac.baseURL+"/token", req, nil)
	if err != nil {
		return nil, fmt.Errorf("获取client token 失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取client token 失败 状态码: %d", resp.StatusCode)
	}

	var result Result[*TokenResponse]
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("获取client token 失败: %s", result.Msg)
	}

	ac.token = result.Data
	return result.Data, nil
}
