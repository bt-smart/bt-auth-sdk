package authclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// PublicKey 公钥信息
type PublicKey struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	PEM string `json:"pem"`
}

func (ac *AuthClient) getPublicKeys() ([]PublicKey, error) {
	resp, err := ac.httpclient.Get(ac.baseURL+"/public-key", nil)
	if err != nil {
		return nil, fmt.Errorf("获取公钥失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取公钥失败 状态码: %d", resp.StatusCode)
	}

	var result Result[[]PublicKey]
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("获取公钥失败: %s", result.Msg)
	}

	if len(result.Data) == 0 {
		return nil, errors.New("获取公钥失败: 公钥列表为空")
	}
	return result.Data, nil
}
