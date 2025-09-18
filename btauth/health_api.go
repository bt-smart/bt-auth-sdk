package btauth

import (
	"fmt"
	"net/http"
)

func (ac *AuthClient) checkHealth() (bool, error) {
	resp, err := ac.httpclient.Get(ac.baseURL+"/health", nil)
	if err != nil {
		return false, fmt.Errorf("健康检查失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("健康检查失败 状态码: %d", resp.StatusCode)
	}
	return true, nil
}
