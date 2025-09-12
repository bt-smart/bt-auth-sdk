package authclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type UserClient struct {
	ac *AuthClient
}

type ApiUser struct {
	//主键
	ID uint64 `json:"id"`
	//用户名
	Username string `json:"username" `
	// 昵称
	Name string `json:"name" `
	//手机号
	Phone *string `json:"phone" `
	//邮箱
	Email *string `json:"email" `
	// 用户状态 0正常 1封禁
	Status int8 `json:"status"`
	// 最后登录时间
	LastLoginTime *time.Time `json:"lastLoginTime"`
	// 创建时间
	CreatedAt time.Time `json:"createdAt"`
}

func (uc *UserClient) Info(id uint64) (*ApiUser, error) {
	authHeader, err := uc.ac.getAuthHeaders()
	if err != nil {
		return nil, err
	}
	resp, err := uc.ac.httpclient.Get(fmt.Sprintf("%s/user/read/%d", uc.ac.baseURL, id), authHeader)
	if err != nil {
		return nil, fmt.Errorf("获取用户信息失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取用户信息失败 状态码: %d", resp.StatusCode)
	}

	var result Result[*ApiUser]
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	return result.Data, nil
}
