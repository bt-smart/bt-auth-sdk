package btauth

import (
	"context"
	"errors"
	"fmt"
	"github.com/bt-smart/btutil/redisutil"
	"github.com/redis/go-redis/v9"
)

// 用户权限策略缓存
const userPolicyPrefix = "user:policies:"

func UserPolicyKey(userID uint64) string {
	return fmt.Sprintf("%s%d", userPolicyPrefix, userID)
}

// 应用权限策略缓存
const appPolicyPrefix = "app:policies:"

func AppPolicyKey(clientId uint64) string {
	return fmt.Sprintf("%s%d", appPolicyPrefix, clientId)
}

func GetAppCache(appId uint64, c *redis.Client) ([]string, error) {
	var ps []string
	err := redisutil.GetStruct(c, context.Background(), AppPolicyKey(appId), &ps)
	if err != nil {
		return ps, errors.New("get app cache fail")
	}
	return ps, nil
}

func GetUserCache(userId uint64, c *redis.Client) ([]string, error) {
	var ps []string
	err := redisutil.GetStruct(c, context.Background(), UserPolicyKey(userId), &ps)
	if err != nil {
		return ps, errors.New("get user cache fail" + err.Error())
	}
	return ps, nil
}
