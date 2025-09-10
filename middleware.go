package bt_auth_sdk

import (
	"github.com/bt-smart/btutil/result"
	"github.com/bt-smart/btutil/urlutil"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"net/http"
)

const (
	// ContextUserIDKey 用户ID上下文键
	ContextUserIDKey = "userId"
	// ContextClientIDKey 客户端ID上下文键
	ContextClientIDKey = "clientId"
)

// AuthMiddleware 授权中间件
type AuthMiddleware struct {
	client      *AuthClient
	redisClient *redis.Client
}

// NewAuthMiddleware 创建新的授权中间件
func NewAuthMiddleware(client *AuthClient, redisClient *redis.Client) *AuthMiddleware {
	return &AuthMiddleware{
		client:      client,
		redisClient: redisClient,
	}
}

// AuthMiddleware 是一个 Gin 中间件，用于检查 zk-token
func (m *AuthMiddleware) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取请求的 URL
		requestURL := c.Request.URL.Path
		zkToken := c.GetHeader("bt-token")
		// 如果没有传 zk-token 返回 401 Unauthorized
		if zkToken == "" {
			c.JSON(http.StatusUnauthorized, result.FailWithCodeAndMsg(http.StatusUnauthorized, "not logged in"))
			c.Abort()
			return
		}

		// 校验jwt并从其中取出userId
		claims, err := m.client.VerifyJWT(zkToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, result.FailWithCodeAndMsg(http.StatusUnauthorized, "not logged in"))
			c.Abort()
			return
		}
		// 校验tokenType
		if claims.TokenType == TokenTypeUser {
			// 校验用户对这个接口有没有权限
			ok := m.checkUserPermission(requestURL, claims.UserId)
			if !ok {
				c.JSON(http.StatusForbidden, result.FailWithCodeAndMsg(http.StatusForbidden, "permission denied"))
				c.Abort()
				return
			}
			// 将 userId 放入请求上下文
			c.Set(ContextUserIDKey, claims.UserId)
		} else if claims.TokenType == TokenTypeClient {
			// 校验客户端对这个接口有没有权限
			ok := m.checkClientPermission(requestURL, claims.ClientId)
			if !ok {
				c.JSON(http.StatusForbidden, result.FailWithCodeAndMsg(http.StatusForbidden, "permission denied"))
				c.Abort()
				return
			}
			// 将 userId 放入请求上下文
			c.Set(ContextClientIDKey, claims.ClientId)
		} else {
			c.JSON(http.StatusUnauthorized, result.FailWithCodeAndMsg(http.StatusUnauthorized, "not logged in"))
			c.Abort()
			return
		}

		// 继续处理请求
		c.Next()
	}
}

// 检查权限
func (m *AuthMiddleware) checkUserPermission(url string, userId uint64) bool {
	polices, err := GetUserCache(userId, m.redisClient)
	if err != nil || polices == nil {
		return false
	}
	for _, pattern := range polices {
		ok := urlutil.MatchesPattern(url, pattern)
		if ok {
			return true
		}
	}
	return false
}

func (m *AuthMiddleware) checkClientPermission(url string, clientId uint64) bool {
	polices, err := GetClientCache(clientId, m.redisClient)
	if err != nil || polices == nil {
		return false
	}
	for _, pattern := range polices {
		ok := urlutil.MatchesPattern(url, pattern)
		if ok {
			return true
		}
	}
	return false
}
