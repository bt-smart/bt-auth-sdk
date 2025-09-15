package authclient

import (
	"github.com/bt-smart/btutil/result"
	"github.com/bt-smart/btutil/urlutil"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

const (
	// ContextUserIDKey 用户ID上下文键
	ContextUserIDKey = "userId"
	// ContextClientIDKey 客户端ID上下文键
	ContextClientIDKey = "clientId"
)

// Middleware 是一个 Gin 中间件，用于检查 请求头的token
func (ac *AuthClient) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		// 如果没有传 zk-token 返回 401 Unauthorized
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, result.FailWithCodeAndMsg(http.StatusUnauthorized, "missing authorization header"))
			c.Abort()
			return
		}

		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			c.JSON(http.StatusUnauthorized, result.FailWithCodeAndMsg(http.StatusUnauthorized, "invalid authorization header format"))
			c.Abort()
			return
		}

		// 提取 token
		token := strings.TrimPrefix(authHeader, prefix)

		// 校验jwt
		claims, err := ac.VerifyJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, result.FailWithCodeAndMsg(http.StatusUnauthorized, "not logged in"))
			c.Abort()
			return
		}

		// 获取请求的 URL
		requestURL := c.Request.URL.Path

		// 校验tokenType
		if claims.TokenType == TokenTypeUser {
			// 校验用户对这个接口有没有权限
			ok := ac.checkUserPermission(requestURL, claims.UserId)
			if !ok {
				c.JSON(http.StatusForbidden, result.FailWithCodeAndMsg(http.StatusForbidden, "permission denied"))
				c.Abort()
				return
			}
			// 将 userId 放入请求上下文
			c.Set(ContextUserIDKey, claims.UserId)
		} else if claims.TokenType == TokenTypeClient {
			// 校验客户端对这个接口有没有权限
			ok := ac.checkClientPermission(requestURL, claims.ClientId)
			if !ok {
				c.JSON(http.StatusForbidden, result.FailWithCodeAndMsg(http.StatusForbidden, "permission denied"))
				c.Abort()
				return
			}
			// 将 clientId 放入请求上下文
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
func (ac *AuthClient) checkUserPermission(url string, userId uint64) bool {
	polices, err := GetUserCache(userId, ac.redisClient)
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

func (ac *AuthClient) checkClientPermission(url string, clientId uint64) bool {
	polices, err := GetClientCache(clientId, ac.redisClient)
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
