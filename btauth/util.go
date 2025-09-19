package btauth

import "github.com/gin-gonic/gin"

// GetUserId 获取上下文中的userId
func GetUserId(c *gin.Context) uint64 {
	return c.GetUint64(ContextUserIDKey)
}

// GetAppId 获取上下文中的appId
func GetAppId(c *gin.Context) uint64 {
	return c.GetUint64(ContextAppIdKey)
}
