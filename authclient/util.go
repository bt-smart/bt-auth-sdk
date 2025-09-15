package authclient

import "github.com/gin-gonic/gin"

// GetUserId 获取上下文中的userId
func GetUserId(c *gin.Context) uint64 {
	return c.GetUint64(ContextUserIDKey)
}

// GetClientId 获取上下文中的clientId
func GetClientId(c *gin.Context) uint64 {
	return c.GetUint64(ContextClientIDKey)
}
