package main

import (
	"context"
	"fmt"
	btAuth "github.com/bt-smart/bt-auth-sdk"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
)

func main() {
	// 创建Redis客户端
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "192.168.98.214:6379",
		Password: "btredis123", // 无密码
		DB:       6,            // 默认DB
	})

	// 测试Redis连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("连接Redis失败: %v", err)
	}

	str := "123456"
	fmt.Printf(str)
	// 创建cron实例
	cronInstance := cron.New()

	// 创建授权客户端（使用外部注入的cron）
	authClient := btAuth.NewAuthClientWithCron("http://localhost:7080", cronInstance)

	// 启动cron实例（使用外部注入时，需要手动启动）
	cronInstance.Start()
	// 也可以选择停止整个cron实例
	defer cronInstance.Stop()

	// 创建授权中间件
	authMiddleware := btAuth.NewAuthMiddleware(authClient, redisClient)

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	g := r.Group("/auth-test", authMiddleware.AuthMiddleware())
	{
		g.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, "auth success")
		})
	}
	if err := r.Run("0.0.0.0:7081"); err != nil {
		log.Fatal("gin 启动错误", zap.Error(err))
		return
	}
}
