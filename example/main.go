package main

import (
	"context"
	"github.com/bt-smart/bt-auth-sdk/authclient"
	"github.com/bt-smart/btlog/btzap"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

	logger, err := newLogger()
	if err != nil {
		log.Println(err.Error())
		return
	}

	// 创建cron实例
	cronInstance := cron.New()

	// 创建授权客户端（使用外部注入的cron）
	ac := authclient.NewAuthClient("http://localhost:7080", redisClient, authclient.WithLogger(logger), authclient.WithCron(cronInstance))

	// 启动cron实例（使用外部注入时，需要手动启动）
	cronInstance.Start()
	// 也可以选择停止整个cron实例
	defer cronInstance.Stop()

	// 创建授权中间件

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	g := r.Group("/auth-test", ac.Middleware())
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

func newLogger() (*btzap.Logger, error) {
	// 创建共享的 HTTP 客户端
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
	}

	cfg := &btzap.Config{
		EnableConsole: true,              // 是否启用控制台日志输出
		EnableFile:    false,             // 是否启用文件日志输出
		EnableLoki:    true,              // 是否启用Loki日志输出
		ConsoleLevel:  zapcore.InfoLevel, // 控制台输出的最小日志级别
		FileLevel:     zapcore.InfoLevel, // 文件输出的最小日志级别
		LokiLevel:     zapcore.InfoLevel, // loki输出的最小日志级别
		EnableCaller:  true,              // 是否记录调用方信息
		FilePath:      "./logs/app.log",  // 日志文件路径
		MaxSize:       100,               // 日志文件最大大小(MB)
		MaxBackups:    3,                 // 保留旧文件的最大个数
		MaxAge:        28,                // 保留旧文件的最大天数
		Compress:      true,              // 是否压缩旧文件
		LokiConfig: btzap.LokiConfig{ // Loki配置
			URL:        "http://192.168.98.214:3100",
			BatchSize:  100,
			Labels:     map[string]string{"service_name": "btlog-demo-dev"},
			HTTPClient: httpClient,
		},
	}

	logger, err := btzap.NewLogger(cfg)
	if err != nil {
		return nil, err
	}
	return logger, nil
}
