package authclient

import (
	"github.com/bt-smart/btlog/btzap"
	"github.com/robfig/cron/v3"
)

type Option func(c *AuthClient)

// WithLogger 设置自定义日志
func WithLogger(logger *btzap.Logger) Option {
	return func(c *AuthClient) {
		c.btlog = logger
	}
}

// WithCron 设置自定义 cron
// 外部传入的 cron 由外部启动和管理
func WithCron(cronInstance *cron.Cron) Option {
	return func(c *AuthClient) {
		c.cron = cronInstance
	}
}
