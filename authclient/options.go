package authclient

import (
	"github.com/bt-smart/btlog/btzap"
	"github.com/bt-smart/btutil/httpclient"
)

type Option func(c *AuthClient)

// WithLogger 设置自定义日志
func WithLogger(logger *btzap.Logger) Option {
	return func(c *AuthClient) {
		c.btlog = logger
	}
}

func WithHttpClient(hc *httpclient.Client) Option {
	return func(c *AuthClient) {
		c.httpclient = hc
	}
}
