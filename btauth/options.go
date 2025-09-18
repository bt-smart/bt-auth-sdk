package btauth

import (
	"github.com/bt-smart/btutil/httpclient"
)

type Option func(c *AuthClient)

func WithHttpClient(hc *httpclient.Client) Option {
	return func(c *AuthClient) {
		c.httpclient = hc
	}
}
