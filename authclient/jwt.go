package authclient

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType 令牌类型
type TokenType string

const (
	TokenTypeUser   TokenType = "u"
	TokenTypeClient TokenType = "c"
)

const KID = "kid"

// Claims JWT声明结构体
type Claims struct {
	UserId    uint64    `json:"uid,omitempty"`
	ClientId  uint64    `json:"cid,omitempty"`
	TokenType TokenType `json:"tkt,omitempty"`
	jwt.RegisteredClaims
}

// VerifyJWT 验证JWT令牌
func (ac *AuthClient) VerifyJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header[KID].(string)
		if !ok {
			return nil, errors.New("kid header missing or invalid")
		}
		pubKey, ok := ac.GetPublicKeyByKid(kid)
		if !ok {
			return nil, fmt.Errorf("unknown kid: %s", kid)
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}
