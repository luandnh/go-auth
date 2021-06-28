package goauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/go-guardian/v2/auth/strategies/union"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
)

// type IGoAuthMiddleware interface {
// 	ValidateBasicAuth(ctx context.Context, r *http.Request, username, password string) (auth.Info, error)
// }

type GoAuthMiddleware struct {
	GoAuth        IGoAuth
	CacheObj      libcache.Cache
	Strategy      union.Union
	TokenStrategy auth.Strategy
}

func NewAuthMiddleware(client IGoAuth) (*GoAuthMiddleware, error) {
	ig := new(GoAuthMiddleware)
	ig.GoAuth = client

	ig.SetupGoAuthMiddleware()
	return ig, nil
}

func (ig *GoAuthMiddleware) SetupGoAuthMiddleware() {
	ig.CacheObj = libcache.FIFO.New(0)
	ig.CacheObj.SetTTL(time.Minute * 10)
	ig.CacheObj.RegisterOnExpired(func(key, _ interface{}) {
		ig.CacheObj.Peek(key)
	})
	basicStrategy := basic.NewCached(ig.ValidateBasicAuth, ig.CacheObj)
	ig.TokenStrategy = token.New(ig.ValidateTokenAuth, ig.CacheObj)
	ig.Strategy = union.New(ig.TokenStrategy, basicStrategy)
}

func (ig *GoAuthMiddleware) ValidateBasicAuth(ctx context.Context, r *http.Request, username, password string) (auth.Info, error) {

	if username == "luandnh" && password == "123456" {
		extension := make(map[string][]string)
		user := auth.NewDefaultUser("", "u-123", nil, extension)
		return user, nil
	}
	return nil, errors.New("invalid credentials")
}

func (ig *GoAuthMiddleware) ValidateTokenAuth(ctx context.Context, r *http.Request, tokenString string) (auth.Info, time.Time, error) {
	client, err := ig.GoAuth.CheckTokenInRedis(tokenString)
	if err != nil {
		return nil, time.Time{}, err
	}
	token, err := jwt.Parse(client.JWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		extension := make(map[string][]string)
		user := auth.NewDefaultUser("", claims["id"].(string), nil, extension)
		return user, time.Time{}, nil
	}
	return nil, time.Time{}, errors.New("invalid token")
}

func (ig *GoAuthMiddleware) SetupStrategies(strategies ...auth.Strategy) {
	ig.Strategy = union.New(strategies...)
}
func (ig *GoAuthMiddleware) GinAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, user, err := ig.Strategy.AuthenticateRequest(c.Request)
		if err != nil {
			c.JSON(
				http.StatusUnauthorized,
				gin.H{
					"error": http.StatusText(http.StatusUnauthorized),
				},
			)
			c.Abort()
			return
		}
		c.Set("user", user)
	}
}
