package main

import (
	"context"
	"errors"
	goauth "go-auth"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/shaj13/go-guardian/v2/auth"
	log "github.com/sirupsen/logrus"
)

const (
	serviceName = "auth-go-api"
	version     = "v1.0"
)

type Server struct {
	Engine *gin.Engine
}

func NewServer() *Server {
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": serviceName,
			"version": version,
			"time":    time.Now().Unix(),
		})
	})
	server := &Server{Engine: engine}
	return server
}

func (server *Server) Start(port string) {
	v := make(chan struct{})
	go func() {
		if err := server.Engine.Run(":" + port); err != nil {
			log.WithError(err).Error("failed to start service")
			close(v)
		}
	}()
	log.Infof("service %v listening on port %v", serviceName, port)
	<-v
}

var GoAuthMdw *goauth.GoAuthMiddleware
var GoAuth goauth.IGoAuth

func main() {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})
	ctx := context.Background()
	str, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatal("Redis - Connect - Error : ", err)
	}
	log.Info("Redis - Connect - Str : ", str)
	g := goauth.GoAuth{
		RedisClient:    redisClient,
		RedisExpiredIn: 120,
		TokenType:      "Bearer",
	}
	GoAuth, err = goauth.NewGoAuth(g)
	if err != nil {
		log.Fatal("GoAuth - Error : ", err)
	}
	GoAuthMdw, err = goauth.NewAuthMiddleware(GoAuth)
	if err != nil {
		log.Fatal("GoAuthMdw - Error : ", err)
	}
	server := NewServer()
	server.Engine.GET("/auth", GoAuthMdw.GinAuthMiddleware(), TestAuth)
	server.Engine.POST("/auth", CreateToken)
	server.Start("8000")
}

func ValidateBasicAuth2(ctx context.Context, r *http.Request, username, password string) (auth.Info, error) {
	return nil, errors.New("invalid credentials")
}

func TestAuth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "OK",
	})
}

func CreateToken(c *gin.Context) {
	client := goauth.AuthClient{
		ClienId: "c2314982-653a-412c-9d7f-42d8e4a10ca6",
		UserId:  "u-1",
	}
	clientRes, err := GoAuth.ClientCredential(client, false)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"code":    http.StatusOK,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":    http.StatusOK,
		"message": "OK",
		"data":    clientRes,
	})
}
