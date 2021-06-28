package goauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	tokenKey  = "access_token_key"
	userKey   = "access_user_key"
	expiredIn = 10000
	redisHost = "localhost"
	redisPort = "6379"
	redisDb   = 2
	tokenType = "Bearer"
)

var ctx = context.Background()

type IGoAuth interface {
	GetTokenFromRedis(clientId string) (interface{}, error)
	GetUserFromRedis(clientId string) (interface{}, error)
	InsertClientToRedis(client AuthClient) error
	DeleteClientFromRedis(client AuthClient) error
	ClientCredential(client AuthClient, isRefresh bool) (AuthClient, error)
	CheckClientInRedis(client AuthClient) (AuthClient, error)
	CheckTokenInRedis(token string) (AuthClient, error)
	CreateClient(client AuthClient) AuthClient
	CreateClientResponse(client AuthClient, isRefresh bool) (AuthClient, error)
}

type GoAuth struct {
	RedisTokenKey  string
	RedisUserKey   string
	RedisExpiredIn int
	RedisClient    *redis.Client
	TokenType      string
}

type AuthClient struct {
	ClienId      string            `json:"client_id"`
	UserId       string            `json:"user_id"`
	Token        string            `json:"token"`
	RefreshToken string            `json:"refresh_token"`
	CreatedTime  time.Time         `json:"created_at"`
	ExpiredTime  time.Time         `json:"expired_at"`
	ExpiredIn    int               `json:"expired_in"`
	Scope        string            `json:"scope"`
	TokenType    string            `json:"token_type"`
	JWT          string            `json:"jwt"`
	UserData     map[string]string `json:"-"`
}

func NewGoAuth(client GoAuth) (IGoAuth, error) {
	g := new(GoAuth)
	if client.RedisTokenKey == "" {
		g.RedisTokenKey = tokenKey
	} else {
		g.RedisTokenKey = client.RedisTokenKey
	}
	if client.RedisUserKey == "" {
		g.RedisUserKey = userKey
	} else {
		g.RedisUserKey = client.RedisTokenKey
	}
	if client.RedisExpiredIn == 0 {
		g.RedisExpiredIn = expiredIn
	} else {
		g.RedisExpiredIn = client.RedisExpiredIn
	}
	if client.RedisClient == nil {
		return nil, errors.New("please config redis client")
	} else {
		g.RedisClient = client.RedisClient
	}
	if client.TokenType == "" {
		g.TokenType = tokenType
	} else {
		g.TokenType = client.TokenType
	}
	return g, nil
}

func GenerateJWT(id string, data map[string]string) string {
	claim := jwt.MapClaims{
		"id": id,
	}
	if len(data) > 0 {
		for key, value := range data {
			claim[key] = value
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	jwtToken, _ := token.SignedString([]byte("secret"))
	return jwtToken
}

func (g *GoAuth) GetTokenFromRedis(clientId string) (interface{}, error) {
	res, err := g.RedisClient.HMGet(ctx, g.RedisTokenKey, clientId).Result()
	if err != nil {
		return nil, err
	}
	var authClient AuthClient
	if len(res) == 0 {
		return nil, nil
	} else {
		authClientRes, ok := res[0].(string)
		if ok {
			err := json.Unmarshal([]byte(authClientRes), &authClient)
			if err != nil {
				return nil, err
			}
		}
		return authClient, nil
	}
}

func (g *GoAuth) GetUserFromRedis(clientId string) (interface{}, error) {
	res, err := g.RedisClient.HMGet(ctx, g.RedisUserKey, clientId).Result()
	if err != nil {
		return nil, err
	}
	var authClient AuthClient
	if len(res) == 0 {
		return nil, nil
	} else {
		authClientRes, ok := res[0].(string)
		if ok {
			err := json.Unmarshal([]byte(authClientRes), &authClient)
			if err != nil {
				return nil, err
			}
		}
		return authClient, nil
	}
}

func (g *GoAuth) InsertClientToRedis(client AuthClient) error {
	clientId := client.ClienId
	token := client.Token
	jsonClient, err := json.Marshal(client)
	if err != nil {
		return err
	}
	jsonClientString := string(jsonClient)
	clientStoreInfo := map[string]interface{}{clientId: jsonClientString}
	tokenStoreInfo := map[string]interface{}{token: jsonClientString}
	if err := g.RedisClient.HSet(ctx, g.RedisUserKey, clientStoreInfo).Err(); err != nil {
		return err
	}
	if err := g.RedisClient.HSet(ctx, g.RedisTokenKey, tokenStoreInfo).Err(); err != nil {
		return err
	}
	return nil
}

func (g *GoAuth) DeleteClientFromRedis(client AuthClient) error {
	clientId := client.ClienId
	token := client.Token
	err := g.RedisClient.HDel(ctx, g.RedisUserKey, clientId).Err()
	if err != nil {
		return err
	}
	err = g.RedisClient.HDel(ctx, g.RedisTokenKey, token).Err()
	if err != nil {
		return err
	}
	return err
}

func (g *GoAuth) CreateClient(client AuthClient) AuthClient {
	currentTime := time.Now().Local()
	expiredIn := 0
	if client.ExpiredIn != 0 {
		expiredIn = client.ExpiredIn
	} else {
		expiredIn = g.RedisExpiredIn
	}
	expiredTime := currentTime.Add(time.Duration(expiredIn) * time.Second)
	accesstoken := AuthClient{
		ClienId:      client.ClienId,
		UserId:       client.UserId,
		Token:        GenerateToken(client.ClienId),
		RefreshToken: GenerateRefreshToken(client.ClienId),
		CreatedTime:  currentTime,
		ExpiredTime:  expiredTime,
		Scope:        client.Scope,
		TokenType:    g.TokenType,
	}
	accesstoken.JWT = GenerateJWT(client.UserId, client.UserData)
	return accesstoken
}

func (g *GoAuth) ClientCredential(client AuthClient, isRefresh bool) (AuthClient, error) {
	client, err := g.CheckClientInRedis(client)
	if err != nil {
		return client, err
	}
	clientResponse, err := g.CreateClientResponse(client, isRefresh)
	if err != nil {
		return client, err
	}
	return clientResponse, nil
}
func (g *GoAuth) CheckClientInRedis(client AuthClient) (AuthClient, error) {
	log.Info("ClientCredential - clientId : ", client.ClienId)
	var clientNew AuthClient
	clientRes, err := g.GetUserFromRedis(client.ClienId)
	if err != nil {
		return clientNew, err
	}
	if clientRes != "" {
		var ok bool
		clientNew, ok = clientRes.(AuthClient)
		if !ok {
			return clientNew, errors.New("parse client json failed")
		}
	}
	if clientNew.ClienId == "" {
		clientNew = g.CreateClient(client)
		if err := g.InsertClientToRedis(clientNew); err != nil {
			return clientNew, err
		}
	} else {
		currentTime := time.Now().Local()
		if clientNew.ExpiredTime.Sub(currentTime) <= 0 {
			if err := g.DeleteClientFromRedis(clientNew); err != nil {
				return clientNew, err
			}
			clientNew = g.CreateClient(client)
			if err := g.InsertClientToRedis(clientNew); err != nil {
				return clientNew, err
			}
		} else {
			log.Info("ClientCredential - token already existed")
		}
	}
	return clientNew, nil
}

func (g *GoAuth) CheckTokenInRedis(token string) (AuthClient, error) {
	var client AuthClient
	clientRes, err := g.GetTokenFromRedis(token)
	if err != nil {
		return client, err
	}
	client, ok := clientRes.(AuthClient)
	if !ok {
		return client, errors.New("parse client json failed")
	}
	currentTime := time.Now().Local()
	if client.ExpiredTime.Sub(currentTime) <= 0 {
		return client, errors.New("token is expired")
	}
	return client, nil
}

func (g *GoAuth) CreateClientResponse(client AuthClient, isRefresh bool) (AuthClient, error) {
	response := AuthClient{}
	if client.Token == "" {
		return response, errors.New("token is null")
	}
	currentTime := time.Now().Local()
	if !isRefresh {
		response = AuthClient{
			CreatedTime: client.CreatedTime,
			ClienId:     client.ClienId,
			UserId:      client.UserId,
			Token:       client.Token,
			ExpiredTime: client.ExpiredTime,
			ExpiredIn:   int(client.ExpiredTime.Sub(currentTime).Seconds()),
			TokenType:   g.TokenType,
			JWT:         client.JWT,
			Scope:       client.Scope,
		}
	} else {
		response = AuthClient{
			CreatedTime:  client.CreatedTime,
			ClienId:      client.ClienId,
			UserId:       client.UserId,
			Token:        client.Token,
			ExpiredTime:  client.ExpiredTime,
			ExpiredIn:    int(client.ExpiredTime.Sub(currentTime).Seconds()),
			TokenType:    g.TokenType,
			Scope:        client.Scope,
			JWT:          client.JWT,
			RefreshToken: client.RefreshToken,
		}
	}

	return response, nil
}

func GenerateToken(id string) string {
	uuidNew, _ := uuid.NewRandom()
	idEnc := base64.StdEncoding.EncodeToString([]byte(id))
	token := strings.Replace(uuidNew.String(), "-", "", -1)
	token = token + "-" + idEnc
	return token
}

func GenerateRefreshToken(id string) string {
	uuidNew, _ := uuid.NewRandom()
	idEnc := base64.StdEncoding.EncodeToString([]byte(id))
	token := strings.Replace(uuidNew.String(), "-", "", -1)
	token = "fre-" + token + idEnc
	return token
}
