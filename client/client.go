package client

import (
	"fmt"

	"github.com/jodydadescott/simple-go-hash-auth/rand"
	"github.com/jodydadescott/simple-go-hash-auth/types"
)

type AuthRequest = types.AuthRequest
type Token = types.Token

type Client struct {
	secret string
	rand   *rand.Rand
	token  *Token
}

type Config struct {
	Secret string
}

func New(config *Config) *Client {

	if config.Secret == "" {
		panic("secret is empty")
	}

	return &Client{
		secret: config.Secret,
		rand:   rand.New(&rand.Config{}),
	}
}

func (t *Client) ProcessRequest(request *AuthRequest) error {

	if request == nil {
		return fmt.Errorf("request is nil")
	}

	if request.ServerNonce == "" {
		return fmt.Errorf("ServerNonce is empty")
	}

	if request.ClientNonce == "" {
		request.ClientNonce = t.rand.String()
	}

	hash := request.GetHashFromSecret(t.secret)
	request.Hash = hash

	return nil
}
