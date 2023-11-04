package server

import (
	"fmt"
	"time"

	"github.com/jodydadescott/simple-go-hash-auth/nonce"
	"github.com/jodydadescott/simple-go-hash-auth/token"
	"github.com/jodydadescott/simple-go-hash-auth/types"
)

type AuthRequest = types.AuthRequest
type Token = types.Token

type Server struct {
	secret      string
	nonceServer *nonce.Server
	tokenServer *token.Server
}

type Config struct {
	Secret               string
	NonceLife            time.Duration
	CacheRefreshInterval time.Duration
}

func NewServer(config *Config) *Server {

	if config == nil {
		panic("config is nil")
	}

	if config.Secret == "" {
		panic("secret is required")
	}

	s := &Server{
		secret:      config.Secret,
		nonceServer: nonce.New(&nonce.Config{}),
		tokenServer: token.New(&token.Config{}),
	}

	return s
}

func (t *Server) Shutdown() {
	t.nonceServer.Shutdown()
	t.tokenServer.Shutdown()
}

func (t *Server) NewRequest() *AuthRequest {
	return &AuthRequest{
		ServerNonce: t.nonceServer.New(),
	}
}

func (t *Server) GetTokenFromRequest(request *AuthRequest) (*Token, error) {

	if request == nil {
		return nil, fmt.Errorf("Auth is nil")
	}

	request = request.Clone()

	if request.ServerNonce == "" {
		return nil, fmt.Errorf("Request is missing ServerNonce")
	}

	if request.ClientNonce == "" {
		return nil, fmt.Errorf(fmt.Sprintf("Request %s ClientNonce is empty", request.ServerNonce))
	}

	if request.Hash == "" {
		return nil, fmt.Errorf(fmt.Sprintf("Request %s Hash is empty", request.ServerNonce))
	}

	if !t.nonceServer.Check(request.ServerNonce) {
		return nil, fmt.Errorf(fmt.Sprintf("Request %s ServerNonce not found", request.ServerNonce))
	}

	if request.Hash != request.GetHashFromSecret(t.secret) {
		return nil, fmt.Errorf("Request %s failed hash", request.ServerNonce)
	}

	return t.tokenServer.NewToken(), nil
}

func (t *Server) ValidateToken(key string) error {

	if t.tokenServer.GetToken(key) == nil {
		return types.AuthErrorUnAuthorized
	}

	return nil
}
