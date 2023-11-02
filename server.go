package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"go.uber.org/zap"
)

type authJar struct {
	auth *Auth
	exp  int64
	hash string
}

type Server struct {
	mutex    sync.RWMutex
	nonceMap map[string]*authJar
	cancel   context.CancelFunc
	ctx      context.Context
	ticker   *time.Ticker
	randSeed *rand.Rand
	secret   string
}

func NewServer(config *Config) *Server {

	if config.Secret == "" {
		panic("secret is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		nonceMap: make(map[string]*authJar),
		randSeed: rand.New(rand.NewSource(time.Now().Unix())),
		ctx:      ctx,
		cancel:   cancel,
		ticker:   time.NewTicker(CacheRefreshInterval),
		secret:   config.Secret,
	}

	go s.run()
	return s
}

func (t *Server) Shutdown() {
	t.cancel()
}

func (t *Server) NewAuth() *Auth {

	b := make([]byte, 64)
	for i := range b {
		b[i] = NonceCharset[t.randSeed.Intn(len(NonceCharset))]
	}

	jar := &authJar{
		auth: &Auth{
			ServerNonce: string(b),
		},
		exp: time.Now().Unix() + int64(NonceLifeTime.Seconds()),
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.nonceMap[jar.auth.ServerNonce] = jar
	return jar.auth.Clone()
}

func (t *Server) PutAuth(auth *Auth) error {

	if auth == nil {
		return fmt.Errorf("Auth is nil")
	}

	auth = auth.Clone()

	if auth.ServerNonce == "" {
		return fmt.Errorf("Auth is missing ServerNonce")
	}

	if auth.ClientNonce == "" {
		return fmt.Errorf(fmt.Sprintf("Auth %s ClientNonce is empty", auth.ServerNonce))
	}

	if auth.Token == "" {
		return fmt.Errorf(fmt.Sprintf("Auth %s Token is empty", auth.ServerNonce))
	}

	t.mutex.RLock()
	defer t.mutex.RUnlock()
	jar := t.nonceMap[auth.ServerNonce]

	if jar == nil {
		return fmt.Errorf("Auth %s not found", auth.ServerNonce)
	}

	if time.Now().Unix() > jar.exp {
		return fmt.Errorf("Auth %s expired", auth.ServerNonce)
	}

	s := jar.auth.ServerNonce + auth.ClientNonce + t.secret
	h := sha256.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)

	if string(bs) == auth.Token {
		jar.hash = auth.Token
		return nil
	}

	return fmt.Errorf("Auth %s failed hash", auth.ServerNonce)
}

func (t *Server) ValidateToken(token string) error {

	t.mutex.RLock()
	defer t.mutex.RUnlock()

	for _, jar := range t.nonceMap {
		if jar.hash == token {
			return authorized
		}
	}

	return unauthorized
}

func (t *Server) run() {

	cleanup := func() {

		zap.L().Debug("Running cleanup")

		var removes []string
		t.mutex.Lock()
		defer t.mutex.Unlock()

		for key, e := range t.nonceMap {
			if time.Now().Unix() > e.exp {
				removes = append(removes, key)
				zap.L().Debug(fmt.Sprintf("Ejecting %s", key))
			}
		}

		if len(removes) > 0 {
			for _, key := range removes {
				delete(t.nonceMap, key)
			}
		}

		zap.L().Debug("Completed cleanup")

	}

	for {
		select {

		case <-t.ctx.Done():
			zap.L().Debug("Shutting down")
			t.ticker.Stop()
			return

		case <-t.ticker.C:
			cleanup()

		}
	}

}
