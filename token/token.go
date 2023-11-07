package token

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/jodydadescott/simple-go-hash-auth/rand"
	"github.com/jodydadescott/simple-go-hash-auth/types"
)

type Token = types.Token

type Server struct {
	mutex                sync.RWMutex
	xmap                 map[string]*Token
	cancel               context.CancelFunc
	ctx                  context.Context
	ticker               *time.Ticker
	tokenLife            time.Duration
	cacheRefreshInterval time.Duration
	rand                 *rand.Rand
}

type Config struct {
	TokenLife            time.Duration `json:"tokenLife,omitempty" yaml:"tokenLife,omitempty"`
	TokenSize            int           `json:"tokenSize,omitempty" yaml:"tokenSize,omitempty"`
	CacheRefreshInterval time.Duration `json:"cacheRefreshInterval,omitempty" yaml:"cacheRefreshInterval,omitempty"`
}

func New(config *Config) *Server {

	if config == nil {
		panic("config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	tokenLife := defaultTokenLife
	if config.TokenLife > 0 {
		tokenLife = config.TokenLife
		zap.L().Debug(fmt.Sprintf("Using default TokenLife seconds %f", tokenLife.Seconds()))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config TokenLife seconds %f", tokenLife.Seconds()))
	}

	cacheRefreshInterval := defaultCacheRefreshInterval
	if config.CacheRefreshInterval > 0 {
		cacheRefreshInterval = config.CacheRefreshInterval
		zap.L().Debug(fmt.Sprintf("Using default CacheRefreshInterval seconds %f", cacheRefreshInterval.Seconds()))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config CacheRefreshInterval seconds %f", cacheRefreshInterval.Seconds()))
	}

	tokenSize := defaultTokenSize
	if config.TokenSize > 0 {
		tokenSize = config.TokenSize
		zap.L().Debug(fmt.Sprintf("Using default TokenSize of %d", tokenSize))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config TokenSize of %d", tokenSize))
	}

	s := &Server{
		xmap:                 make(map[string]*Token),
		ctx:                  ctx,
		cancel:               cancel,
		ticker:               time.NewTicker(cacheRefreshInterval),
		tokenLife:            tokenLife,
		cacheRefreshInterval: cacheRefreshInterval,
		rand:                 rand.New(&rand.Config{Size: tokenSize}),
	}

	go s.run()
	return s
}

func (t *Server) Shutdown() {
	t.cancel()
}

func (t *Server) GetToken(key string) *Token {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	token := t.xmap[key]
	if token == nil {
		zap.L().Debug(fmt.Sprintf("Token %s not found", key))
		return nil
	}

	if isExpired(time.Now().Unix(), token.Exp) {
		zap.L().Debug(fmt.Sprintf("Token %s was found but it is expired", key))
		return nil
	}

	return token.Clone()
}

func (t *Server) NewToken() *Token {

	token := &Token{
		Exp:   time.Now().Unix() + int64(t.tokenLife.Seconds()),
		Token: t.rand.String(),
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.xmap[token.Token] = token
	return token.Clone()
}

func (t *Server) run() {

	getExpired := func() []string {

		var expired []string
		t.mutex.RLock()
		defer t.mutex.RUnlock()

		now := time.Now().Unix()

		for key, token := range t.xmap {
			if isExpired(now, token.Exp) {
				expired = append(expired, key)
			}
		}

		return expired
	}

	ejectExpired := func(expired []string) {

		t.mutex.Lock()
		defer t.mutex.Unlock()

		for _, key := range expired {
			zap.L().Debug(fmt.Sprintf("Ejecting expired %s", key))
			delete(t.xmap, key)
		}

	}

	cleanup := func() {

		zap.L().Debug("Running cleanup")

		expired := getExpired()

		if len(expired) > 0 {
			ejectExpired(expired)
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

func isExpired(now, exp int64) bool {
	if now > exp {
		return true
	}
	return false
}
