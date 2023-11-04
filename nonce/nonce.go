package nonce

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/jodydadescott/simple-go-hash-auth/rand"
)

type Server struct {
	mutex                sync.RWMutex
	xmap                 map[string]int64
	cancel               context.CancelFunc
	ctx                  context.Context
	ticker               *time.Ticker
	rand                 *rand.Rand
	nonceLife            time.Duration
	cacheRefreshInterval time.Duration
}

type Config struct {
	NonceLife            time.Duration
	NonceSize            int
	CacheRefreshInterval time.Duration
}

func New(config *Config) *Server {

	if config == nil {
		panic("config is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	nonceLife := defaultNonceLife
	if config.NonceLife > 0 {
		nonceLife = config.NonceLife
		zap.L().Debug(fmt.Sprintf("Using default NonceLife seconds %f", nonceLife.Seconds()))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config NonceLife seconds %f", nonceLife.Seconds()))
	}

	cacheRefreshInterval := defaultCacheRefreshInterval
	if config.CacheRefreshInterval > 0 {
		cacheRefreshInterval = config.CacheRefreshInterval
		zap.L().Debug(fmt.Sprintf("Using default CacheRefreshInterval seconds %f", cacheRefreshInterval.Seconds()))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config CacheRefreshInterval seconds %f", cacheRefreshInterval.Seconds()))
	}

	nonceSize := defaultNonceSize
	if config.NonceSize > 0 {
		nonceSize = config.NonceSize
		zap.L().Debug(fmt.Sprintf("Using default NonceSize of %d", nonceSize))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config NonceSize of %d", nonceSize))
	}

	s := &Server{
		xmap:                 make(map[string]int64),
		rand:                 rand.New(&rand.Config{Size: nonceSize}),
		ctx:                  ctx,
		cancel:               cancel,
		ticker:               time.NewTicker(cacheRefreshInterval),
		nonceLife:            nonceLife,
		cacheRefreshInterval: cacheRefreshInterval,
	}

	go s.run()
	return s
}

func (t *Server) Shutdown() {
	t.cancel()
}

func (t *Server) New() string {

	key := t.rand.String()

	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.xmap[key] = time.Now().Unix() + int64(t.nonceLife.Seconds())
	return key
}

func (t *Server) Check(key string) bool {

	t.mutex.Lock()
	defer t.mutex.Unlock()

	exp := t.xmap[key]

	if exp <= 0 {
		zap.L().Debug(fmt.Sprintf("Key does not exist %s", key))
		return false
	}

	if isExpired(time.Now().Unix(), exp) {
		zap.L().Debug(fmt.Sprintf("Key exist but is expired %s", key))
		return false
	}

	zap.L().Debug(fmt.Sprintf("Key exist and is not expired %s", key))
	return true
}

func (t *Server) run() {

	getExpired := func() []string {

		var expired []string
		t.mutex.RLock()
		defer t.mutex.RUnlock()

		now := time.Now().Unix()

		for key, exp := range t.xmap {
			if isExpired(now, exp) {
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
