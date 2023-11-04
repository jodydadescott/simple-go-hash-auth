package rand

import (
	"fmt"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

type Rand struct {
	randSeed *rand.Rand
	size     int
}

type Config struct {
	Size int
}

func New(config *Config) *Rand {

	if config == nil {
		panic("config is nil")
	}

	size := defaultSize
	if config.Size > 0 {
		size = config.Size
		zap.L().Debug(fmt.Sprintf("Using default size %d", size))
	} else {
		zap.L().Debug(fmt.Sprintf("Using config size %d", size))
	}

	return &Rand{
		randSeed: rand.New(rand.NewSource(time.Now().UnixNano())),
		size:     size,
	}
}

func (t *Rand) String() string {
	b := make([]byte, t.size)
	for i := range b {
		b[i] = nonceCharset[t.randSeed.Intn(len(nonceCharset))]
	}
	return string(b)
}
