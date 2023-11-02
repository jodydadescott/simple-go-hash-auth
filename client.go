package auth

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"
)

type Client struct {
	randSeed *rand.Rand
	secret   string
}

func NewClient(config *Config) *Client {

	config = config.Clone()

	if config.Secret == "" {
		panic("Secret is required")
	}

	return &Client{
		secret:   config.Secret,
		randSeed: rand.New(rand.NewSource(time.Now().Unix())),
	}
}

func (t *Client) Update(auth *Auth) error {

	if auth == nil {
		return fmt.Errorf("auth is nil")
	}

	if auth.ServerNonce == "" {
		return fmt.Errorf("ServerNonce is empty")
	}

	b := make([]byte, 64)
	for i := range b {
		b[i] = NonceCharset[t.randSeed.Intn(len(NonceCharset))]
	}

	auth.ClientNonce = string(b)

	s := auth.ServerNonce + auth.ClientNonce + t.secret
	h := sha256.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)

	auth.Token = string(bs)

	return nil
}
