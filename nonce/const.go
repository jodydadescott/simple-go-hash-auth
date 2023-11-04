package nonce

import "time"

const (
	nonceCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	defaultCacheRefreshInterval = time.Duration(120) * time.Second
	defaultNonceLife            = time.Duration(30) * time.Second
	defaultNonceSize            = 64
)
