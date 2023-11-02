package auth

import "time"

const (
	NonceCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	CacheRefreshInterval = time.Duration(120) * time.Second

	NonceLifeTime = time.Duration(300) * time.Second
)
