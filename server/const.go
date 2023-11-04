package server

import "time"

const (
	nonceCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	cacheRefreshInterval = time.Duration(120) * time.Second

	defaultTokenLife int64 = 60
)
