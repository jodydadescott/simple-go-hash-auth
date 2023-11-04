package token

import "time"

const (
	defaultCacheRefreshInterval = time.Duration(120) * time.Second
	defaultTokenLife            = time.Duration(30) * time.Second
	defaultTokenSize            = 128
)
