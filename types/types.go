package types

import (
	"crypto/sha256"

	"github.com/jinzhu/copier"
)

type AuthRequest struct {
	ServerNonce string `json:"serverNonce,omitempty" yaml:"serverNonce,omitempty"`
	ClientNonce string `json:"clientNonce,omitempty" yaml:"clientNonce,omitempty"`
	Hash        string `json:"hash,omitempty" yaml:"hash,omitempty"`
}

// Clone return copy
func (t *AuthRequest) Clone() *AuthRequest {
	c := &AuthRequest{}
	copier.Copy(&c, &t)
	return c
}

// Clone return copy
func (t *AuthRequest) GetHashFromSecret(secret string) string {

	if t.ServerNonce == "" {
		return ""
	}

	if t.ClientNonce == "" {
		return ""
	}

	if secret == "" {
		return ""
	}

	s := t.ServerNonce + t.ClientNonce + secret
	h := sha256.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return string(bs)
}

type Token struct {
	Token string `json:"token,omitempty" yaml:"token,omitempty"`
	Exp   int64  `json:"exp,omitempty" yaml:"exp,omitempty"`
}

// Clone return copy
func (t *Token) Clone() *Token {
	c := &Token{}
	copier.Copy(&c, &t)
	return c
}

var (
	AuthErrorUnAuthorized = &AuthError{
		message: "Unauthorized",
	}
)

type AuthError struct {
	message string
}

func (t *AuthError) Error() string {
	return t.message
}
