package auth

import "github.com/jinzhu/copier"

type Auth struct {
	ServerNonce string `json:"serverNonce,omitempty" yaml:"serverNonce,omitempty"`
	ClientNonce string `json:"clientNonce,omitempty" yaml:"clientNonce,omitempty"`
	Token       string `json:"token,omitempty" yaml:"token,omitempty"`
}

type Config struct {
	Secret string
}

// Clone return copy
func (t *Config) Clone() *Config {
	c := &Config{}
	copier.Copy(&c, &t)
	return c
}

// Clone return copy
func (t *Auth) Clone() *Auth {
	c := &Auth{}
	copier.Copy(&c, &t)
	return c
}

var (
	unauthorized = &AuthError{
		message: "Unauthorized",
	}
	authorized = &AuthError{
		message: "Authorized",
	}
)

type AuthError struct {
	message string
}

func (t *AuthError) Error() string {
	return t.message
}
