package authtoken

import "errors"

var (
	ErrInvalidKeyType       = errors.New("invalid key type")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrInvalidToken         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token is expired")
)
