package authtoken

import "errors"

var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrInvalidKeyType       = errors.New("invalid key type")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
)
