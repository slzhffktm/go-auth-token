package authtoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Options is list of options for the AuthToken.
type Options struct {
	// SigningMethod is the signing method for the jwt token.
	// SigningMethodHS*** is symmetric, while the rest are asymmetric.
	SigningMethod SigningMethod

	// SecretKey is required for symmetric SigningMethod.
	SecretKey string

	// PrivateKey is required for asymmetric SigningMethod.
	PrivateKey any
	// PublicKey is required for asymmetric SigningMethod.
	PublicKey any
}

type AuthToken[T any] struct {
	opts Options
}

// New generates a new AuthToken instance.
// T is the data type that wants to be inserted into the token.
func New[T any](opts Options) (*AuthToken[T], error) {
	if isSigningMethodSymmetric(opts.SigningMethod) {
		if opts.SecretKey == "" {
			return nil, errors.New("SecretKey is required for symmetric SigningMethod.")
		}
	} else {
		if opts.PrivateKey == "" || opts.PublicKey == "" {
			return nil, errors.New("PrivateKey and PublicKey is required for asymmetric SigningMethod.")
		}

		if err := validatePrivatePublicKey(opts); err != nil {
			return nil, err
		}
	}

	return &AuthToken[T]{
		opts: opts,
	}, nil
}

func validatePrivatePublicKey(opts Options) error {
	switch opts.SigningMethod {
	case SigningMethodEdDSA:
		_, ok := opts.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return ErrInvalidKeyType
		}
		_, ok = opts.PublicKey.(ed25519.PublicKey)
		if !ok {
			return ErrInvalidKeyType
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		_, ok := opts.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return ErrInvalidKeyType
		}
		_, ok = opts.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrInvalidKeyType
		}
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		_, ok := opts.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return ErrInvalidKeyType
		}
		_, ok = opts.PublicKey.(*rsa.PublicKey)
		if !ok {
			return ErrInvalidKeyType
		}
	}
	
	return ErrInvalidSigningMethod
}

// GenerateToken generates a token with its expiry date.
// data in the param is the data that we want to store in the token.
func (a AuthToken[T]) GenerateToken(
	data T,
	expiresIn time.Duration,
) (token string, expiresAt time.Time, err error) {
	expiresAt = time.Now().Add(expiresIn).UTC()

	unsigned := jwt.NewWithClaims(a.opts.SigningMethod, struct {
		Data T `json:"data"`
		jwt.RegisteredClaims
	}{
		data,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	tokenString, err := unsigned.SignedString([]byte(a.opts.SecretKey))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token.SignedString: %w", err)
	}

	return tokenString, expiresAt, nil
}

// ParseToken parses a token and return its data.
func (a AuthToken[T]) ParseToken(
	token string,
) (data *T, err error) {
	claims := &struct {
		Data T `json:"data"`
		jwt.RegisteredClaims
	}{}

	jwtTokenObj, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if token.Method != a.opts.SigningMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.opts.SecretKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseWithClaims: %w", err)
	}
	if !jwtTokenObj.Valid {
		return nil, ErrInvalidToken
	}

	return &claims.Data, nil
}
