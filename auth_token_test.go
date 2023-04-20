package authtoken_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	authtoken "github.com/slzhffktm/go-auth-token"
	"github.com/stretchr/testify/assert"
)

type Data struct {
	Email string `json:"email"`
}

var data = Data{
	Email: "test@osterone.com",
}

func TestAuthToken_GenerateAndParseToken_SigningMethodHS256(t *testing.T) {
	authToken, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     []byte("steve-ao-key"),
		SigningMethod: authtoken.SigningMethodHS256,
	})
	assert.NoError(t, err)

	token, expiresAt, err := authToken.GenerateToken(data, time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	resData, err := authToken.ParseToken(token)
	assert.NoError(t, err)

	assert.Equal(t, data, *resData)
}

func TestAuthToken_GenerateAndParseToken_SigningMethodEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	authToken, err := authtoken.New[Data](authtoken.Options{
		SigningMethod: authtoken.SigningMethodEdDSA,
		PrivateKey:    priv,
		PublicKey:     pub,
	})
	assert.NoError(t, err)

	token, expiresAt, err := authToken.GenerateToken(data, time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	resData, err := authToken.ParseToken(token)
	assert.NoError(t, err)

	assert.Equal(t, data, *resData)
}

func TestAuthToken_GenerateAndParseToken_SigningMethodES384(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	authToken, err := authtoken.New[Data](authtoken.Options{
		SigningMethod: authtoken.SigningMethodES384,
		PrivateKey:    priv,
		PublicKey:     priv.Public(),
	})
	assert.NoError(t, err)

	token, expiresAt, err := authToken.GenerateToken(data, time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	resData, err := authToken.ParseToken(token)
	assert.NoError(t, err)

	assert.Equal(t, data, *resData)
}

func TestAuthToken_GenerateAndParseToken_SigningMethodRS512(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	authToken, err := authtoken.New[Data](authtoken.Options{
		SigningMethod: authtoken.SigningMethodRS512,
		PrivateKey:    priv,
		PublicKey:     priv.Public(),
	})
	assert.NoError(t, err)

	token, expiresAt, err := authToken.GenerateToken(data, time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	resData, err := authToken.ParseToken(token)
	assert.NoError(t, err)

	assert.Equal(t, data, *resData)
}

func TestNew_Failed(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	type testCase struct {
		name        string
		opts        authtoken.Options
		expectedErr error
	}
	tests := []testCase{
		{
			name: "empty SecretKey for symmetric SigningMethod.",
			opts: authtoken.Options{
				SigningMethod: authtoken.SigningMethodHS384,
			},
			expectedErr: errors.New("SecretKey is required for symmetric SigningMethod."),
		},
		{
			name: "empty PrivateKey for asymmetric SigningMethod",
			opts: authtoken.Options{
				SigningMethod: authtoken.SigningMethodES256,
				SecretKey:     []byte("test-key"),
				PrivateKey:    priv,
			},
			expectedErr: errors.New("PrivateKey and PublicKey are required for asymmetric SigningMethod."),
		},
		{
			name: "invalid key type for asymmetric SigningMethod",
			opts: authtoken.Options{
				SigningMethod: authtoken.SigningMethodEdDSA,
				PrivateKey:    priv,
				PublicKey:     priv.Public(),
			},
			expectedErr: authtoken.ErrInvalidKeyType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authtoken.New[Data](tt.opts)

			assert.Empty(t, got)
			assert.Error(t, err)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestAuthToken_ParseToken_InvalidTokenString(t *testing.T) {
	authToken, err := authtoken.New[Data](authtoken.Options{
		SigningMethod: authtoken.SigningMethodHS384,
		SecretKey:     []byte("key-stroke"),
	})
	assert.NoError(t, err)

	res, err := authToken.ParseToken("some-invalid-token")

	assert.Empty(t, res)
	assert.Error(t, err)
	assert.Equal(t, authtoken.ErrInvalidToken, err)
}

func TestAuthToken_ParseToken_ExpiredToken(t *testing.T) {
	authToken, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     []byte("ronan-key-ting"),
		SigningMethod: authtoken.SigningMethodHS256,
	})
	assert.NoError(t, err)

	token, expiresAt, err := authToken.GenerateToken(data, -time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	res, err := authToken.ParseToken(token)

	assert.Empty(t, res)
	assert.Error(t, err)
	assert.Equal(t, authtoken.ErrTokenExpired, err)
}

func TestAuthToken_ParseToken_InvalidSigningMethod(t *testing.T) {
	authTokenGen, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     []byte("ronan-key-ting"),
		SigningMethod: authtoken.SigningMethodHS256,
	})
	assert.NoError(t, err)

	token, expiresAt, err := authTokenGen.GenerateToken(data, -time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	authTokenParse, err := authtoken.New[Data](authtoken.Options{
		SigningMethod: authtoken.SigningMethodRS512,
		PrivateKey:    priv,
		PublicKey:     priv.Public(),
	})

	res, err := authTokenParse.ParseToken(token)

	assert.Empty(t, res)
	assert.Error(t, err)
	assert.Equal(t, authtoken.ErrInvalidToken, err)
}
