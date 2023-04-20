package authtoken_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	secretKey := "steve-ao-key"

	authToken, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     []byte(secretKey),
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
