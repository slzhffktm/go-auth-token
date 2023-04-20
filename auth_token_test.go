package authtoken_test

import (
	"testing"
	"time"

	authtoken "github.com/slzhffktm/go-auth-token"
	"github.com/stretchr/testify/assert"
)

type Data struct {
	Email string `json:"email"`
}

var secretKey = "secretKey"

func TestAuthToken_GenerateAndParseToken_SigningMethodHS(t *testing.T) {
	authToken, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     secretKey,
		SigningMethod: authtoken.SigningMethodHS256,
	})

	data := Data{
		Email: "test@osterone.com",
	}

	token, expiresAt, err := authToken.GenerateToken(data, time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	resData, err := authToken.ParseToken(token)
	assert.NoError(t, err)

	assert.Equal(t, data, *resData)
}

func TestAuthToken_GenerateAndParseToken_SigningMethodHS(t *testing.T) {
	authToken, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     secretKey,
		SigningMethod: authtoken.SigningMethodHS256,
	})

	data := Data{
		Email: "test@osterone.com",
	}

	token, expiresAt, err := authToken.GenerateToken(data, time.Minute*5)
	assert.NoError(t, err)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, expiresAt)

	resData, err := authToken.ParseToken(token)
	assert.NoError(t, err)

	assert.Equal(t, data, *resData)
}
