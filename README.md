# Go Auth Token

Golang library to generate auth token in JWT-formatted (Bearer) authentication token.
This library is using https://github.com/golang-jwt/jwt.

## Goal

The aim of this project is to simplify the generation and parsing of JWT tokens.

## Usage

```go
package main

import (
	"fmt"
	"time"

	authtoken "github.com/slzhffktm/go-auth-token"
)

type Data struct {
	Email string `json:"email"`
}

func main() {
	// For symmetric SigningMethod.
	authToken, err := authtoken.New[Data](authtoken.Options{
		SecretKey:     []byte("steve-ao-key"),
		SigningMethod: authtoken.SigningMethodHS256,
	})

	// Generate token which contains the data.
	token, expiresAt, err := authToken.GenerateToken(Data{
		Email: "test@oster.one",
	}, time.Minute*5)
	if err != nil {
		// do something with error
	}

	fmt.Printf("Token: %s, will expire at: %s\n", token, expiresAt)

	// Parse the token.
	resData, err := authToken.ParseToken(token)
	if err != nil {
		// do something with error
	}

	fmt.Printf("Email: %s\n", resData.Email)
	// Output: Email: test@oster.one
}
```

For asymmetric SigningMethod, you need to provide PrivateKey and PublicKey instead of SecretKey.

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	
	authtoken "github.com/slzhffktm/go-auth-token"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		// do something with error
    }

	authToken, err := authtoken.New[Data](authtoken.Options{
		SigningMethod: authtoken.SigningMethodEdDSA,
		PrivateKey:    priv,
		PublicKey:     pub,
	})
	
	// Usage is the same as the symmetric SigningMethod.
}
```

## Contributing

Thank you for your interest in contributing to our project! 
We welcome contributions of all kinds, including bug reports, security issue, 
feature suggestions, documentation improvements, and code contributions.

### How to contribute

Feel free to contribute to this project by opening an issue or a pull request.

## Contact

If you have any questions or concerns about contributing to our project, please reach out to us by email or on GitHub. We appreciate your interest and look forward to working with you!