package authtoken

import "github.com/golang-jwt/jwt/v5"

// SigningMethod is the alias for the jwt.SigningMethod.
type SigningMethod jwt.SigningMethod

var (
	SigningMethodHS256 SigningMethod = jwt.SigningMethodHS256
	SigningMethodHS384 SigningMethod = jwt.SigningMethodHS384
	SigningMethodHS512 SigningMethod = jwt.SigningMethodHS512

	SigningMethodES256 SigningMethod = jwt.SigningMethodES256
	SigningMethodES384 SigningMethod = jwt.SigningMethodES384
	SigningMethodES512 SigningMethod = jwt.SigningMethodES512
	SigningMethodEdDSA SigningMethod = jwt.SigningMethodEdDSA
	SigningMethodRS256 SigningMethod = jwt.SigningMethodRS256
	SigningMethodRS384 SigningMethod = jwt.SigningMethodRS384
	SigningMethodRS512 SigningMethod = jwt.SigningMethodRS512
)

func isSigningMethodSymmetric(s SigningMethod) bool {
	switch s {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		return true
	default:
		return false
	}
}
