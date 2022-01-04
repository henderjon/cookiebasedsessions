package cookiebasedsessions

import (
	jwt "github.com/golang-jwt/jwt/v4"
)

// These represent the method of signing the JWT.
const (
	HS256 = iota
	HS384
	HS512
	ES256
	ES384
	ES512
	EdDSA
	RS256
	RS384
	RS512
	PS256
	PS384
	PS512
)

// NewSigner returns a TokenSigner assigned the given method
func NewSigner(m int, key interface{}) *TokenSigner {
	var method jwt.SigningMethod
	switch true {
	default:
		fallthrough
	case m == HS256:
		method = jwt.SigningMethodHS256
	case m == HS384:
		method = jwt.SigningMethodHS384
	case m == HS512:
		method = jwt.SigningMethodHS512
	case m == ES256:
		method = jwt.SigningMethodES256
	case m == ES384:
		method = jwt.SigningMethodES384
	case m == ES512:
		method = jwt.SigningMethodES512
	case m == EdDSA:
		method = jwt.SigningMethodEdDSA
	case m == RS256:
		method = jwt.SigningMethodRS256
	case m == RS384:
		method = jwt.SigningMethodRS384
	case m == RS512:
		method = jwt.SigningMethodRS512
	case m == PS256:
		method = jwt.SigningMethodPS256
	case m == PS384:
		method = jwt.SigningMethodPS384
	case m == PS512:
		method = jwt.SigningMethodPS512
	}

	return &TokenSigner{
		Method: method,
		Key:    key,
	}
}
