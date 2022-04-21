package cookiebasedsessions

import (
	"fmt"

	jwt "github.com/golang-jwt/jwt/v4"
)

// RegisteredClaims is an alias that avoids asking implimntors to import the parent JWT lib.
type RegisteredClaims = jwt.RegisteredClaims

// Claims is an alias that avoids asking implimntors to import the parent JWT lib.
type Claims = jwt.Claims

// NumericDate is an alias that avoids asking implimntors to import the parent JWT lib.
type NumericDate = jwt.NumericDate

// NewNumericDate is an alias that avoids asking implimntors to import the parent JWT lib.
var NewNumericDate = jwt.NewNumericDate

// Serializer is some API sugar to simplify making and reading JWTs.
type Serializer interface {
	Serialize(claims Claims) (string, error)
	Unserialize(jwt string, dest Claims) error
}

// TokenSigner combines signing and serializing a JWT by holding the signing method and implementing the Serializer interface.
type TokenSigner struct {
	Method jwt.SigningMethod
	Key    interface{}
}

// Serialize takes a set of Claims and returns a signed & encoded JWT.
func (s *TokenSigner) Serialize(claims Claims) (string, error) {
	token := jwt.NewWithClaims(s.Method, claims)

	// Sign and get the complete encoded token as a string using the Key
	return token.SignedString(s.Key)
}

// Unserialize takes a signed & encoded JWT and sets the claims within the destination.
func (s *TokenSigner) Unserialize(json string, dest Claims) error {
	token, err := jwt.ParseWithClaims(json, dest, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := s.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.Key, nil
	}, jwt.WithValidMethods([]string{s.Method.Alg()}))

	if !token.Valid {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return fmt.Errorf("invalid jwt; malformed; %w", err)
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				return fmt.Errorf("invalid jwt; expired/inactive; %w", err)
			} else {
				return fmt.Errorf("invalid jwt; %w", err)
			}
		}
	}

	if err != nil {
		return err
	}

	return nil
}
