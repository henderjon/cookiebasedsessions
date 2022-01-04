package cookiebasedsessions

import (
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/henderjon/oid"
)

// Session wraps the set of claims in a couple of sugary methods
type Session struct {
	RegisteredClaims
}

// TTL is sugar for pushing the expiration date ahead by the given duration
func (s *Session) TTL(t time.Duration) {
	s.ExpiresAt = jwt.NewNumericDate(time.Now().Add(t).UTC())
}

// Active checks to see if the claims' `nbf` field is less than the given time
func (s *Session) Active(now time.Time) bool {
	return s.NotBefore.Before(now.UTC())
	// return s.VerifyNotBefore(time.Now().UTC().Unix(), true)
}

// IsExpired checks to see if the claims' `exp` field is less than the given time
func (s *Session) IsExpired(now time.Time) bool {
	return s.ExpiresAt.Before(now.UTC())
	// return s.VerifyExpiresAt(time.Now().UTC().Unix(), true)
}

// IsValid implements Claimer and validates the current claim `NotActive` & `IsExpired` against time.Now()
func (s *Session) IsValid() bool {
	t := time.Now().UTC()
	return s.Active(t) && !s.IsExpired(t)
}

// NewSession creates a new local session JWT
func NewSession() *Session {
	return &Session{
		RegisteredClaims: RegisteredClaims{
			ID:       oid.UID(),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
}
