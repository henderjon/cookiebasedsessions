package cookiebasedsessions

import (
	"net/http"
	"time"

	"github.com/henderjon/durations"
)

// SessionHandler manages an http session cookie of a given name
type SessionHandler struct {
	name       string
	factory    CookieFactory
	serializer Serializer
}

// NewSessionHandler returns a session handler tied to a given name and equipped to sign the token and set the cookie
func NewSessionHandler(
	name string,
	factory CookieFactory,
	serializer Serializer,
) *SessionHandler {
	return &SessionHandler{
		name:       name,
		factory:    factory,
		serializer: serializer,
	}

}

// GetSession retrieves the named session from the http request
func (h *SessionHandler) GetSession(r *http.Request, checkOnly bool) (*Session, error) {
	var err error
	session := NewSession()
	cookie, err := h.factory.GetCookie(r, h.name)
	if err != nil && err == http.ErrNoCookie {
		return nil, err
	}

	err = h.serializer.Unserialize(cookie.Value, session)
	if err != nil || checkOnly {
		return nil, err
	}

	if session.VerifyExpiresAt(time.Now().UTC(), false) {
		session = NewSession()
	}

	// use the cookie expiration in our JWT
	session.TTL(durations.Minutes(h.factory.GetOpts().TTL))
	return session, nil
}

// SaveSession sets the named session in the http request
func (h *SessionHandler) SaveSession(w http.ResponseWriter, session *Session) error {
	token, err := h.serializer.Serialize(session)
	if err != nil {
		return err
	}

	c := h.factory.NewCookie(h.name, token)
	h.factory.SetCookie(w, c)
	return nil
}

// DeleteSession replaces the session with one that is expired and sets the cookie to expired
func (h *SessionHandler) DeleteSession(w http.ResponseWriter) error {
	s := NewSession()
	s.TTL(durations.Minutes(-30))
	token, err := h.serializer.Serialize(s)
	if err != nil {
		return err
	}

	c := h.factory.NewCookie(h.name, token)
	c = h.factory.ExpireCookie(c)
	h.factory.SetCookie(w, c)
	return nil
}
