package cookiebasedsessions

import (
	"net/http"
	"strings"
)

// CookieParams represents the various bits of information that make up a cookie.
type CookieParams struct {
	Name     string
	Value    string
	TTL      int
	Path     string
	Domain   string
	IsSecure bool
	HTTPOnly bool
	SameSite http.SameSite
}

// Factory is a set of params used to create cookies.
type CookieFactory struct {
	Opts CookieParams
}

// NewCookieFactory creates a new Factory with the given options.
func NewCookieFactory(opts CookieParams) CookieFactory {
	return CookieFactory{
		Opts: opts,
	}
}

// CookieFactory is an interface for our Cookie Factory
type CookieMaker interface {
	GetCookie(r *http.Request, name string) (*http.Cookie, error)
	ExpireCookie(c *http.Cookie) *http.Cookie
	NewCookie(name, value string) *http.Cookie
	SetCookie(w http.ResponseWriter, c *http.Cookie)
	GetOpts() CookieParams
}

// GetOpts allows visibility to the underlying options of a Cookie.
func (f CookieFactory) GetOpts() CookieParams {
	return f.Opts
}

// GetCookie returns the http cookie of the given name.
func (f CookieFactory) GetCookie(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(name)
}

// ExpireCookie returns the http cookie having set it's expiration. This cookie must still be sent to the browser.
func (f CookieFactory) ExpireCookie(c *http.Cookie) *http.Cookie {
	c.MaxAge = -1
	// without "Expires" older browsers will assume a session cookie ... /shrug
	// Go's implementation:
	// MaxAge=0 means no 'Max-Age' attribute specified. (session cookie)
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0' (delete cookie)
	// MaxAge>0 means Max-Age attribute present and given in seconds (TTL in the future)
	return c
}

// NewCookie creates a cookie with the given name and value and CookieFactory's options.
func (f CookieFactory) NewCookie(name, value string) *http.Cookie {
	f.Opts.Name = name
	f.Opts.Value = value
	return NewCookie(f.Opts)
}

// SetCookie essentially "saves" the cookie by adding it to the request.
func (f CookieFactory) SetCookie(w http.ResponseWriter, c *http.Cookie) {
	http.SetCookie(w, c)
}

// NewCookie creates a new Cookie. Keep in mind that using a non-secure cookie will not overwrite a secure cookie
func NewCookie(opts CookieParams) *http.Cookie {
	return &http.Cookie{
		Name:   opts.Name,
		Value:  opts.Value,
		MaxAge: opts.TTL,
		Path:   opts.Path,
		Domain: opts.Domain,
		// @NOTE using a non-secure cookie will not overwrite a secure cookie
		Secure:   opts.IsSecure,
		HttpOnly: opts.HTTPOnly,
		SameSite: opts.SameSite,
	}
}

// NewSimpleCookie creates a secure, HTTP-only cookie for the TLD that expires in 30 min.
func NewSimpleCookie(name, value string) *http.Cookie {
	return NewCookie(CookieParams{
		Name:   name,
		Value:  value,
		TTL:    60 * 30, // 30 min.
		Path:   "/",
		Domain: "",
		// @NOTE using a non-secure cookie will not overwrite a secure cookie
		IsSecure: true,
		HTTPOnly: true,
	})
}

// CookieSameSite takes a string value and return an http.SameSite
func CookieSameSite(ss string) http.SameSite {
	ss = strings.ToLower(ss)
	switch ss {
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	}
	return http.SameSiteDefaultMode
}
