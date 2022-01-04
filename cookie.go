package cookiebasedsessions

import (
	"net/http"
)

const (
	// SameSiteStrict only sends cookies with requests from the exact URL
	SameSiteStrict = iota
	// SameSiteLax also sends cookies with user nav requests from the other URLs; default if not specified
	SameSiteLax
	// SameSiteNone sends cookies; requires secure
	SameSiteNone
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
	SameSite int
}

// Factory is a set of params used to create cookies.
type Factory struct {
	Opts CookieParams
}

// NewCookieFactory creates a new Factory with the given options.
func NewCookieFactory(opts CookieParams) Factory {
	return Factory{
		Opts: opts,
	}
}

// CookieFactory is an interface for our Cookie Factory
type CookieFactory interface {
	GetCookie(r *http.Request, name string) (*http.Cookie, error)
	ExpireCookie(c *http.Cookie) *http.Cookie
	NewCookie(name, value string) *http.Cookie
	SetCookie(w http.ResponseWriter, c *http.Cookie)
	GetOpts() CookieParams
}

// GetOpts allows visibility to the underlying options of a Cookie.
func (f Factory) GetOpts() CookieParams {
	return f.Opts
}

// GetCookie returns the http cookie of the given name.
func (f Factory) GetCookie(r *http.Request, name string) (*http.Cookie, error) {
	return r.Cookie(name)
}

// ExpireCookie returns the http cookie having set it's expiration. This cookie must still be sent to the browser.
func (f Factory) ExpireCookie(c *http.Cookie) *http.Cookie {
	c.MaxAge = -1
	// without "Expires" older browsers will assume a session cookie ... /shrug
	// Go's implementation:
	// MaxAge=0 means no 'Max-Age' attribute specified. (session cookie)
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0' (delete cookie)
	// MaxAge>0 means Max-Age attribute present and given in seconds (TTL in the future)
	return c
}

// NewCookie creates a cookie with the given name and value and Factory's options.
func (f Factory) NewCookie(name, value string) *http.Cookie {
	f.Opts.Name = name
	f.Opts.Value = value
	return NewCookie(f.Opts)
}

// SetCookie essentially "saves" the cookie by adding it to the request.
func (f Factory) SetCookie(w http.ResponseWriter, c *http.Cookie) {
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
		SameSite: setSameSite(opts.SameSite),
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

// setSameSite translates an int to a samesite setting.
func setSameSite(ss int) http.SameSite {
	switch ss {
	case SameSiteNone:
		return http.SameSiteNoneMode
	case SameSiteLax:
		return http.SameSiteLaxMode
	case SameSiteStrict:
		return http.SameSiteStrictMode
	}
	return http.SameSiteDefaultMode
}