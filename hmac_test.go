package cookiebasedsessions

import (
	"os"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
)

type hsClaims struct {
	Name  string `json:"nam,omitempty"`
	Email string `json:"eml,omitempty"`
	RegisteredClaims
}

func newHsClaims(t *testing.T) *hsClaims {
	secret := os.Getenv("TESTSALT")
	if len(secret) == 0 {
		t.Fatal("undefined NEV VAR: TESTSALT")
	}

	return &hsClaims{
		RegisteredClaims: RegisteredClaims{
			Subject:   "a new jam",
			ExpiresAt: jwt.NewNumericDate(time.Unix(1653073538, 0)),
			ID:        "7e3f16d2-b0d8-4248-85cb-db7856d4bfc4",
		},
		Name:  "John Paul Jones",
		Email: "jpj@ledzep.com",
	}
}

func TestSerializeSignHS256(t *testing.T) {
	payload := newHsClaims(t)
	signer := NewSigner(HS256, []byte(os.Getenv("TESTSALT")))

	token, err := signer.Serialize(payload)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.NHkKE4PVSz_B6OM1m5qR-mDBQlWIr_JB_0nMyXOjPbw`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestUnserializeSignHS256(t *testing.T) {
	payload := newHsClaims(t)
	signer := NewSigner(HS256, []byte(os.Getenv("TESTSALT")))

	token, err := signer.Serialize(payload)
	if err != nil {
		t.Error(err)
	}

	m := &hsClaims{}
	if e := signer.Unserialize(token, m); e != nil {
		t.Errorf("unserialize error:\n%s", e)
	}

	if err = m.Valid(); err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(m, payload); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestSerializeHS384(t *testing.T) {
	payload := newHsClaims(t)
	signer := NewSigner(HS384, []byte(os.Getenv("TESTSALT")))

	token, err := signer.Serialize(payload)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.azHKQJ9Jkm28Kta5QwdNhQfq-9lTZyJyf-NIu2Vyd-Elr6HhHXSM--HeHbxjLCps`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s\n%s", err, diff)
	}
}

func TestUnserializeHS384(t *testing.T) {
	payload := newHsClaims(t)
	signer := NewSigner(HS384, []byte(os.Getenv("TESTSALT")))

	token, err := signer.Serialize(payload)
	if err != nil {
		t.Error(err)
	}

	m := &hsClaims{}
	if e := signer.Unserialize(token, m); e != nil {
		t.Errorf("unserialize error:\n%s", e)
	}

	if err = m.Valid(); err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(m, payload); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestSerializeHS512(t *testing.T) {
	payload := newHsClaims(t)
	signer := NewSigner(HS512, []byte(os.Getenv("TESTSALT")))

	token, err := signer.Serialize(payload)
	if err != nil {
		t.Error(err)
	}

	expected := `eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW0iOiJKb2huIFBhdWwgSm9uZXMiLCJlbWwiOiJqcGpAbGVkemVwLmNvbSIsInN1YiI6ImEgbmV3IGphbSIsImV4cCI6MTY1MzA3MzUzOCwianRpIjoiN2UzZjE2ZDItYjBkOC00MjQ4LTg1Y2ItZGI3ODU2ZDRiZmM0In0.5DbwS0RXRaR73xntE3cGDbl7rrUAqAZ4V4FSoK_zET4ZRZPTTXimdsntS2WXDtRkKhjlSqFSfVewCK4rYU6VzA`
	if diff := cmp.Diff(token, expected); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

func TestUnserializeHS512(t *testing.T) {
	payload := newHsClaims(t)
	signer := NewSigner(HS512, []byte(os.Getenv("TESTSALT")))

	token, err := signer.Serialize(payload)
	if err != nil {
		t.Error(err)
	}

	m := &hsClaims{}
	if e := signer.Unserialize(token, m); e != nil {
		t.Errorf("unserialize error:\n%s", e)
	}

	if err = m.Valid(); err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(m, payload); diff != "" {
		t.Errorf("serialize error: (-got +want)\n%s", diff)
	}
}

type myonClaims struct {
	RegisteredClaims
	UserID      int      `json:"uid,omitempty"`
	UserRoleID  int      `json:"urid,omitempty"`
	UserGradeID int      `json:"ugid,omitempty"`
	AccountID   int      `json:"aid,omitempty"`
	BuildingID  int      `json:"bid,omitempty"`
	Permissions []int    `json:"perms,omitempty"`
	Lang        []string `json:"lng,omitempty"`
	LoggedIn    bool     `json:"loggedIn,omitempty"`
}

func TestHS256Verify(t *testing.T) {
	payload := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL3d3dy5teW9uLmNvbSIsImlzcyI6Imh0dHBzOi8vd3d3Lm15b24uY29tIiwianRpIjoiZTA5YWIwOGYtMmRmYS00ZTQxLTljOGItZWViZGYwOGJlZjBjIiwiaWF0IjoxNTYyNjc4MDQzLCJleHAiOjE5NjI2NzkzNjMsInVpZCI6MjA1MDg0MCwidXJpZCI6MiwidWdpZCI6OCwiYWlkIjo0MDU2NzUsImJpZCI6NDA1Njc2LCJwZXJtcyI6WzEsMiw0LDUsNiw4LDE5LDMxLDc0LDEzMiwxMzcsMTM4LDE0MywxNDcsMTY1LDE2NiwxNzYsMTc4LDE3OV0sImxuZyI6WyJlbl91cyJdLCJsb2dnZWRJbiI6dHJ1ZX0.hUJFvBV3WmKDDm4e9OVLXeRBt1c55I979Um7oMWY1QM`
	signer := NewSigner(HS256, []byte(os.Getenv("TESTSALT")))

	m := &myonClaims{}
	err := signer.Unserialize(payload, m)
	if err != nil {
		t.Error(err)
	}
}

func Test_myON(t *testing.T) {
	// payload := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL3d3dy5teW9uLmNvbSIsImlzcyI6Imh0dHBzOi8vd3d3Lm15b24uY29tIiwianRpIjoiMDM5ZDhiN2YtNzdiZS00NmE1LWIwN2UtOWViZGM1ZTg3ZWI5IiwiaWF0IjoxNjQwMjc0NDMyLjkzNzg1MywiZXhwIjoxOTQwMjc1NzUyLjkzNzg1NSwidWlkIjoyMDUwODQ1LCJ1cmlkIjoyLCJ1Z2lkIjo4LCJhaWQiOjQwNTY3NSwiYmlkIjo0MDU2NzYsImxtdGgiOiJsb2NhbGN2IiwicGVybXMiOlsxLDIsNCw1LDYsNyw4LDksMTAsMTEsMTIsMTMsMTQsMTUsMTYsMTcsMTgsMTksMjAsMjEsMjIsMjMsMjUsMjYsMjcsMjgsMjksMzAsMzEsMzIsMzMsMzQsMzUsMzYsMzcsMzgsMzksNDEsNDIsNDMsNDQsNDUsNDYsNDcsNDgsNDksNTAsNTEsNTIsNTMsNTQsNTUsNTYsNTcsNTgsNTksNjAsNjEsNjIsNjMsNjQsNjUsNjYsNjcsNjgsNjksNzAsNzEsNzIsNzMsNzQsNzUsNzYsNzcsNzgsNzksODAsODIsODMsODQsODUsODYsODcsODgsODksOTAsOTEsOTIsOTMsOTQsOTUsOTYsOTcsOTgsOTksMTAwLDEwMSwxMDIsMTAzLDEwNCwxMDUsMTA2LDEwNywxMDgsMTA5LDExMCwxMTEsMTEzLDExNCwxMTUsMTE2LDExNywxMTgsMTE5LDEyMCwxMjEsMTIyLDEyMywxMjQsMTI1LDEyNiwxMjcsMTI4LDEyOSwxMzAsMTMxLDEzMiwxMzMsMTM0LDEzNSwxMzYsMTM3LDEzOCwxMzksMTQwLDE0MSwxNDUsMTQ2LDE0NywxNDgsMTUxLDE1NSwxNTYsMTU3LDE2MSwxNjIsMTYzLDE2NCwxNjUsMTY2LDE2OCwxNjksMTcwLDE3MywxNzQsMTc2LDE3OCwxODAsMTgxLDE4MiwxODMsMTg0LDE4NSwxODYsMTg4LDE5MywxOTQsMTk1LDE5NiwxOTcsMTk4LDE5OSwyMDAsMjAxLDIwMiwyMDgsMjEwLDIxMSwyMTUsMjQ2XSwibG5nIjpbImVuX3VzIiwiZW5fYXUiLCJlbl9nYiIsImVzX214IiwiemhfY24iXSwibm9uY2UiOiJkNDY0ODJkOC01OGFjLTQzMjItOGM1Zi01ZTk2M2I5NTAxNzMiLCJsb2dnZWRJbiI6dHJ1ZX0.3H2eCxa3ofu82yuJeJhcuhXm6h60fTZOet4Mhz1Tvmk`
	payload := `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL3d3dy5teW9uLmNvbSIsImlzcyI6Imh0dHBzOi8vd3d3Lm15b24uY29tIiwianRpIjoiMDM5ZDhiN2YtNzdiZS00NmE1LWIwN2UtOWViZGM1ZTg3ZWI5IiwiaWF0IjoxNjQwMjc0NDMyLjkzNzg1MywiZXhwIjoxOTQwMjc1NzUyLjkzNzg1NSwidWlkIjoyMDUwODQ1LCJ1cmlkIjoyLCJ1Z2lkIjo4LCJhaWQiOjQwNTY3NSwiYmlkIjo0MDU2NzYsImxtdGgiOiJsb2NhbGN2IiwicGVybXMiOlsxLDIsNCw1LDYsNyw4LDksMTAsMTEsMTIsMTMsMTQsMTUsMTYsMTcsMTgsMTksMjAsMjEsMjIsMjMsMjUsMjYsMjcsMjgsMjksMzAsMzEsMzIsMzMsMzQsMzUsMzYsMzcsMzgsMzksNDEsNDIsNDMsNDQsNDUsNDYsNDcsNDgsNDksNTAsNTEsNTIsNTMsNTQsNTUsNTYsNTcsNTgsNTksNjAsNjEsNjIsNjMsNjQsNjUsNjYsNjcsNjgsNjksNzAsNzEsNzIsNzMsNzQsNzUsNzYsNzcsNzgsNzksODAsODIsODMsODQsODUsODYsODcsODgsODksOTAsOTEsOTIsOTMsOTQsOTUsOTYsOTcsOTgsOTksMTAwLDEwMSwxMDIsMTAzLDEwNCwxMDUsMTA2LDEwNywxMDgsMTA5LDExMCwxMTEsMTEzLDExNCwxMTUsMTE2LDExNywxMTgsMTE5LDEyMCwxMjEsMTIyLDEyMywxMjQsMTI1LDEyNiwxMjcsMTI4LDEyOSwxMzAsMTMxLDEzMiwxMzMsMTM0LDEzNSwxMzYsMTM3LDEzOCwxMzksMTQwLDE0MSwxNDUsMTQ2LDE0NywxNDgsMTUxLDE1NSwxNTYsMTU3LDE2MSwxNjIsMTYzLDE2NCwxNjUsMTY2LDE2OCwxNjksMTcwLDE3MywxNzQsMTc2LDE3OCwxODAsMTgxLDE4MiwxODMsMTg0LDE4NSwxODYsMTg4LDE5MywxOTQsMTk1LDE5NiwxOTcsMTk4LDE5OSwyMDAsMjAxLDIwMiwyMDgsMjEwLDIxMSwyMTUsMjQ2XSwibG5nIjpbImVuX3VzIiwiZW5fYXUiLCJlbl9nYiIsImVzX214IiwiemhfY24iXSwibm9uY2UiOiJkNDY0ODJkOC01OGFjLTQzMjItOGM1Zi01ZTk2M2I5NTAxNzMiLCJsb2dnZWRJbiI6dHJ1ZX0.3H2eCxa3ofu82yuJeJhcuhXm6h60fTZOet4Mhz1Tvmk`
	signer := NewSigner(HS256, []byte(os.Getenv("TESTSALT")))

	m := &myonClaims{}
	err := signer.Unserialize(payload, m)
	// spew.Dump(err)
	if err != nil {
		t.Error(err)
	}
}
