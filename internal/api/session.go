// Package api serves the console and a filtered read/write API in front of the
// Kubernetes API.
//
// It exists because the console cannot talk to Kubernetes directly and still be
// safe. Findings name the exact file holding an exploitable pickle and the
// offset of a leaked credential; Kubernetes RBAC authorises resource *types*,
// so anyone who can read a namespace reads every finding in it at full detail.
// The filtering in internal/authz has to happen somewhere the browser cannot
// reach around, which means server-side, which means here.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// sessionCookie is the name of the cookie carrying the signed session.
const sessionCookie = "cupel_session"

// session is what is stored in the cookie after a successful login. It holds
// identity only — never capabilities or tenant scope, which are re-derived
// from the bindings on every request so that revoking a binding takes effect
// immediately rather than whenever the cookie happens to expire.
type session struct {
	Username string   `json:"u"`
	Groups   []string `json:"g"`
	Expires  int64    `json:"e"`
}

// sessionCodec signs and verifies session cookies.
//
// Signed rather than encrypted: the contents are the user's own username and
// groups, which they already know. What matters is that they cannot change
// them, because the whole authorization model is derived from those groups.
type sessionCodec struct {
	key []byte
	ttl time.Duration
}

func newSessionCodec(key []byte, ttl time.Duration) (*sessionCodec, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("session key must be at least 32 bytes, got %d", len(key))
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &sessionCodec{key: key, ttl: ttl}, nil
}

// randomKey generates a session key. Used when no key is configured, which
// means sessions do not survive a restart or span replicas — acceptable for a
// single-replica install, and loudly warned about at startup.
func randomKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("cannot read random bytes for the session key: " + err.Error())
	}
	return k
}

func (c *sessionCodec) sign(payload []byte) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (c *sessionCodec) verify(value string) (*session, error) {
	body, sig, ok := strings.Cut(value, ".")
	if !ok {
		return nil, fmt.Errorf("malformed session")
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("malformed session payload")
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("malformed session signature")
	}
	mac := hmac.New(sha256.New, c.key)
	mac.Write(payload)
	// Constant time, so a forged cookie cannot be refined byte by byte.
	if !hmac.Equal(mac.Sum(nil), want) {
		return nil, fmt.Errorf("session signature does not verify")
	}

	var s session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, fmt.Errorf("malformed session contents")
	}
	if time.Now().Unix() > s.Expires {
		return nil, fmt.Errorf("session expired")
	}
	return &s, nil
}

// issue writes a signed session cookie.
func (c *sessionCodec) issue(w http.ResponseWriter, r *http.Request, username string, groups []string) error {
	payload, err := json.Marshal(session{
		Username: username,
		Groups:   groups,
		Expires:  time.Now().Add(c.ttl).Unix(),
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: c.sign(payload),
		Path:  "/",
		// The session is the only thing standing between an anonymous visitor
		// and every finding in the cluster, so it never goes to script and
		// never leaves on a cross-site request.
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isTLS(r),
		Expires:  time.Now().Add(c.ttl),
	})
	return nil
}

func (c *sessionCodec) clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isTLS(r),
		MaxAge: -1,
	})
}

// isTLS reports whether the request arrived over TLS, directly or through a
// proxy that terminated it. Getting this wrong in the permissive direction
// would drop the Secure flag and let the session travel in clear text.
func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
