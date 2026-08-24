package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
)

// OIDCConfig configures login against any standards-compliant provider —
// Keycloak, Okta, Entra, Dex, Auth0, Rancher, and OpenShift's OAuth server.
// One implementation rather than one per platform, because a security tool
// that only authenticates on one vendor's Kubernetes is not portable.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes requested in addition to openid. "groups" is what the binding
	// layer maps to roles, and providers differ on whether it must be asked
	// for explicitly.
	Scopes []string
	// GroupsClaim is the token claim holding group membership. Providers
	// disagree: "groups" is common, Entra uses "roles" or "groups" depending
	// on configuration.
	GroupsClaim string
	// UsernameClaim identifies the user. "email" and "preferred_username" are
	// the usual choices.
	UsernameClaim string
	// InsecureSkipVerify disables issuer TLS verification. For a test provider
	// with a self-signed certificate only.
	InsecureSkipVerify bool
}

// authenticator turns a browser round-trip into a verified identity.
type authenticator struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	cfg      OIDCConfig
}

func newAuthenticator(ctx context.Context, cfg OIDCConfig) (*authenticator, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("OIDC requires an issuer URL and a client ID")
	}
	provider, err := oidc.NewProvider(ctx, strings.TrimRight(cfg.IssuerURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer %q: %w", cfg.IssuerURL, err)
	}
	scopes := append([]string{oidc.ScopeOpenID, "profile", "email"}, cfg.Scopes...)
	return &authenticator{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       dedupe(scopes),
		},
		cfg: cfg,
	}, nil
}

const stateCookie = "cupel_oidc_state"

// login starts the authorization code flow. The state parameter is random per
// attempt and echoed in a cookie, so a callback that did not originate here is
// rejected rather than logging someone in.
func (a *authenticator) login(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: state, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: isTLS(r),
		Expires: time.Now().Add(10 * time.Minute),
	})
	http.Redirect(w, r, a.oauth.AuthCodeURL(state), http.StatusFound)
}

// callback completes the flow and returns the verified claims.
func (a *authenticator) callback(w http.ResponseWriter, r *http.Request) (*authz.Claims, error) {
	want, err := r.Cookie(stateCookie)
	if err != nil {
		return nil, fmt.Errorf("no login in progress")
	}
	// Constant-time compare is unnecessary here — the state is not a secret,
	// it is a nonce — but it must match exactly or this is a CSRF hole.
	if got := r.URL.Query().Get("state"); got == "" || got != want.Value {
		return nil, fmt.Errorf("login state does not match; start again")
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", MaxAge: -1})

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		return nil, fmt.Errorf("identity provider refused the login: %s", errParam)
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("no authorization code in the callback")
	}

	token, err := a.oauth.Exchange(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("the provider returned no id_token")
	}
	idToken, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("read token claims: %w", err)
	}
	return extractClaims(claims, a.cfg), nil
}

// extractClaims pulls the username and groups out of a verified token.
//
// Claim shapes differ between providers, so this is deliberately forgiving
// about types while never inventing a value: an identity with no username is
// an error rather than an empty string, because an empty username would
// otherwise match a binding written against "".
func extractClaims(claims map[string]any, cfg OIDCConfig) *authz.Claims {
	userKey := cfg.UsernameClaim
	if userKey == "" {
		userKey = "email"
	}
	out := &authz.Claims{}
	for _, k := range dedupe([]string{userKey, "email", "preferred_username", "sub"}) {
		if v, ok := claims[k].(string); ok && v != "" {
			out.Username = v
			break
		}
	}

	groupKey := cfg.GroupsClaim
	if groupKey == "" {
		groupKey = "groups"
	}
	switch v := claims[groupKey].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				out.Groups = append(out.Groups, s)
			}
		}
	case []string:
		out.Groups = append(out.Groups, v...)
	case string:
		// Some providers emit a single group as a bare string, and others a
		// space or comma separated list.
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			if part != "" {
				out.Groups = append(out.Groups, part)
			}
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
