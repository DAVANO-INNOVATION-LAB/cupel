// Command cupel-api serves the console and the authenticated API.
//
// It is a separate process from the operator on purpose. The operator holds
// broad cluster credentials because it has to create Jobs and write status
// across namespaces; the console is reachable by people. Running them in one
// process means any flaw in the HTTP surface reaches the operator's service
// account, so they get separate deployments with separate RBAC — the API
// server only needs to read the CRDs and create scans and exceptions.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/api"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/console"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/indexes"
)

func main() {
	var (
		addr           string
		namespace      string
		bindingsPath   string
		issuerURL      string
		clientID       string
		clientSecret   string
		redirectURL    string
		groupsClaim    string
		usernameClaim  string
		scopes         string
		sessionTTL     time.Duration
		sessionKeyPath string
		certFile       string
		keyFile        string
	)

	flag.StringVar(&addr, "listen", ":8443", "address to serve on")
	flag.StringVar(&namespace, "namespace", envOr("POD_NAMESPACE", "cupel-system"),
		"namespace scans and exceptions are created in")
	flag.StringVar(&bindingsPath, "bindings", "/config/bindings.yaml",
		"role bindings mapping identity-provider groups to roles and tenants")
	flag.StringVar(&issuerURL, "oidc-issuer-url", os.Getenv("CUPEL_OIDC_ISSUER"),
		"OIDC issuer; required, there is no anonymous mode")
	flag.StringVar(&clientID, "oidc-client-id", os.Getenv("CUPEL_OIDC_CLIENT_ID"), "OIDC client ID")
	flag.StringVar(&clientSecret, "oidc-client-secret", os.Getenv("CUPEL_OIDC_CLIENT_SECRET"),
		"OIDC client secret; prefer the environment over a flag so it stays out of the process list")
	flag.StringVar(&redirectURL, "oidc-redirect-url", os.Getenv("CUPEL_OIDC_REDIRECT_URL"),
		"OAuth2 callback URL, e.g. https://cupel.example/auth/callback")
	flag.StringVar(&groupsClaim, "oidc-groups-claim", "groups", "claim holding group membership")
	flag.StringVar(&scopes, "oidc-scopes", "groups",
		"comma-separated scopes requested beyond openid/profile/email. Without a scope that "+
			"yields group membership, every login lands with no groups and therefore no role")
	flag.StringVar(&usernameClaim, "oidc-username-claim", "email", "claim holding the username")
	flag.DurationVar(&sessionTTL, "session-ttl", 8*time.Hour, "how long a login lasts")
	flag.StringVar(&sessionKeyPath, "session-key-file", "",
		"file holding the session signing key; without it sessions do not survive a restart or span replicas")
	flag.StringVar(&certFile, "tls-cert-file", "", "TLS certificate")
	flag.StringVar(&keyFile, "tls-private-key-file", "", "TLS private key")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	logger := ctrl.Log.WithName("cupel-api")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, config{
		addr: addr, namespace: namespace, bindingsPath: bindingsPath,
		oidc: api.OIDCConfig{
			IssuerURL: issuerURL, ClientID: clientID, ClientSecret: clientSecret,
			RedirectURL: redirectURL, GroupsClaim: groupsClaim, UsernameClaim: usernameClaim,
			Scopes: splitList(scopes),
		},
		sessionTTL: sessionTTL, sessionKeyPath: sessionKeyPath,
		certFile: certFile, keyFile: keyFile,
	}); err != nil {
		logger.Error(err, "the console API could not start")
		os.Exit(1)
	}
}

// stripServerMetadata drops bookkeeping the console never reads before an
// object is cached. It must not touch anything a handler depends on: name,
// namespace, labels, spec and status all survive.
func stripServerMetadata(obj any) (any, error) {
	o, ok := obj.(client.Object)
	if !ok {
		return obj, nil
	}
	o.SetManagedFields(nil)
	if ann := o.GetAnnotations(); ann != nil {
		if _, found := ann[corev1.LastAppliedConfigAnnotation]; found {
			// Copy before mutating: the object handed to a transform may be
			// shared, and deleting from a map somebody else holds is a data
			// race that only shows up under load.
			trimmed := make(map[string]string, len(ann)-1)
			for k, v := range ann {
				if k != corev1.LastAppliedConfigAnnotation {
					trimmed[k] = v
				}
			}
			o.SetAnnotations(trimmed)
		}
	}
	return obj, nil
}

type config struct {
	addr           string
	namespace      string
	bindingsPath   string
	oidc           api.OIDCConfig
	sessionTTL     time.Duration
	sessionKeyPath string
	certFile       string
	keyFile        string
}

func run(ctx context.Context, cfg config) error {
	logger := ctrl.Log.WithName("cupel-api")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load cluster config: %w", err)
	}
	// Reads go through a cache with field indexes rather than straight to the
	// API server. The console polls, so an uncached client turned every open
	// tab into a steady stream of full-collection lists — the whole compliance
	// collection every couple of seconds, to answer a question about one model.
	// The cache also makes indexed lookups possible at all: the API server has
	// no field selectors for custom resources, so narrowing has to happen here.
	informers, err := cache.New(restCfg, cache.Options{
		Scheme: scheme,
		// Managed fields are a rewrite history the API server keeps for
		// server-side apply. Nothing here reads them, and on a compliance
		// report -- which already carries every assessed control -- they are a
		// large fraction of the object. Dropping them on the way into the cache
		// is the difference between holding the cluster's metadata and holding
		// its meaning.
		DefaultTransform: stripServerMetadata,
	})
	if err != nil {
		return fmt.Errorf("build cluster cache: %w", err)
	}
	if err := indexes.Register(ctx, informers); err != nil {
		return err
	}

	cacheCtx, stopCache := context.WithCancel(ctx)
	defer stopCache()
	cacheErr := make(chan error, 1)
	go func() { cacheErr <- informers.Start(cacheCtx) }()

	// Serving before the cache has synced would answer the first requests from
	// an empty store, which reads as "this cluster has no models" rather than
	// as "ask again shortly".
	syncCtx, cancelSync := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelSync()
	if !informers.WaitForCacheSync(syncCtx) {
		return fmt.Errorf("the cluster cache did not sync within two minutes")
	}
	logger.Info("cluster cache synced")

	k8s, err := client.New(restCfg, client.Options{
		Scheme: scheme,
		Cache: &client.CacheOptions{
			Reader: informers,
			// The audit chain is append-only and read rarely, and holding every
			// record in memory to serve an occasional drawer is the wrong
			// trade: these stay uncached and read through to the API server.
			DisableFor: audit.UncachedTypes(),
		},
	})
	if err != nil {
		return fmt.Errorf("build cluster client: %w", err)
	}

	bindings, err := loadBindings(cfg.bindingsPath)
	if err != nil {
		return err
	}
	logger.Info("loaded role bindings", "bindings", len(bindings), "path", cfg.bindingsPath)

	sessionKey, err := loadSessionKey(cfg.sessionKeyPath)
	if err != nil {
		return err
	}
	if len(sessionKey) == 0 {
		logger.Info("no session key file configured; sessions will not survive a restart " +
			"and will not work across replicas")
	}

	server, err := api.New(ctx, k8s, api.Config{
		Namespace:  cfg.namespace,
		Bindings:   bindings,
		OIDC:       cfg.oidc,
		SessionKey: sessionKey,
		SessionTTL: cfg.sessionTTL,
		Console:    console.IndexHTML,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()

	// Session cookies are marked Secure, so over plain HTTP a browser will
	// refuse to send them back and every request looks unauthenticated. Serving
	// without TLS is supported for a local port-forward and warned about
	// loudly, because it is not a deployment posture.
	if cfg.certFile == "" || cfg.keyFile == "" {
		logger.Info("serving without TLS: session cookies are Secure, so this only works " +
			"behind a TLS-terminating proxy or through a local port-forward")
		logger.Info("console listening", "addr", cfg.addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	logger.Info("console listening with TLS", "addr", cfg.addr)
	if err := httpServer.ListenAndServeTLS(cfg.certFile, cfg.keyFile); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// loadBindings reads the role bindings.
//
// A missing file is fatal rather than defaulting to something permissive. The
// failure mode of guessing here is a console that shows everything to everyone,
// which is the exact thing this server exists to prevent.
func loadBindings(path string) (authz.Bindings, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return authz.Bindings{}, fmt.Errorf(
				"no role bindings at %s. Without them nobody can be granted a role, and "+
					"defaulting to a permissive mapping would hand every finding to every "+
					"authenticated user. Mount a bindings file, or see config/samples for one",
				path)
		}
		return authz.Bindings{}, err
	}
	bindings, err := authz.ParseBindings(raw)
	if err != nil {
		return authz.Bindings{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := bindings.Validate(); err != nil {
		return authz.Bindings{}, fmt.Errorf("%s: %w", path, err)
	}
	return bindings, nil
}

func loadSessionKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read session key: %w", err)
	}
	key := []byte(strings.TrimSpace(string(raw)))
	if len(key) < 32 {
		return nil, fmt.Errorf("the session key must be at least 32 bytes; %s holds %d", path, len(key))
	}
	return key, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitList turns a comma-separated flag into a slice, dropping blanks.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
