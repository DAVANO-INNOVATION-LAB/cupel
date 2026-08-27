package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
)

// Config configures the console API.
type Config struct {
	// Namespace the pipeline writes into. Reads are scoped to the subject's
	// tenants; this is where scans and exceptions are created.
	Namespace string
	// Bindings map identity-provider groups to roles and tenants.
	Bindings authz.Bindings
	// OIDC configures login. When IssuerURL is empty the server refuses to
	// start rather than serving findings to anyone who can reach the port.
	OIDC OIDCConfig
	// SessionKey signs session cookies. Generated if empty, which means
	// sessions do not survive a restart or span replicas.
	SessionKey []byte
	// SessionTTL bounds how long a login lasts.
	SessionTTL time.Duration
	// Console is the single-page console. Nil serves the API only.
	Console []byte
}

// Server is the console API.
type Server struct {
	k8s      client.Client
	cfg      Config
	sessions *sessionCodec
	auth     *authenticator
}

// New builds the server. It fails rather than starting unauthenticated: a
// console that serves exploit paths to anyone who reaches the port is worse
// than no console, and "we will add auth later" is how that ships.
func New(ctx context.Context, k8s client.Client, cfg Config) (*Server, error) {
	if cfg.OIDC.IssuerURL == "" {
		return nil, fmt.Errorf(
			"the console API requires an OIDC issuer: it serves finding detail, and there is no " +
				"anonymous mode. Set --oidc-issuer-url, or disable the console with --enable-console=false")
	}
	if err := cfg.Bindings.Validate(); err != nil {
		return nil, err
	}
	key := cfg.SessionKey
	if len(key) == 0 {
		key = randomKey()
	}
	sessions, err := newSessionCodec(key, cfg.SessionTTL)
	if err != nil {
		return nil, err
	}
	auth, err := newAuthenticator(ctx, cfg.OIDC)
	if err != nil {
		return nil, err
	}
	return &Server{k8s: k8s, cfg: cfg, sessions: sessions, auth: auth}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		s.auth.login(w, r)
	})
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		s.sessions.clear(w, r)
		w.WriteHeader(http.StatusNoContent)
	})

	// Everything below requires a verified session.
	mux.Handle("GET /api/whoami", s.authenticated(s.handleWhoami))
	mux.Handle("GET /api/models", s.authenticated(s.handleModels))
	mux.Handle("GET /api/findings", s.authenticated(s.handleFindings))
	mux.Handle("GET /api/bom", s.authenticated(s.handleBOM))
	mux.Handle("POST /api/scans", s.authenticated(s.handleCreateScan))
	mux.Handle("POST /api/exceptions", s.authenticated(s.handleCreateException))
	mux.Handle("GET /api/scans", s.authenticated(s.handleScans))
	mux.Handle("GET /api/exceptions", s.authenticated(s.handleExceptions))
	mux.Handle("GET /api/connectors", s.authenticated(s.handleConnectors))
	mux.Handle("POST /api/connectors", s.authenticated(s.handleCreateConnector))
	mux.Handle("DELETE /api/connectors/{name}", s.authenticated(s.handleDeleteConnector))
	mux.Handle("POST /api/connectors/{name}/sync", s.authenticated(s.handleSyncConnector))
	mux.Handle("GET /api/policies", s.authenticated(s.handlePolicies))
	mux.Handle("GET /api/scanners", s.authenticated(s.handleScanners))
	mux.Handle("GET /api/compliance", s.authenticated(s.handleCompliance))

	mux.HandleFunc("GET /", s.handleConsole)
	return securityHeaders(mux)
}

// securityHeaders sets the headers a page rendering untrusted finding text
// should carry. The console is self-contained, so the policy can be strict.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	claims, err := s.auth.callback(w, r)
	if err != nil {
		http.Error(w, "login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if claims.Username == "" {
		http.Error(w, "the identity provider returned no username claim", http.StatusUnauthorized)
		return
	}
	if err := s.sessions.issue(w, r, claims.Username, claims.Groups); err != nil {
		http.Error(w, "cannot start session", http.StatusInternalServerError)
		return
	}
	// Log the resolved access, so "why can this person see that" is
	// answerable from the operator log without reading the bindings.
	log.FromContext(r.Context()).Info("console login",
		"access", s.cfg.Bindings.SubjectFor(*claims).Describe())
	http.Redirect(w, r, "/", http.StatusFound)
}

// authenticated resolves the session into a Subject and puts it on the
// request. Capabilities and scope are re-derived from the bindings every time
// rather than stored in the cookie, so removing a binding takes effect on the
// next request instead of whenever the session happens to expire.
func (s *Server) authenticated(next func(http.ResponseWriter, *http.Request, authz.Subject)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		sess, err := s.sessions.verify(c.Value)
		if err != nil {
			s.sessions.clear(w, r)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		subject := s.cfg.Bindings.SubjectFor(authz.Claims{
			Username: sess.Username, Groups: sess.Groups,
		})
		next(w, r, subject)
	})
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	caps := map[string]bool{}
	for _, c := range []authz.Capability{
		authz.CapViewInventory, authz.CapViewFindings, authz.CapViewFindingPath,
		authz.CapViewCompliance, authz.CapRunScan, authz.CapWaive, authz.CapManage,
	} {
		caps[string(c)] = sub.Can(c)
	}
	roles := make([]string, 0, len(sub.Roles))
	for _, r := range sub.Roles {
		roles = append(roles, string(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		// The namespace the pipeline writes into. The console needs it to show
		// an accurate `kubectl create secret` command; guessing it would print
		// instructions that quietly fail on a non-default install.
		"namespace":    s.cfg.Namespace,
		"username":     sub.Username,
		"roles":        roles,
		"tenants":      sub.Scope.Namespaces,
		"allTenants":   sub.Scope.AllNamespaces,
		"capabilities": caps,
		"access":       sub.Describe(),
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	var list securityv1alpha1.ModelSecurityReportList
	if err := s.k8s.List(r.Context(), &list); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot list models"})
		return
	}
	views := make([]authz.ModelView, 0, len(list.Items))
	for _, m := range list.Items {
		st := m.Status
		v := authz.ModelView{
			ModelName: m.Spec.ModelName, ModelVersion: m.Spec.ModelVersion,
			Namespace: m.Namespace, Verdict: st.Verdict, RiskScore: st.RiskScore,
			Malware: st.Malware, Secrets: st.Secrets, Severities: st.CVEs,
		}
		if st.LastScanTime != nil {
			v.LastScanTime = st.LastScanTime.UTC().Format(time.RFC3339)
		}
		views = append(views, v)
	}
	visible, redaction := authz.FilterModels(sub, views)
	writeJSON(w, http.StatusOK, map[string]any{"models": visible, "redaction": redaction})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	model := r.URL.Query().Get("model")
	version := r.URL.Query().Get("version")
	if model == "" || version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model and version are required"})
		return
	}

	// Find the scans for this model version, then the reports for those scans.
	var scans securityv1alpha1.ArtifactScanList
	if err := s.k8s.List(r.Context(), &scans); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot list scans"})
		return
	}
	owned := map[string]string{} // scan name -> namespace
	for _, sc := range scans.Items {
		if sc.Spec.ModelName == model && sc.Spec.ModelVersion == version {
			owned[sc.Name] = sc.Namespace
		}
	}

	var reports securityv1alpha1.ArtifactScanReportList
	if err := s.k8s.List(r.Context(), &reports); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot list reports"})
		return
	}

	var out []authz.FindingView
	var red authz.Redaction
	for _, rep := range reports.Items {
		ns, ok := owned[rep.ScanRef]
		if !ok {
			continue
		}
		views, r2 := authz.RedactFindings(sub, ns, rep.Findings, rep.Scanner)
		out = append(out, views...)
		if r2.HiddenFindings > 0 || r2.DetailWithheld {
			red = r2
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "redaction": red})
}

type scanRequest struct {
	ModelName    string   `json:"modelName"`
	ModelVersion string   `json:"modelVersion"`
	URI          string   `json:"uri"`
	Format       string   `json:"format"`
	PolicyRef    string   `json:"policyRef"`
	Scanners     []string `json:"scanners"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapRunScan) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "your role cannot start scans"})
		return
	}
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if req.ModelName == "" || req.URI == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "modelName and uri are required"})
		return
	}
	if !sub.CanSeeNamespace(s.cfg.Namespace) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you cannot create scans in this tenant"})
		return
	}
	version := req.ModelVersion
	if version == "" {
		version = "scan-" + time.Now().UTC().Format("150405")
	}

	scan := &securityv1alpha1.ArtifactScan{}
	scan.Name = naming.SanitizeLabel(req.ModelName + "-" + version)
	scan.Namespace = s.cfg.Namespace
	scan.Spec.ModelName = req.ModelName
	scan.Spec.ModelVersion = version
	scan.Spec.Artifact = securityv1alpha1.ArtifactRef{URI: req.URI, Format: req.Format}
	scan.Spec.PolicyRef = req.PolicyRef
	scan.Spec.Scanners = req.Scanners
	// A scan somebody clicked is a different assurance from one a registry
	// produced, so say which this was and who asked.
	scan.Spec.Trigger = "Manual"
	scan.Spec.TriggeredBy = sub.Username
	scan.Labels = map[string]string{"security.davano.io/trigger": "Manual"}

	if err := s.k8s.Create(r.Context(), scan); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": scan.Name, "namespace": scan.Namespace})
}

type exceptionRequest struct {
	ModelName    string   `json:"modelName"`
	ModelVersion string   `json:"modelVersion"`
	Reason       string   `json:"reason"`
	Rules        []string `json:"rules"`
}

func (s *Server) handleCreateException(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	// Accepting risk on your own model is not a control, so this is the one
	// capability owners deliberately do not have.
	if !sub.Can(authz.CapWaive) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "your role cannot accept risk; a model owner cannot sign off their own model"})
		return
	}
	var req exceptionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if req.Reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "a reason is required: an unexplained waiver is indistinguishable from a mistake"})
		return
	}
	if !sub.CanSeeNamespace(s.cfg.Namespace) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you cannot accept risk in this tenant"})
		return
	}

	ex := &securityv1alpha1.ArtifactException{}
	ex.Name = naming.SanitizeLabel("accept-" + req.ModelName + "-" + req.ModelVersion)
	ex.Namespace = s.cfg.Namespace
	ex.Spec.ModelName = req.ModelName
	ex.Spec.ModelVersion = req.ModelVersion
	ex.Spec.Reason = req.Reason
	ex.Spec.Rules = req.Rules
	// The signing webhook overwrites this from the authenticated Kubernetes
	// identity. Setting it here records who asked through the console, for the
	// case where the webhook is not installed — and the console says plainly
	// when that has happened.
	ex.Spec.ApprovedBy = sub.Username

	if err := s.k8s.Create(r.Context(), ex); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	log.FromContext(r.Context()).Info("risk accepted through the console",
		"by", sub.Username, "model", req.ModelName, "version", req.ModelVersion)
	writeJSON(w, http.StatusCreated, map[string]any{
		"name": ex.Name, "approvedBy": ex.Spec.ApprovedBy,
	})
}

func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.Console) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(s.cfg.Console)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
