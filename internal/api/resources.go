package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// The endpoints the console needs beyond models and findings.
//
// Each one filters by the subject's scope rather than returning what the
// operator's service account can see. That distinction is the whole reason
// this server exists: the operator necessarily has broad cluster access, and
// handing that reach to whoever loads the page is exactly what serving the
// console through `kubectl proxy` did.

// scanView is a scan in flight, or a recently finished one.
type scanView struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	Phase        string `json:"phase"`
	Verdict      string `json:"verdict,omitempty"`
	RiskScore    int32  `json:"riskScore"`
	// Scored distinguishes "no verdict yet" from "scored zero".
	Scored      bool   `json:"scored"`
	Trigger     string `json:"trigger,omitempty"`
	TriggeredBy string `json:"triggeredBy,omitempty"`
	Scanners    int    `json:"scanners"`
	StartTime   string `json:"startTime,omitempty"`
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewInventory) {
		forbid(w, "your role cannot see the model inventory")
		return
	}
	var list securityv1alpha1.ArtifactScanList
	if err := s.k8s.List(r.Context(), &list); err != nil {
		internalError(w, "cannot list scans")
		return
	}

	out := make([]scanView, 0, len(list.Items))
	for _, sc := range list.Items {
		if !sub.CanSeeNamespace(sc.Namespace) {
			continue
		}
		v := scanView{
			Name: sc.Name, Namespace: sc.Namespace,
			ModelName: sc.Spec.ModelName, ModelVersion: sc.Spec.ModelVersion,
			Phase: sc.Status.Phase, Verdict: sc.Status.Verdict,
			Trigger: sc.Spec.Trigger, TriggeredBy: sc.Spec.TriggeredBy,
			Scanners: len(sc.Status.Results),
		}
		// A nil risk score means the scan has not reached a verdict, which is
		// different from a score of zero. Flattening the two would make a scan
		// still running look like a clean result.
		if sc.Status.RiskScore != nil {
			v.RiskScore = *sc.Status.RiskScore
			v.Scored = true
		}
		if sc.Status.StartTime != nil {
			v.StartTime = sc.Status.StartTime.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartTime > out[j].StartTime })
	writeJSON(w, http.StatusOK, map[string]any{"scans": out})
}

// exceptionView is an accepted risk.
//
// The approver is included because an acceptance without attribution is not a
// decision anyone can be held to, and hiding it would make the queue read as
// though every waiver were properly signed.
type exceptionView struct {
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace"`
	ModelName    string   `json:"modelName"`
	ModelVersion string   `json:"modelVersion"`
	FindingIDs   []string `json:"findingIds,omitempty"`
	Rules        []string `json:"rules,omitempty"`
	Reason       string   `json:"reason"`
	ApprovedBy   string   `json:"approvedBy"`
	ApprovedAt   string   `json:"approvedAt,omitempty"`
	ExpiresAt    string   `json:"expiresAt,omitempty"`
	// Signed is false when no admission webhook established the identity, so
	// the console can say "accepted, unsigned" rather than implying attribution
	// the record does not carry.
	Signed bool `json:"signed"`
}

func (s *Server) handleExceptions(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewFindings) {
		forbid(w, "your role cannot see findings or the acceptances against them")
		return
	}
	var list securityv1alpha1.ArtifactExceptionList
	if err := s.k8s.List(r.Context(), &list); err != nil {
		internalError(w, "cannot list exceptions")
		return
	}

	out := make([]exceptionView, 0, len(list.Items))
	for _, e := range list.Items {
		if !sub.CanSeeNamespace(e.Namespace) {
			continue
		}
		v := exceptionView{
			Name: e.Name, Namespace: e.Namespace,
			ModelName: e.Spec.ModelName, ModelVersion: e.Spec.ModelVersion,
			FindingIDs: e.Spec.FindingIDs, Rules: e.Spec.Rules,
			Reason: e.Spec.Reason, ApprovedBy: e.Spec.ApprovedBy,
			Signed: e.Spec.ApprovedBy != "" && e.Spec.ApprovedAt != nil,
		}
		if e.Spec.ApprovedAt != nil {
			v.ApprovedAt = e.Spec.ApprovedAt.UTC().Format(time.RFC3339)
		}
		if e.Spec.ExpiresAt != nil {
			v.ExpiresAt = e.Spec.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"exceptions": out})
}

// connectorView is a model source.
type connectorView struct {
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	Type             string `json:"type"`
	RegistryURL      string `json:"registryUrl"`
	Phase            string `json:"phase"`
	Message          string `json:"message,omitempty"`
	RegisteredModels int32  `json:"registeredModels"`
	ModelVersions    int32  `json:"modelVersions"`
	ScansCreated     int32  `json:"scansCreated"`
	LastSyncTime     string `json:"lastSyncTime,omitempty"`
	PollInterval     string `json:"pollInterval,omitempty"`
	RescanInterval   string `json:"rescanInterval,omitempty"`
	PolicyRef        string `json:"policyRef,omitempty"`
	// HasCredential reports that a secret is referenced, without naming it.
	// Which secret backs a connector is an operational detail that does not
	// need to reach every viewer.
	HasCredential bool `json:"hasCredential"`
}

func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewInventory) {
		forbid(w, "your role cannot see model sources")
		return
	}
	var list securityv1alpha1.ModelRegistryConnectorList
	if err := s.k8s.List(r.Context(), &list); err != nil {
		internalError(w, "cannot list connectors")
		return
	}

	out := make([]connectorView, 0, len(list.Items))
	for _, c := range list.Items {
		if !sub.CanSeeNamespace(c.Namespace) {
			continue
		}
		v := connectorView{
			Name: c.Name, Namespace: c.Namespace,
			Type: c.Spec.Type, RegistryURL: c.Spec.RegistryURL,
			Phase: c.Status.Phase, Message: c.Status.Message,
			RegisteredModels: c.Status.RegisteredModels,
			ModelVersions:    c.Status.ModelVersions,
			ScansCreated:     c.Status.ScansCreated,
			PolicyRef:        c.Spec.PolicyRef,
			HasCredential:    c.Spec.AuthSecretRef != nil,
		}
		if v.Type == "" {
			v.Type = "KubeflowModelRegistry"
		}
		if c.Status.LastSyncTime != nil {
			v.LastSyncTime = c.Status.LastSyncTime.UTC().Format(time.RFC3339)
		}
		if c.Spec.PollInterval != nil {
			v.PollInterval = c.Spec.PollInterval.Duration.String()
		}
		if c.Spec.RescanInterval != nil {
			v.RescanInterval = c.Spec.RescanInterval.Duration.String()
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"connectors": out})
}

// connectorRequest creates a model source.
//
// There is deliberately no field for a token. The console is reachable over a
// network and a credential typed into a form is a credential in a request log;
// the connector carries a reference to a Secret the cluster administrator
// created out of band.
type connectorRequest struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	RegistryURL    string   `json:"registryUrl"`
	PollInterval   string   `json:"pollInterval"`
	RescanInterval string   `json:"rescanInterval"`
	PolicyRef      string   `json:"policyRef"`
	IncludeModels  []string `json:"includeModels"`
	SecretName     string   `json:"secretName"`
	SecretKey      string   `json:"secretKey"`
	InsecureTLS    bool     `json:"insecureSkipTlsVerify"`
	WriteBack      *bool    `json:"writeBack"`
}

var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func (s *Server) handleCreateConnector(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapManage) {
		forbid(w, "connecting a model source is an administrative action")
		return
	}
	var req connectorRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		badRequest(w, "could not read the request: "+err.Error())
		return
	}
	if !dnsName.MatchString(req.Name) {
		badRequest(w, "the name must be lowercase letters, digits and dashes: it becomes a Kubernetes object name")
		return
	}
	if req.RegistryURL == "" {
		badRequest(w, "an endpoint is required")
		return
	}
	if !strings.HasPrefix(req.RegistryURL, "http://") && !strings.HasPrefix(req.RegistryURL, "https://") {
		badRequest(w, "the endpoint must be an http or https URL")
		return
	}

	spec := securityv1alpha1.ModelRegistryConnectorSpec{
		Type:                  req.Type,
		RegistryURL:           req.RegistryURL,
		PolicyRef:             req.PolicyRef,
		IncludeModels:         req.IncludeModels,
		InsecureSkipTLSVerify: req.InsecureTLS,
		WriteBack:             req.WriteBack,
	}
	if d, err := parseDuration(req.PollInterval); err != nil {
		badRequest(w, "poll interval: "+err.Error())
		return
	} else if d != nil {
		spec.PollInterval = d
	}
	if d, err := parseDuration(req.RescanInterval); err != nil {
		badRequest(w, "rescan interval: "+err.Error())
		return
	} else if d != nil {
		spec.RescanInterval = d
	}
	if req.SecretName != "" {
		key := req.SecretKey
		if key == "" {
			key = "token"
		}
		spec.AuthSecretRef = &securityv1alpha1.SecretKeyRef{Name: req.SecretName, Key: key}
	}

	connector := &securityv1alpha1.ModelRegistryConnector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: s.cfg.Namespace,
			Annotations: map[string]string{
				// Who added a source is worth recording: it decides which
				// models enter the pipeline at all.
				"security.davano.io/created-by": sub.Username,
			},
		},
		Spec: spec,
	}
	if err := s.k8s.Create(r.Context(), connector); err != nil {
		if apierrors.IsAlreadyExists(err) {
			badRequest(w, fmt.Sprintf("a source named %q already exists", req.Name))
			return
		}
		internalError(w, "could not create the source: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": connector.Name})
}

func (s *Server) handleDeleteConnector(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapManage) {
		forbid(w, "removing a model source is an administrative action")
		return
	}
	name := r.PathValue("name")
	if !dnsName.MatchString(name) {
		badRequest(w, "invalid source name")
		return
	}
	connector := &securityv1alpha1.ModelRegistryConnector{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: s.cfg.Namespace},
	}
	if err := s.k8s.Delete(r.Context(), connector); err != nil {
		if apierrors.IsNotFound(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such source"})
			return
		}
		internalError(w, "could not remove the source: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSyncConnector pokes a connector so it reconciles now.
func (s *Server) handleSyncConnector(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapManage) {
		forbid(w, "triggering a sync is an administrative action")
		return
	}
	name := r.PathValue("name")
	if !dnsName.MatchString(name) {
		badRequest(w, "invalid source name")
		return
	}

	var connector securityv1alpha1.ModelRegistryConnector
	key := client.ObjectKey{Name: name, Namespace: s.cfg.Namespace}
	if err := s.k8s.Get(r.Context(), key, &connector); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such source"})
		return
	}
	if connector.Annotations == nil {
		connector.Annotations = map[string]string{}
	}
	connector.Annotations["security.davano.io/sync-requested"] = time.Now().UTC().Format(time.RFC3339)
	connector.Annotations["security.davano.io/sync-requested-by"] = sub.Username
	if err := s.k8s.Update(r.Context(), &connector); err != nil {
		internalError(w, "could not trigger a sync: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewInventory) {
		forbid(w, "your role cannot see policies")
		return
	}
	var list securityv1alpha1.ArtifactScanPolicyList
	if err := s.k8s.List(r.Context(), &list); err != nil {
		internalError(w, "cannot list policies")
		return
	}
	names := make([]string, 0, len(list.Items))
	for _, p := range list.Items {
		if sub.CanSeeNamespace(p.Namespace) {
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]any{"policies": names})
}

// scannerView describes an available scanner for the scan form.
type scannerView struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Default  bool   `json:"default"`
}

func (s *Server) handleScanners(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewInventory) {
		forbid(w, "your role cannot see the scanner catalog")
		return
	}
	defaults := map[string]bool{}
	for _, n := range scanners.Defaults() {
		defaults[n] = true
	}
	// Available() excludes scanners with no published image, so the form
	// cannot offer a scan that would fail to pull.
	names := scanners.Available()
	out := make([]scannerView, 0, len(names))
	for _, n := range names {
		def, err := scanners.Get(n)
		if err != nil {
			continue
		}
		out = append(out, scannerView{Name: n, Category: string(def.Category), Default: defaults[n]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"scanners": out})
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewCompliance) {
		forbid(w, "your role cannot see compliance reports")
		return
	}
	var list securityv1alpha1.ComplianceReportList
	if err := s.k8s.List(r.Context(), &list); err != nil {
		internalError(w, "cannot list compliance reports")
		return
	}
	out := make([]securityv1alpha1.ComplianceReport, 0, len(list.Items))
	for _, c := range list.Items {
		if sub.CanSeeNamespace(c.Namespace) {
			out = append(out, c)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out})
}

// parseDuration accepts the Go duration strings the CRDs use.
func parseDuration(s string) (*metav1.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a duration; use forms like 5m, 1h or 24h", s)
	}
	if d < 0 {
		return nil, fmt.Errorf("a duration cannot be negative")
	}
	return &metav1.Duration{Duration: d}, nil
}

func forbid(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
}

func badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func internalError(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": msg})
}
