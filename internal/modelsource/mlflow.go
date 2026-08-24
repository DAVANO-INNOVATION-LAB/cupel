package modelsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
)

// MLflow is a Source backed by an MLflow tracking server's Model Registry and
// artifact proxy. It targets the stable 2.0 REST API, so it works against any
// MLflow deployment that serves artifacts (the default since MLflow 2.x).
type MLflow struct {
	// baseURL is the tracking server root, e.g. http://localhost:5000.
	baseURL string
	http    *http.Client
	token   string
	// resolvers handles artifact sources that are storage URIs (s3://, oci://)
	// rather than the tracking server's own mlflow-artifacts proxy.
	resolvers *resolver.Registry
}

// MLflowOptions configures an MLflow source.
type MLflowOptions struct {
	// BaseURL is the tracking server root. Required.
	BaseURL string
	// Token is an optional bearer token for authenticated servers.
	Token string
	// HTTPClient overrides the default client (timeouts, TLS). Optional.
	HTTPClient *http.Client
	// Resolvers handles non-proxy artifact URIs. Defaults to the standard set.
	Resolvers *resolver.Registry
}

// NewMLflow builds an MLflow source.
func NewMLflow(opts MLflowOptions) *MLflow {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resolvers := opts.Resolvers
	if resolvers == nil {
		resolvers = resolver.NewRegistry()
	}
	return &MLflow{
		baseURL:   strings.TrimRight(opts.BaseURL, "/"),
		http:      httpClient,
		token:     opts.Token,
		resolvers: resolvers,
	}
}

// Name identifies this source.
func (m *MLflow) Name() string { return "mlflow" }

// Tag keys Cupel writes back onto an MLflow model version. Dotted so they group
// under "cupel" in the MLflow UI's tag list.
const (
	TagVerdict   = "cupel.verdict"
	TagRiskScore = "cupel.risk_score"
	TagMalware   = "cupel.malware"
	TagSecrets   = "cupel.secrets"
	TagScanTime  = "cupel.scan_time"
	TagReport    = "cupel.report"
)

// --- REST payload shapes (only the fields Cupel reads) ---

type mlflowRegisteredModel struct {
	Name string `json:"name"`
}

type mlflowModelVersion struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	CurrentStage string `json:"current_stage"`
	Source       string `json:"source"`
	RunID        string `json:"run_id"`
	Status       string `json:"status"`
}

type searchModelsResponse struct {
	RegisteredModels []mlflowRegisteredModel `json:"registered_models"`
	NextPageToken    string                  `json:"next_page_token"`
}

type searchVersionsResponse struct {
	ModelVersions []mlflowModelVersion `json:"model_versions"`
	NextPageToken string               `json:"next_page_token"`
}

// List enumerates every version of every registered model in the source.
func (m *MLflow) List(ctx context.Context) ([]Version, error) {
	models, err := m.searchRegisteredModels(ctx)
	if err != nil {
		return nil, err
	}

	var versions []Version
	for _, model := range models {
		mvs, err := m.searchModelVersions(ctx, model.Name)
		if err != nil {
			return nil, fmt.Errorf("list versions of %q: %w", model.Name, err)
		}
		for _, mv := range mvs {
			versions = append(versions, Version{
				ModelName: mv.Name,
				Version:   mv.Version,
				VersionID: mv.Version, // MLflow keys write-back on (name, version)
				Artifact: securityv1alpha1.ArtifactRef{
					// MLflow reports "mlflow-artifacts:/..." — a path inside a
					// server it does not name. The scan pod receives only the
					// URI, so rewrite it to carry the tracking host and stay
					// resolvable away from this process.
					URI:    m.resolvableURI(mv.Source),
					Format: "", // MLflow does not declare a serialization format
				},
				Labels: map[string]string{
					"mlflow.run_id": mv.RunID,
					"mlflow.stage":  mv.CurrentStage,
				},
			})
		}
	}
	return versions, nil
}

// resolvableURI makes an artifact location meaningful outside this process.
func (m *MLflow) resolvableURI(source string) string {
	if rewritten, ok := resolver.RewriteMLflowURI(source, m.baseURL); ok {
		return rewritten
	}
	return source
}

func (m *MLflow) searchRegisteredModels(ctx context.Context) ([]mlflowRegisteredModel, error) {
	var all []mlflowRegisteredModel
	pageToken := ""
	for {
		q := url.Values{"max_results": {"200"}}
		if pageToken != "" {
			q.Set("page_token", pageToken)
		}
		var resp searchModelsResponse
		if err := m.get(ctx, "/api/2.0/mlflow/registered-models/search", q, &resp); err != nil {
			return nil, fmt.Errorf("search registered models: %w", err)
		}
		all = append(all, resp.RegisteredModels...)
		if resp.NextPageToken == "" {
			return all, nil
		}
		pageToken = resp.NextPageToken
	}
}

func (m *MLflow) searchModelVersions(ctx context.Context, modelName string) ([]mlflowModelVersion, error) {
	var all []mlflowModelVersion
	pageToken := ""
	for {
		q := url.Values{
			// Single-quote escaping per the MLflow filter grammar.
			"filter":      {fmt.Sprintf("name='%s'", strings.ReplaceAll(modelName, "'", "\\'"))},
			"max_results": {"200"},
		}
		if pageToken != "" {
			q.Set("page_token", pageToken)
		}
		var resp searchVersionsResponse
		if err := m.get(ctx, "/api/2.0/mlflow/model-versions/search", q, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.ModelVersions...)
		if resp.NextPageToken == "" {
			return all, nil
		}
		pageToken = resp.NextPageToken
	}
}

// Resolve stages a model version's bytes into destDir. When the artifact
// source is an mlflow-artifacts: URI it is fetched through the tracking
// server's artifact proxy; any other scheme is handed to the storage resolvers.
func (m *MLflow) Resolve(ctx context.Context, v Version, destDir string) (*resolver.Artifact, error) {
	src := v.Artifact.URI
	if src == "" {
		return nil, fmt.Errorf("model version %s/%s has no artifact source", v.ModelName, v.Version)
	}

	if proxyPath, ok := mlflowArtifactPath(src); ok {
		return m.resolveViaProxy(ctx, src, proxyPath, destDir)
	}

	// Storage-backed source (s3://, oci://, ...): defer to the resolvers.
	if m.resolvers.Supports(src) {
		return m.resolvers.Resolve(ctx, src, destDir)
	}
	return nil, fmt.Errorf("no resolver for MLflow artifact source %q", src)
}

// mlflowArtifactPath reports whether src addresses the tracking server's own
// artifact proxy and, if so, returns the proxy-relative path.
//
// The source can be written two ways:
//
//	mlflow-artifacts:/0/<run>/artifacts/model         (host-less)
//	mlflow-artifacts://host:port/0/<run>/artifacts     (with authority)
func mlflowArtifactPath(src string) (string, bool) {
	const scheme = "mlflow-artifacts:"
	if !strings.HasPrefix(src, scheme) {
		return "", false
	}
	rest := strings.TrimPrefix(src, scheme)
	rest = strings.TrimPrefix(rest, "//")
	// Drop an authority component if one is present.
	if i := strings.Index(rest, "/"); strings.Contains(rest, ":") && i > 0 && !strings.HasPrefix(rest, "/") {
		rest = rest[i:]
	}
	return strings.TrimPrefix(rest, "/"), true
}

type artifactFile struct {
	Path     string `json:"path"`
	IsDir    bool   `json:"is_dir"`
	FileSize int64  `json:"file_size"`
}

type listArtifactsResponse struct {
	Files []artifactFile `json:"files"`
}

// resolveViaProxy walks the artifact proxy listing under root and downloads
// every file into destDir, preserving the tree below root.
//
// The proxy's listing endpoint returns each entry's path *relative to the
// queried directory* (a bare "weights.pkl"), while the download endpoint wants
// the *full* proxy path ("0/run/artifacts/model/weights.pkl"). Every path is
// therefore rejoined onto the directory it was listed under before use.
func (m *MLflow) resolveViaProxy(ctx context.Context, srcURI, root, destDir string) (*resolver.Artifact, error) {
	var total int64
	// Iterative walk so a deeply nested artifact tree cannot blow the stack.
	queue := []string{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]

		q := url.Values{}
		if dir != "" {
			q.Set("path", dir)
		}
		var listing listArtifactsResponse
		if err := m.get(ctx, "/api/2.0/mlflow-artifacts/artifacts", q, &listing); err != nil {
			return nil, fmt.Errorf("list artifacts under %q: %w", dir, err)
		}

		for _, f := range listing.Files {
			full := path.Join(dir, f.Path)
			if f.IsDir {
				queue = append(queue, full)
				continue
			}
			rel, err := filepath.Rel(root, full)
			if err != nil || strings.HasPrefix(rel, "..") {
				return nil, fmt.Errorf("artifact path %q escapes model root %q", full, root)
			}
			n, err := m.downloadArtifact(ctx, full, filepath.Join(destDir, rel))
			if err != nil {
				return nil, err
			}
			total += n
		}
	}

	return &resolver.Artifact{
		URI:       srcURI,
		LocalPath: destDir,
		SizeBytes: total,
	}, nil
}

func (m *MLflow) downloadArtifact(ctx context.Context, artifactPath, destPath string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return 0, err
	}

	endpoint := m.baseURL + "/api/2.0/mlflow-artifacts/artifacts/" + pathEscape(artifactPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	m.authorize(req)

	resp, err := m.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download %q: %w", artifactPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return 0, fmt.Errorf("download %q: HTTP %d: %s", artifactPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	out, err := os.Create(destPath)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	// Cap a single artifact file so a hostile tracking server cannot fill the
	// disk; 16 GiB is well past any real model shard.
	n, err := io.Copy(out, io.LimitReader(resp.Body, 16<<30))
	if err != nil {
		return n, fmt.Errorf("write %q: %w", destPath, err)
	}
	return n, nil
}

// WriteBack records the verdict on the model version as MLflow tags.
func (m *MLflow) WriteBack(ctx context.Context, v Version, verdict Verdict) error {
	tags := map[string]string{
		TagVerdict:   orUnknown(verdict.Verdict),
		TagRiskScore: fmt.Sprintf("%d", verdict.RiskScore),
	}
	if verdict.Malware != "" {
		tags[TagMalware] = verdict.Malware
	}
	if verdict.Secrets != "" {
		tags[TagSecrets] = verdict.Secrets
	}
	if !verdict.ScanTime.IsZero() {
		tags[TagScanTime] = verdict.ScanTime.UTC().Format(time.RFC3339)
	}
	if verdict.ReportRef != "" {
		tags[TagReport] = verdict.ReportRef
	}

	for key, value := range tags {
		if err := m.setModelVersionTag(ctx, v.ModelName, v.Version, key, value); err != nil {
			return fmt.Errorf("set tag %q on %s/%s: %w", key, v.ModelName, v.Version, err)
		}
	}
	return nil
}

func (m *MLflow) setModelVersionTag(ctx context.Context, name, version, key, value string) error {
	body := map[string]string{"name": name, "version": version, "key": key, "value": value}
	return m.post(ctx, "/api/2.0/mlflow/model-versions/set-tag", body)
}

// orUnknown mirrors the registry package: an empty verdict reads as Unknown.
func orUnknown(v string) string {
	if v == "" {
		return securityv1alpha1.VerdictUnknown
	}
	return v
}

// --- HTTP plumbing ---

func (m *MLflow) get(ctx context.Context, apiPath string, query url.Values, out any) error {
	endpoint := m.baseURL + apiPath
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	m.authorize(req)
	return m.do(req, out)
}

func (m *MLflow) post(ctx context.Context, apiPath string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.baseURL+apiPath, strings.NewReader(string(encoded)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	m.authorize(req)
	return m.do(req, nil)
}

func (m *MLflow) do(req *http.Request, out any) error {
	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d: %s", req.Method, req.URL.Path, resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode %s: %w", req.URL.Path, err)
	}
	return nil
}

func (m *MLflow) authorize(req *http.Request) {
	if m.token != "" {
		req.Header.Set("Authorization", "Bearer "+m.token)
	}
}

// pathEscape percent-escapes each segment of an artifact path while keeping the
// slashes that separate them.
func pathEscape(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return path.Join(parts...)
}
