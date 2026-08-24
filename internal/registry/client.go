// Package registry is a client for the OpenShift AI (Kubeflow) Model Registry
// REST API. Cupel uses it as the primary integration point: it discovers
// registered models and versions, resolves artifact locations, and writes
// security summaries back as custom properties.
package registry

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIPath is the versioned base path of the Model Registry REST API.
const APIPath = "/api/model_registry/v1alpha3"

// Client talks to a single Model Registry instance.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Options configure a Client.
type Options struct {
	BaseURL               string
	Token                 string
	InsecureSkipTLSVerify bool
	Timeout               time.Duration
}

// New returns a Client for the given registry.
func New(opts Options) *Client {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	// Clone the default transport when it is the stdlib one, but never assume
	// it: an imported package can replace http.DefaultTransport, and an
	// unchecked assertion would panic the operator at startup.
	transport := &http.Transport{}
	if def, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = def.Clone()
	}
	if opts.InsecureSkipTLSVerify {
		// Opt-in per connector, for registries behind an internal CA that the
		// operator's trust store does not carry. Off unless a CR asks for it.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit per-connector opt-in
	}
	return &Client{
		baseURL: strings.TrimSuffix(opts.BaseURL, "/"),
		token:   opts.Token,
		http:    &http.Client{Timeout: timeout, Transport: transport},
	}
}

// RegisteredModel is a model registered in the Model Registry.
type RegisteredModel struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	Owner            string                   `json:"owner,omitempty"`
	State            string                   `json:"state,omitempty"`
	CustomProperties map[string]MetadataValue `json:"customProperties,omitempty"`
}

// ModelVersion is a version of a registered model.
type ModelVersion struct {
	ID                       string                   `json:"id"`
	Name                     string                   `json:"name"`
	RegisteredModelID        string                   `json:"registeredModelId"`
	Description              string                   `json:"description,omitempty"`
	Author                   string                   `json:"author,omitempty"`
	State                    string                   `json:"state,omitempty"`
	CreateTimeSinceEpoch     string                   `json:"createTimeSinceEpoch,omitempty"`
	LastUpdateTimeSinceEpoch string                   `json:"lastUpdateTimeSinceEpoch,omitempty"`
	CustomProperties         map[string]MetadataValue `json:"customProperties,omitempty"`
}

// ModelArtifact points at the stored bytes of a model version.
type ModelArtifact struct {
	ID                 string                   `json:"id"`
	Name               string                   `json:"name,omitempty"`
	ArtifactType       string                   `json:"artifactType,omitempty"`
	URI                string                   `json:"uri,omitempty"`
	ModelFormatName    string                   `json:"modelFormatName,omitempty"`
	ModelFormatVersion string                   `json:"modelFormatVersion,omitempty"`
	StorageKey         string                   `json:"storageKey,omitempty"`
	StoragePath        string                   `json:"storagePath,omitempty"`
	ServiceAccountName string                   `json:"serviceAccountName,omitempty"`
	CustomProperties   map[string]MetadataValue `json:"customProperties,omitempty"`
}

// MetadataValue is the registry's tagged-union custom property value.
type MetadataValue struct {
	MetadataType string  `json:"metadataType"`
	StringValue  string  `json:"string_value,omitempty"`
	IntValue     string  `json:"int_value,omitempty"`
	DoubleValue  float64 `json:"double_value,omitempty"`
	BoolValue    bool    `json:"bool_value,omitempty"`
}

// StringProperty builds a string-valued custom property.
func StringProperty(v string) MetadataValue {
	return MetadataValue{MetadataType: "MetadataStringValue", StringValue: v}
}

// IntProperty builds an int-valued custom property. The registry encodes
// integers as strings.
func IntProperty(v int64) MetadataValue {
	return MetadataValue{MetadataType: "MetadataIntValue", IntValue: fmt.Sprintf("%d", v)}
}

// BoolProperty builds a bool-valued custom property.
func BoolProperty(v bool) MetadataValue {
	return MetadataValue{MetadataType: "MetadataBoolValue", BoolValue: v}
}

type listResponse[T any] struct {
	Items         []T    `json:"items"`
	NextPageToken string `json:"nextPageToken"`
	PageSize      int32  `json:"pageSize"`
	Size          int32  `json:"size"`
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	endpoint := c.baseURL + APIPath + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Method: method, Path: path, Body: string(payload)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	return nil
}

// APIError is a non-2xx response from the registry.
type APIError struct {
	Status int
	Method string
	Path   string
	Body   string
}

func (e *APIError) Error() string {
	body := e.Body
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	return fmt.Sprintf("model registry %s %s: status %d: %s", e.Method, e.Path, e.Status, body)
}

// NotFound reports whether the error is a 404 from the registry.
//
// errors.As rather than a hand-rolled unwrap loop: the loop missed errors
// joined with errors.Join or a multi-verb fmt.Errorf, whose Unwrap returns
// []error. A missed 404 reads as a hard failure and stalls a reconcile.
func NotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusNotFound
	}
	return false
}

func paginate[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	token := ""
	for {
		q := url.Values{}
		q.Set("pageSize", "100")
		if token != "" {
			q.Set("nextPageToken", token)
		}
		var page listResponse[T]
		if err := c.do(ctx, http.MethodGet, path, q, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextPageToken == "" || len(page.Items) == 0 {
			return all, nil
		}
		token = page.NextPageToken
	}
}

// Ping verifies connectivity and authentication against the registry.
func (c *Client) Ping(ctx context.Context) error {
	q := url.Values{}
	q.Set("pageSize", "1")
	var page listResponse[RegisteredModel]
	return c.do(ctx, http.MethodGet, "/registered_models", q, nil, &page)
}

// ListRegisteredModels returns every registered model.
func (c *Client) ListRegisteredModels(ctx context.Context) ([]RegisteredModel, error) {
	return paginate[RegisteredModel](ctx, c, "/registered_models")
}

// ListModelVersions returns every version of a registered model.
func (c *Client) ListModelVersions(ctx context.Context, modelID string) ([]ModelVersion, error) {
	return paginate[ModelVersion](ctx, c, fmt.Sprintf("/registered_models/%s/versions", url.PathEscape(modelID)))
}

// ListArtifacts returns the artifacts attached to a model version.
func (c *Client) ListArtifacts(ctx context.Context, versionID string) ([]ModelArtifact, error) {
	return paginate[ModelArtifact](ctx, c, fmt.Sprintf("/model_versions/%s/artifacts", url.PathEscape(versionID)))
}

// GetModelVersion fetches a single model version.
func (c *Client) GetModelVersion(ctx context.Context, versionID string) (*ModelVersion, error) {
	var mv ModelVersion
	if err := c.do(ctx, http.MethodGet, "/model_versions/"+url.PathEscape(versionID), nil, nil, &mv); err != nil {
		return nil, err
	}
	return &mv, nil
}

// PatchModelVersionProperties merges custom properties into a model version.
// Cupel writes only summary security metadata here; detailed findings stay in
// ArtifactScanReport resources inside the cluster.
func (c *Client) PatchModelVersionProperties(ctx context.Context, versionID string, props map[string]MetadataValue) error {
	body := map[string]any{"customProperties": props}
	return c.do(ctx, http.MethodPatch, "/model_versions/"+url.PathEscape(versionID), nil, body, nil)
}
