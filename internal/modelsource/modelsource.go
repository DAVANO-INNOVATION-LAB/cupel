// Package modelsource abstracts the systems that hold model versions and can
// carry a security verdict — the OpenShift AI Model Registry, MLflow, and
// whatever comes next — behind one interface.
//
// A Source is deliberately not a storage backend. internal/resolver already
// abstracts where the *bytes* live (S3, OCI, PVC); a Source abstracts where a
// model is *declared and tracked*. The two compose: a Source enumerates model
// versions and hands each one's artifact URI to Resolve, which stages the
// bytes so the same inspector and policy engine run regardless of origin.
//
// The three operations are the whole contract:
//
//	List       discover the model versions a source currently holds
//	Resolve    stage one version's bytes onto local disk for scanning
//	WriteBack  record the verdict on the version, in the source's own metadata
//
// Registry scanning and MLflow scanning are then the same pipeline with a
// different Source — one spine, many triggers.
package modelsource

import (
	"context"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
)

// Version is a scannable model version discovered in a Source.
type Version struct {
	// ModelName and Version identify the model within the source, as a human
	// reads it. Together they name what a verdict is written back onto.
	ModelName string
	Version   string

	// VersionID is the source's opaque handle for this version, used by
	// WriteBack when it differs from (ModelName, Version). Sources that key
	// write-back on name+version may leave it empty.
	VersionID string

	// Artifact locates the bytes and declares the format the source believes
	// them to be. Its URI is what Resolve stages.
	Artifact securityv1alpha1.ArtifactRef

	// Labels carries source-native identifiers (MLflow run id and stage,
	// registry model id) for traceability. Never load-bearing for a scan.
	Labels map[string]string
}

// Verdict is the security outcome a scan produced, in the shape a Source
// writes back. It is intentionally small: the detailed findings stay in the
// scanning system, and only the summary a human needs at the source travels.
type Verdict struct {
	// Verdict is Approved, Quarantined, or ReviewRequired.
	Verdict string
	// RiskScore is 0 (clean) to 100 (critical).
	RiskScore int32
	// Malware and Secrets are Clean, Detected, or Unknown.
	Malware string
	Secrets string
	// ScanTime is when the verdict was reached.
	ScanTime time.Time
	// ReportRef is an optional pointer back to the full report (a CR name, a
	// URL); sources that can render a link use it.
	ReportRef string
}

// Source is a system that holds model versions and accepts a security verdict.
// Implementations are constructed with their own configuration (endpoint,
// credentials) and must be safe for sequential use by one reconcile loop.
type Source interface {
	// Name identifies the implementation, e.g. "mlflow" or "model-registry".
	// It is stable and used in logs, labels, and metrics.
	Name() string

	// List enumerates the model versions the source currently exposes. It is
	// the discovery half of the pipeline; an empty slice with a nil error
	// means the source is reachable but holds nothing to scan.
	List(ctx context.Context) ([]Version, error)

	// Resolve stages the bytes of one version into destDir and returns the
	// staged artifact. A Source may satisfy this by delegating to
	// internal/resolver (when the artifact URI is a storage URI) or by using
	// its own artifact API (as MLflow does through its artifact proxy).
	Resolve(ctx context.Context, v Version, destDir string) (*resolver.Artifact, error)

	// WriteBack records the verdict on the version in the source's own
	// metadata, so a user sees it without leaving the source's UI. It must be
	// idempotent: writing the same verdict twice is a no-op-equivalent.
	WriteBack(ctx context.Context, v Version, verdict Verdict) error
}
