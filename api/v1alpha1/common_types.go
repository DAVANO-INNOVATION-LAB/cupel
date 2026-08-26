package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ArtifactRef identifies a model artifact and where it lives.
type ArtifactRef struct {
	// URI of the artifact. Supported schemes: s3://bucket/path,
	// oci://registry/repo:tag, pvc://claim-name/path,
	// modelcar://registry/repo@sha256:..., https://...
	URI string `json:"uri"`

	// Digest is the content digest of the artifact, when known.
	// +optional
	Digest string `json:"digest,omitempty"`

	// MediaType of the artifact, when known.
	// +optional
	MediaType string `json:"mediaType,omitempty"`

	// Format is the model format reported by the registry
	// (e.g. safetensors, onnx, pickle, gguf).
	// +optional
	Format string `json:"format,omitempty"`

	// SizeBytes is the artifact size, when known.
	// +optional
	SizeBytes *int64 `json:"sizeBytes,omitempty"`
}

// SeverityCounts summarizes findings by severity.
type SeverityCounts struct {
	// +optional
	Critical int32 `json:"critical,omitempty"`
	// +optional
	High int32 `json:"high,omitempty"`
	// +optional
	Medium int32 `json:"medium,omitempty"`
	// +optional
	Low int32 `json:"low,omitempty"`
	// +optional
	Unknown int32 `json:"unknown,omitempty"`
}

// Total returns the total number of findings across severities.
func (s SeverityCounts) Total() int32 {
	return s.Critical + s.High + s.Medium + s.Low + s.Unknown
}

// ScannerResult is the per-scanner outcome of a scan.
type ScannerResult struct {
	// Scanner is the scanner name (e.g. clamav, trivy, model-inspector).
	Scanner string `json:"scanner"`

	// +kubebuilder:validation:Enum=Pending;Running;Passed;Failed;Error;Skipped
	Status string `json:"status"`

	// Findings is the total number of findings the scanner reported.
	// +optional
	Findings int32 `json:"findings,omitempty"`

	// +optional
	Severities SeverityCounts `json:"severities,omitempty"`

	// Drift counts the subset of findings reporting that the artifact's own
	// declarations disagree with its bytes — a config naming a precision the
	// tensors do not carry, an index claiming shards that are not there.
	//
	// It is a separate count rather than a severity bucket because drift is
	// gated separately: it is frequently benign (a quantized re-upload
	// carrying its original config is the common case) and occasionally the
	// only sign that an artifact is not what it claims to be. Folding it into
	// Severities would make those two indistinguishable.
	// +optional
	Drift SeverityCounts `json:"drift,omitempty"`
	// Unexamined counts the findings reporting that part of the artifact was
	// not read at all, rather than reporting something about what was in it.
	// Separate from Severities because a policy that wants to refuse an
	// artifact nobody could parse has nothing else to match on.
	// +optional
	Unexamined SeverityCounts `json:"unexamined,omitempty"`

	// Produced reports whether a scanner whose job is to emit a document
	// actually emitted one. Nil means the question does not apply.
	//
	// A bill-of-materials scanner that runs over an artifact it cannot
	// describe finds nothing and exits zero, which is byte-for-byte the same
	// result as one that described a clean model. Without this field a policy
	// requiring a bill of materials is satisfied by a scanner that produced
	// none — the gate would read as enforced and enforce nothing.
	// +optional
	Produced *bool `json:"produced,omitempty"`

	// +optional
	Message string `json:"message,omitempty"`

	// ReportRef names the ArtifactScanReport holding detailed findings.
	// +optional
	ReportRef string `json:"reportRef,omitempty"`

	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}

// Finding is a single detailed security finding.
type Finding struct {
	// ID is the finding identifier (e.g. CVE-2025-1234, signature name).
	// +optional
	ID string `json:"id,omitempty"`
	// +optional
	Title string `json:"title,omitempty"`
	// +kubebuilder:validation:Enum=Critical;High;Medium;Low;Unknown
	// +optional
	Severity string `json:"severity,omitempty"`
	// Category of the finding (malware, cve, secret, license, model, provenance).
	// +optional
	Category string `json:"category,omitempty"`
	// Location within the artifact (file path, layer, tensor name).
	// +optional
	Location string `json:"location,omitempty"`
	// +optional
	Description string `json:"description,omitempty"`
}

// SecretKeyRef points at a key inside a Secret in the same namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	// +kubebuilder:default=token
	// +optional
	Key string `json:"key,omitempty"`
}

// Verdict values shared across resources.
const (
	VerdictApproved       = "Approved"
	VerdictQuarantined    = "Quarantined"
	VerdictReviewRequired = "ReviewRequired"
	VerdictUnknown        = "Unknown"
)
