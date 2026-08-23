package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScannerSpec configures one scanner in a policy.
type ScannerSpec struct {
	// Name of the scanner (clamav, model-inspector, trivy, syft, trufflehog, ...).
	Name string `json:"name"`
	// Image overrides the built-in image for this scanner.
	// +optional
	Image string `json:"image,omitempty"`
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
	// Args overrides the scanner container arguments.
	// +optional
	Args []string `json:"args,omitempty"`
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	// TimeoutSeconds bounds the scan job. Defaults to 1800.
	// +optional
	TimeoutSeconds *int64 `json:"timeoutSeconds,omitempty"`
}

// PolicyRules are the pass/fail gates evaluated after scanning.
type PolicyRules struct {
	// MaxCriticalCVEs above which the artifact is quarantined. Nil = no limit.
	// +optional
	MaxCriticalCVEs *int32 `json:"maxCriticalCVEs,omitempty"`
	// +optional
	MaxHighCVEs *int32 `json:"maxHighCVEs,omitempty"`
	// BlockMalware quarantines on any malware finding. Defaults to true.
	// +optional
	BlockMalware *bool `json:"blockMalware,omitempty"`
	// BlockSecrets quarantines on any leaked-secret finding. Defaults to true.
	// +optional
	BlockSecrets *bool `json:"blockSecrets,omitempty"`
	// BlockUnsafeModel quarantines on a critical model-inspection finding —
	// a pickle that imports os.system, an archive that escapes its directory,
	// trust_remote_code. These execute on load, so they are as serious as
	// malware. Defaults to true.
	// +optional
	BlockUnsafeModel *bool `json:"blockUnsafeModel,omitempty"`
	// RequireSignature demands a verified Cosign signature from a TrustedPublisher.
	// +optional
	RequireSignature bool `json:"requireSignature,omitempty"`
	// RequireSBOM demands a generated SBOM before approval.
	// +optional
	RequireSBOM bool `json:"requireSBOM,omitempty"`
	// RequireAIBOM demands a generated AI bill of materials — a description
	// of the model itself — before approval. This is what the EU AI Act
	// Annex XII, the CISA/G7 minimum elements and Korea's Framework Act each
	// ask a provider to be able to produce, and it is satisfied by a
	// different scanner from RequireSBOM.
	// +optional
	RequireAIBOM bool `json:"requireAIBOM,omitempty"`
	// BlockModelDrift quarantines when the model's own declarations disagree
	// with the weights they describe at High severity or above — a config
	// advertising a parameter count, precision or architecture the tensors do
	// not implement. Defaults to false: drift is frequently benign (a
	// quantized re-upload carrying the original config is the common case),
	// so it is surfaced by default and gated on request.
	// +optional
	BlockModelDrift *bool `json:"blockModelDrift,omitempty"`
	// RequireProvenance demands verified provenance attestations.
	// +optional
	RequireProvenance bool `json:"requireProvenance,omitempty"`
	// AllowedFormats restricts model formats (e.g. safetensors, onnx, gguf).
	// +optional
	AllowedFormats []string `json:"allowedFormats,omitempty"`
	// BlockedFormats quarantines specific formats (e.g. pickle).
	// +optional
	BlockedFormats []string `json:"blockedFormats,omitempty"`
}

// ArtifactScanPolicySpec defines scanners to run and rules to enforce.
type ArtifactScanPolicySpec struct {
	// +optional
	Scanners []ScannerSpec `json:"scanners,omitempty"`
	// +optional
	Rules PolicyRules `json:"rules,omitempty"`
	// Enforcement controls admission behavior for artifacts failing this
	// policy: Enforce rejects, Warn admits with a warning, Audit only logs.
	// +kubebuilder:validation:Enum=Enforce;Warn;Audit
	// +kubebuilder:default=Enforce
	// +optional
	Enforcement string `json:"enforcement,omitempty"`
	// EnvironmentPromotion controls what an empty promotion list means when a
	// workload declares an environment.
	//
	// Require treats "promoted nowhere" as "not promoted here" and denies.
	// Ignore skips the environment check entirely when nothing has been
	// promoted, which is the behaviour for clusters that annotate an
	// environment without using PromotionRequests at all.
	//
	// Require is the default because the alternative inverts the gate: a
	// version promoted to dev is checked against prod and refused, while a
	// version promoted nowhere — never reviewed by anyone — passes. The gate
	// was weakest for exactly the artifacts with the least scrutiny.
	// +kubebuilder:validation:Enum=Require;Ignore
	// +kubebuilder:default=Require
	// +optional
	EnvironmentPromotion string `json:"environmentPromotion,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Enforcement",type=string,JSONPath=`.spec.enforcement`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ArtifactScanPolicy configures scanning and gating for model artifacts.
type ArtifactScanPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ArtifactScanPolicySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ArtifactScanPolicyList contains a list of ArtifactScanPolicy.
type ArtifactScanPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArtifactScanPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ArtifactScanPolicy{}, &ArtifactScanPolicyList{})
}
