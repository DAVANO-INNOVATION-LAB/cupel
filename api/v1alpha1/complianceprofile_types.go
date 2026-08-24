package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ControlAttestation records a human statement closing a control that no
// scanner can observe — that staff are trained, that leadership accepted a
// risk, that a diverse team reviewed a decision.
type ControlAttestation struct {
	// ControlID is the framework subcategory, e.g. "GOVERN 2.2".
	ControlID string `json:"controlID"`

	// Statement is what is being attested.
	// +kubebuilder:validation:MinLength=1
	Statement string `json:"statement"`

	// AttestedBy names the accountable person or team. An unattributed
	// attestation is not an attestation, so this is required.
	// +kubebuilder:validation:MinLength=1
	AttestedBy string `json:"attestedBy"`

	// AttestedAt is when the statement was made.
	// +optional
	AttestedAt *metav1.Time `json:"attestedAt,omitempty"`

	// ExpiresAt bounds the attestation. Omitting it is accepted but reported
	// as a warning: an attestation that never expires is never re-examined.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// EvidenceURI points at supporting documentation — a policy document, a
	// training record, a signed approval.
	// +optional
	EvidenceURI string `json:"evidenceURI,omitempty"`
}

// ControlExclusion scopes a control out of a profile.
type ControlExclusion struct {
	// ControlID to exclude.
	ControlID string `json:"controlID"`
	// Justification for the exclusion. Required — an unexplained exclusion
	// is indistinguishable from an oversight, so Cupel rejects it.
	// +kubebuilder:validation:MinLength=1
	Justification string `json:"justification"`
}

// ComplianceProfileSpec declares a governance framework to report against and
// carries the organizational attestations Cupel cannot produce itself.
type ComplianceProfileSpec struct {
	// Framework to assess against.
	// +kubebuilder:validation:Enum=nist-ai-rmf-1.0
	// +kubebuilder:default=nist-ai-rmf-1.0
	Framework string `json:"framework"`

	// ModelSelector limits the profile to models whose name matches one of
	// these globs. Empty applies it to every model in the namespace.
	// +optional
	ModelSelector []string `json:"modelSelector,omitempty"`

	// Attestations close controls that have no technical evidence path.
	// +optional
	Attestations []ControlAttestation `json:"attestations,omitempty"`

	// Exclusions scope controls out, each with a justification.
	// +optional
	Exclusions []ControlExclusion `json:"exclusions,omitempty"`

	// BlockOnOpenControls makes the admission gate refuse deployment while
	// any control remains open. Off by default: framework conformance is a
	// governance posture, and wiring it to admission on day one would block
	// every model in the cluster.
	// +optional
	BlockOnOpenControls bool `json:"blockOnOpenControls,omitempty"`
}

// ComplianceProfileStatus reports profile-level validity.
type ComplianceProfileStatus struct {
	// +optional
	AttestedControls int32 `json:"attestedControls,omitempty"`
	// +optional
	ExcludedControls int32 `json:"excludedControls,omitempty"`
	// ExpiredAttestations counts attestations past their expiry, which stop
	// closing their control.
	// +optional
	ExpiredAttestations int32 `json:"expiredAttestations,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cprof
// +kubebuilder:printcolumn:name="Framework",type=string,JSONPath=`.spec.framework`
// +kubebuilder:printcolumn:name="Attested",type=integer,JSONPath=`.status.attestedControls`
// +kubebuilder:printcolumn:name="Expired",type=integer,JSONPath=`.status.expiredAttestations`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ComplianceProfile declares a governance framework and its attestations.
type ComplianceProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ComplianceProfileSpec `json:"spec,omitempty"`
	// +optional
	Status ComplianceProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceProfileList contains a list of ComplianceProfile.
type ComplianceProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceProfile{}, &ComplianceProfileList{})
}
