package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KeylessIdentity describes a Sigstore keyless signing identity.
type KeylessIdentity struct {
	// Issuer is the OIDC issuer URL (e.g. https://token.actions.githubusercontent.com).
	Issuer string `json:"issuer"`
	// Subject is the certificate identity (email or workflow URI). Supports
	// a trailing glob.
	Subject string `json:"subject"`
}

// TrustedPublisherSpec declares a publisher whose signatures Cupel trusts.
type TrustedPublisherSpec struct {
	// DisplayName for the console.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// CosignPublicKey is a PEM-encoded public key for key-based verification.
	// +optional
	CosignPublicKey string `json:"cosignPublicKey,omitempty"`
	// KeylessIdentity for Sigstore keyless verification.
	// +optional
	KeylessIdentity *KeylessIdentity `json:"keylessIdentity,omitempty"`
	// URIPrefixes limits which artifact URIs this publisher may sign
	// (e.g. oci://registry.internal/models/). Empty means any.
	// +optional
	URIPrefixes []string `json:"uriPrefixes,omitempty"`
}

// TrustedPublisherStatus reports validation of the publisher config.
type TrustedPublisherStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Display Name",type=string,JSONPath=`.spec.displayName`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TrustedPublisher declares a signer whose model artifacts are trusted.
type TrustedPublisher struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TrustedPublisherSpec `json:"spec,omitempty"`
	// +optional
	Status TrustedPublisherStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustedPublisherList contains a list of TrustedPublisher.
type TrustedPublisherList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustedPublisher `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TrustedPublisher{}, &TrustedPublisherList{})
}
