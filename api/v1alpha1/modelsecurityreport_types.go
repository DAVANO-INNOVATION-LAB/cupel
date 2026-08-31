package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ModelSecurityReportSpec identifies the model version this report covers.
type ModelSecurityReportSpec struct {
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	// +optional
	Artifact ArtifactRef `json:"artifact,omitempty"`
	// ScanRef names the ArtifactScan that produced this report.
	// +optional
	ScanRef string `json:"scanRef,omitempty"`
}

// ModelSecurityReportStatus is the consolidated security posture of a
// model version. The admission webhook reads this to gate deployments.
type ModelSecurityReportStatus struct {
	// +kubebuilder:validation:Enum=Approved;Quarantined;ReviewRequired;Unknown
	// +optional
	Verdict string `json:"verdict,omitempty"`
	// RiskScore is 0 (clean) to 100 (critical risk).
	// +optional
	RiskScore int32 `json:"riskScore,omitempty"`
	// +kubebuilder:validation:Enum=Clean;Detected;Unknown
	// +optional
	Malware string `json:"malware,omitempty"`
	// +kubebuilder:validation:Enum=Clean;Detected;Unknown
	// +optional
	Secrets string `json:"secrets,omitempty"`
	// +optional
	CVEs SeverityCounts `json:"cves,omitempty"`
	// Unexamined counts the findings reporting that part of the artifact was
	// never read, carried up from the scan so the admission gate can see it.
	//
	// Whether an unexamined artifact is refused is the scan policy's call
	// (ArtifactScanPolicy.blockUnexamined). What this field settles is
	// narrower and applies whichever way that is set: without it an approval
	// over a partially-read artifact is byte-for-byte an approval over a fully
	// read one, so the gate could not tell them apart and neither could the
	// audit trail it writes. A verdict is a statement about what was examined,
	// and it has to carry how much that was.
	// +optional
	Unexamined SeverityCounts `json:"unexamined,omitempty"`
	// SBOMRef names the ArtifactScanReport containing the SBOM.
	// +optional
	SBOMRef string `json:"sbomRef,omitempty"`
	// AIBOMRef names the ArtifactScanReport containing the AI bill of
	// materials — the description of the model itself, as opposed to the
	// packages around it. It is a separate field rather than a reuse of
	// SBOMRef because the two documents describe different things and a
	// reader asking for one must not be handed the other.
	// +optional
	AIBOMRef string `json:"aibomRef,omitempty"`
	// +optional
	SignatureVerified bool `json:"signatureVerified,omitempty"`
	// +optional
	Scanners []ScannerResult `json:"scanners,omitempty"`
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`
	// ApprovedEnvironments lists environments this version is promoted to
	// (dev, stage, prod), managed via PromotionRequests.
	// +optional
	ApprovedEnvironments []string `json:"approvedEnvironments,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=msr
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelName`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.modelVersion`
// +kubebuilder:printcolumn:name="Verdict",type=string,JSONPath=`.status.verdict`
// +kubebuilder:printcolumn:name="Risk",type=integer,JSONPath=`.status.riskScore`
// +kubebuilder:printcolumn:name="Malware",type=string,JSONPath=`.status.malware`
// +kubebuilder:printcolumn:name="Last Scan",type=date,JSONPath=`.status.lastScanTime`

// ModelSecurityReport is the consolidated security posture of a model version.
type ModelSecurityReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ModelSecurityReportSpec `json:"spec,omitempty"`
	// +optional
	Status ModelSecurityReportStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ModelSecurityReportList contains a list of ModelSecurityReport.
type ModelSecurityReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ModelSecurityReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ModelSecurityReport{}, &ModelSecurityReportList{})
}
