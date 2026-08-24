package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ControlResult is the assessment of one framework control for one model
// version.
type ControlResult struct {
	// ControlID is the framework subcategory, e.g. "MEASURE 2.7".
	ControlID string `json:"controlID"`
	// Function is the AI RMF core function the control belongs to.
	// +optional
	Function string `json:"function,omitempty"`
	// Status of the control.
	// +kubebuilder:validation:Enum=Satisfied;PartiallySatisfied;NotSatisfied;Attested;AttestationRequired;NotApplicable
	Status string `json:"status"`
	// Automation records how much of this control Cupel can evidence at all:
	// Full, Partial, or None. A control marked None is never satisfied by a
	// scan — only by an attestation.
	// +kubebuilder:validation:Enum=Full;Partial;None
	// +optional
	Automation string `json:"automation,omitempty"`
	// Reason explains the status in terms an auditor can follow.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Evidence lists the Cupel signals observed for this control.
	// +optional
	Evidence []string `json:"evidence,omitempty"`
	// AttestedBy names who closed the control, when an attestation applied.
	// +optional
	AttestedBy string `json:"attestedBy,omitempty"`
	// Warning surfaces something an auditor should examine even when the
	// control is not open.
	// +optional
	Warning string `json:"warning,omitempty"`
}

// FunctionSummary counts control outcomes within one core function.
type FunctionSummary struct {
	Function string `json:"function"`
	// +optional
	Satisfied int32 `json:"satisfied,omitempty"`
	// +optional
	Attested int32 `json:"attested,omitempty"`
	// +optional
	Partial int32 `json:"partial,omitempty"`
	// +optional
	AwaitingAttestation int32 `json:"awaitingAttestation,omitempty"`
	// +optional
	NotSatisfied int32 `json:"notSatisfied,omitempty"`
	// +optional
	NotApplicable int32 `json:"notApplicable,omitempty"`
}

// ComplianceReportSpec identifies what was assessed.
type ComplianceReportSpec struct {
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	// Framework assessed against.
	Framework string `json:"framework"`
	// ProfileRef names the ComplianceProfile used.
	// +optional
	ProfileRef string `json:"profileRef,omitempty"`
	// ReportRef names the ModelSecurityReport the evidence came from.
	// +optional
	ReportRef string `json:"reportRef,omitempty"`
}

// ComplianceReportStatus is the assessment outcome.
type ComplianceReportStatus struct {
	// Conformant reports whether no control is left open. It is deliberately
	// strict: partial technical coverage without attestation counts as open.
	// +optional
	Conformant bool `json:"conformant,omitempty"`

	// Automatable records how much of the framework any scanner could
	// evidence, independent of this particular model. It is reported so the
	// conformance numbers are read in context rather than as a claim that
	// Cupel assessed the whole framework.
	// +optional
	AutomatableFull int32 `json:"automatableFull,omitempty"`
	// +optional
	AutomatablePartial int32 `json:"automatablePartial,omitempty"`
	// +optional
	AttestationOnly int32 `json:"attestationOnly,omitempty"`
	// +optional
	TotalControls int32 `json:"totalControls,omitempty"`

	// +optional
	Summary []FunctionSummary `json:"summary,omitempty"`
	// Controls holds the per-control results.
	// +optional
	Controls []ControlResult `json:"controls,omitempty"`

	// UnmeasuredCharacteristics lists the trustworthiness characteristics
	// this assessment did not evaluate. AI RMF MEASURE 1.1 requires that
	// what cannot be measured is documented, so this is a first-class field
	// rather than a footnote.
	// +optional
	UnmeasuredCharacteristics []string `json:"unmeasuredCharacteristics,omitempty"`

	// +optional
	OpenControlCount int32 `json:"openControlCount,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	AssessedAt *metav1.Time `json:"assessedAt,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=crep
// +kubebuilder:printcolumn:name="Model",type=string,JSONPath=`.spec.modelName`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.spec.modelVersion`
// +kubebuilder:printcolumn:name="Framework",type=string,JSONPath=`.spec.framework`
// +kubebuilder:printcolumn:name="Conformant",type=boolean,JSONPath=`.status.conformant`
// +kubebuilder:printcolumn:name="Open",type=integer,JSONPath=`.status.openControlCount`
// +kubebuilder:printcolumn:name="Assessed",type=date,JSONPath=`.status.assessedAt`

// ComplianceReport is a model version assessed against a governance framework.
type ComplianceReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ComplianceReportSpec `json:"spec,omitempty"`
	// +optional
	Status ComplianceReportStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceReportList contains a list of ComplianceReport.
type ComplianceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ComplianceReport{}, &ComplianceReportList{})
}
