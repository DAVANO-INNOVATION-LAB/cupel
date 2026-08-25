package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuditRecordSpec is one link in the tamper-evident decision log.
//
// Every field is part of the hash preimage. There is deliberately no status
// subresource carrying anything hashed: a record is written once and never
// updated, and RBAC should grant create without update or delete. The chain
// makes edits evident even to someone who bypasses that.
type AuditRecordSpec struct {
	// Seq is the position in the chain, starting at 1.
	Seq int64 `json:"seq"`
	// Time the event was recorded, in UTC to second precision.
	Time metav1.Time `json:"time"`
	// Type of event (RiskAccepted, VerdictIssued, DeploymentBlocked, ...).
	Type string `json:"type"`
	// Subject the event concerns, as "model/version".
	Subject string `json:"subject"`
	// Actor is the authenticated identity responsible, or "system".
	Actor string `json:"actor"`
	// Detail carries event-specific fields.
	// +optional
	Detail map[string]string `json:"detail,omitempty"`
	// PrevHash links to the preceding record.
	PrevHash string `json:"prevHash"`
	// Hash commits to every field above.
	Hash string `json:"hash"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Seq",type=integer,JSONPath=`.spec.seq`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Subject",type=string,JSONPath=`.spec.subject`
// +kubebuilder:printcolumn:name="Actor",type=string,JSONPath=`.spec.actor`
// +kubebuilder:printcolumn:name="Time",type=date,JSONPath=`.spec.time`

// AuditRecord is an immutable entry in the security decision log.
type AuditRecord struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AuditRecordSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AuditRecordList contains a list of AuditRecord.
type AuditRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditRecord `json:"items"`
}

// AuditCheckpointSpec commits to the state of the log at a moment.
//
// This is what makes tail truncation detectable. Anchoring it outside the
// cluster — in a signed evidence bundle, or an auditor's own records — is what
// makes the log tamper-evident against someone who controls the cluster.
type AuditCheckpointSpec struct {
	// Length is how many records the chain held.
	Length int64 `json:"length"`
	// Head is the hash of the final record.
	Head string `json:"head"`
	// Time the checkpoint was taken.
	Time metav1.Time `json:"time"`

	// ArchivedLength is how many records from the front of the chain have been
	// written out of the cluster and deleted from it. Zero means the whole
	// chain is still here.
	//
	// Length above stays the length of the whole chain, archived records
	// included, so a checkpoint means the same thing before and after an
	// archive runs.
	// +optional
	ArchivedLength int64 `json:"archivedLength,omitempty"`
	// ArchivedHead is the hash of the last archived record: the point the
	// records still in the cluster attach to.
	// +optional
	ArchivedHead string `json:"archivedHead,omitempty"`
	// ArchiveLocation is where the archived records were written, so a reader
	// who needs the whole chain knows there is more of it and where to look.
	// +optional
	ArchiveLocation string `json:"archiveLocation,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Length",type=integer,JSONPath=`.spec.length`
// +kubebuilder:printcolumn:name="Head",type=string,JSONPath=`.spec.head`
// +kubebuilder:printcolumn:name="Archived",type=integer,JSONPath=`.spec.archivedLength`
// +kubebuilder:printcolumn:name="Time",type=date,JSONPath=`.spec.time`

// AuditCheckpoint publishes the head of the audit chain.
type AuditCheckpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AuditCheckpointSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AuditCheckpointList contains a list of AuditCheckpoint.
type AuditCheckpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditCheckpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&AuditRecord{}, &AuditRecordList{},
		&AuditCheckpoint{}, &AuditCheckpointList{},
	)
}
