package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ModelRegistryConnectorSpec defines a connection to an OpenShift AI
// (Kubeflow) Model Registry instance to watch for models to scan.
type ModelRegistryConnectorSpec struct {
	// Type selects the registry implementation behind this connector. Both
	// are driven through the same ModelSource interface, so registry
	// scanning is one pipeline with several front doors rather than a
	// separate integration per vendor.
	//
	//	KubeflowModelRegistry  the OpenShift AI / Kubeflow Model Registry
	//	MLflow                 an MLflow tracking server's model registry
	//	Declared               the versions listed in spec.models, wherever
	//	                       they are tracked upstream
	//
	// Declared is the general case. The first two speak one registry's REST
	// dialect each; an organisation running neither had no way in, because the
	// pipeline was pluggable in the code and closed at the API. A declared
	// connector names versions and where their bytes live, and the bytes may
	// use any scheme the resolvers support, so the registry a team happens to
	// run stops being a question Cupel answers on their behalf.
	//
	// +kubebuilder:validation:Enum=KubeflowModelRegistry;MLflow;Declared
	// +kubebuilder:default=KubeflowModelRegistry
	// +optional
	Type string `json:"type,omitempty"`

	// RescanInterval re-scans a version this long after its last scan.
	//
	// A verdict is a statement about what was known when the scan ran. CVE
	// databases move, so an artifact that passed last quarter has not been
	// vouched for today — but nothing rescanned, so every verdict aged
	// silently and a stale pass looked identical to a fresh one. Zero keeps
	// the old behaviour of scanning each version exactly once.
	// +optional
	RescanInterval *metav1.Duration `json:"rescanInterval,omitempty"`

	// RegistryURL is the base URL of the Model Registry REST API,
	// e.g. https://model-registry.rhoai-model-registries.svc:8080
	//
	// Required for every type except Declared, which has no upstream API to
	// call. The reconciler enforces that rather than the schema, so a
	// declared connector is not made to invent a URL nobody dials.
	// +optional
	RegistryURL string `json:"registryURL,omitempty"`

	// Models lists the versions a Declared connector scans. Ignored by the
	// other types.
	//
	// The list is the whole discovery mechanism: a version nobody lists is a
	// version nobody scans. Everything downstream of discovery — scanning,
	// policy, promotion, admission — is the same path the built-in registries
	// take.
	// +optional
	Models []DeclaredModel `json:"models,omitempty"`

	// AuthSecretRef references a Secret containing a bearer token used to
	// authenticate against the registry.
	// +optional
	AuthSecretRef *SecretKeyRef `json:"authSecretRef,omitempty"`

	// InsecureSkipTLSVerify disables TLS certificate verification.
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// PollInterval controls how often the registry is polled for new
	// models and versions. Defaults to 1m.
	// +optional
	PollInterval *metav1.Duration `json:"pollInterval,omitempty"`

	// PolicyRef names the ArtifactScanPolicy applied to scans created by
	// this connector. Empty selects the built-in default scanner set.
	// +optional
	PolicyRef string `json:"policyRef,omitempty"`

	// IncludeModels restricts scanning to registered models whose name
	// matches one of these globs. Empty means all models.
	// +optional
	IncludeModels []string `json:"includeModels,omitempty"`

	// WriteBack controls whether scan summaries are written back into the
	// Model Registry as custom properties. Defaults to true.
	// +optional
	WriteBack *bool `json:"writeBack,omitempty"`
}

// DeclaredModel is one model version listed directly on a Declared connector.
type DeclaredModel struct {
	// Name identifies the model, as a human reads it.
	Name string `json:"name"`

	// Version identifies the version within the model.
	Version string `json:"version"`

	// URI locates the bytes. Any scheme the resolvers support: oci://,
	// modelcar://, s3://, pvc://, hf://, mlflow://, http(s)://, kubeflow://.
	URI string `json:"uri"`

	// Format declares the artifact format the source believes the bytes to
	// be. Advisory: the scanner reads the bytes and is not bound by it.
	// +optional
	Format string `json:"format,omitempty"`
}

// ModelRegistryConnectorStatus reports sync progress.
type ModelRegistryConnectorStatus struct {
	// +kubebuilder:validation:Enum=Pending;Connected;Degraded;Error
	// +optional
	Phase string `json:"phase,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// +optional
	RegisteredModels int32 `json:"registeredModels,omitempty"`
	// +optional
	ModelVersions int32 `json:"modelVersions,omitempty"`
	// +optional
	ScansCreated int32 `json:"scansCreated,omitempty"`
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mrc
// +kubebuilder:printcolumn:name="Registry",type=string,JSONPath=`.spec.registryURL`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Models",type=integer,JSONPath=`.status.registeredModels`
// +kubebuilder:printcolumn:name="Scans",type=integer,JSONPath=`.status.scansCreated`
// +kubebuilder:printcolumn:name="Last Sync",type=date,JSONPath=`.status.lastSyncTime`

// ModelRegistryConnector connects Cupel to an OpenShift AI Model Registry.
type ModelRegistryConnector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ModelRegistryConnectorSpec `json:"spec,omitempty"`
	// +optional
	Status ModelRegistryConnectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ModelRegistryConnectorList contains a list of ModelRegistryConnector.
type ModelRegistryConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ModelRegistryConnector `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ModelRegistryConnector{}, &ModelRegistryConnectorList{})
}
