// Package v1alpha1 contains API Schema definitions for the Cupel
// security v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=security.davano.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "security.davano.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	// nolint:staticcheck // SA1019: scheme.Builder is deprecated for dependency
	// hygiene in api packages, not for correctness. Every types file in this
	// package registers through it; moving to runtime.NewSchemeBuilder means
	// rewriting eleven registration sites, where one type quietly missed is a
	// resource the operator cannot decode at runtime.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
