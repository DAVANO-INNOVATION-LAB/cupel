package controller

import (
	"strings"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

func connector(t, url string, models ...securityv1alpha1.DeclaredModel) *securityv1alpha1.ModelRegistryConnector {
	return &securityv1alpha1.ModelRegistryConnector{
		Spec: securityv1alpha1.ModelRegistryConnectorSpec{
			Type: t, RegistryURL: url, Models: models,
		},
	}
}

// Every supported type must build. The enum on the CRD and this switch are two
// halves of one contract, and a type the API accepts but the reconciler
// rejects is a connector that goes Error for being valid.
func TestSourceForBuildsEverySupportedType(t *testing.T) {
	r := &ModelRegistryConnectorReconciler{}
	for _, tc := range []struct {
		typ, url, want string
	}{
		{SourceKubeflow, "https://registry.example.com", "model-registry"},
		{"", "https://registry.example.com", "model-registry"}, // empty defaults to Kubeflow
		{SourceMLflow, "https://mlflow.example.com", "mlflow"},
		{SourceDeclared, "", "declared"},
	} {
		src, err := r.sourceFor(connector(tc.typ, tc.url), "")
		if err != nil {
			t.Errorf("type %q: %v", tc.typ, err)
			continue
		}
		if src.Name() != tc.want {
			t.Errorf("type %q built source %q, want %q", tc.typ, src.Name(), tc.want)
		}
	}
}

// A declared connector must not be made to supply a URL nobody dials.
func TestDeclaredNeedsNoRegistryURL(t *testing.T) {
	r := &ModelRegistryConnectorReconciler{}
	src, err := r.sourceFor(connector(SourceDeclared, "", securityv1alpha1.DeclaredModel{
		Name: "fraud", Version: "3", URI: "s3://bucket/fraud.safetensors",
	}), "")
	if err != nil {
		t.Fatalf("declared connector with no registryURL: %v", err)
	}
	got, err := src.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].ModelName != "fraud" {
		t.Fatalf("declared connector listed %d versions, want fraud", len(got))
	}
}

// The schema stopped requiring registryURL so Declared could omit it. Every
// type that actually dials one is still held to it — otherwise making the
// field optional would have silently turned a rejected manifest into a
// connector that dials the empty string.
func TestTypesThatDialRequireRegistryURL(t *testing.T) {
	r := &ModelRegistryConnectorReconciler{}
	for _, typ := range []string{SourceKubeflow, SourceMLflow, ""} {
		_, err := r.sourceFor(connector(typ, ""), "")
		if err == nil {
			t.Errorf("type %q accepted an empty registryURL", typ)
			continue
		}
		if !strings.Contains(err.Error(), "spec.registryURL") {
			t.Errorf("type %q: error does not name the missing field: %v", typ, err)
		}
	}
}

// An unknown type must name every type that would have worked.
func TestUnknownTypeNamesTheAlternatives(t *testing.T) {
	r := &ModelRegistryConnectorReconciler{}
	_, err := r.sourceFor(connector("Sagemaker", "https://example.com"), "")
	if err == nil {
		t.Fatal("unknown connector type was accepted")
	}
	for _, want := range []string{SourceKubeflow, SourceMLflow, SourceDeclared} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}
