package modelsource

import (
	"context"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

func TestDeclaredListsWhatTheSpecNames(t *testing.T) {
	src := NewDeclaredFromSpec([]securityv1alpha1.DeclaredModel{
		{Name: "fraud", Version: "3", URI: "s3://bucket/fraud-3.safetensors", Format: "safetensors"},
		{Name: "triage", Version: "1", URI: "oci://registry.example.com/triage:1"},
	}, nil)

	got, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listed %d versions, want 2", len(got))
	}
	if got[0].ModelName != "fraud" || got[0].Version != "3" {
		t.Errorf("first version is %s/%s, want fraud/3", got[0].ModelName, got[0].Version)
	}
	if got[0].Artifact.URI != "s3://bucket/fraud-3.safetensors" {
		t.Errorf("artifact URI is %q", got[0].Artifact.URI)
	}
	if got[0].Artifact.Format != "safetensors" {
		t.Errorf("declared format is %q, want safetensors", got[0].Artifact.Format)
	}
	// Format is advisory and may be omitted; the scanner reads the bytes.
	if got[1].Artifact.Format != "" {
		t.Errorf("second version invented a format %q", got[1].Artifact.Format)
	}
}

// An empty spec is a source holding nothing, not a source that failed. The
// distinction matters: a connector that reported an error here would go
// Degraded for being correctly configured and empty.
func TestDeclaredEmptyIsNotAnError(t *testing.T) {
	got, err := NewDeclaredFromSpec(nil, nil).List(context.Background())
	if err != nil {
		t.Fatalf("empty spec returned an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("listed %d versions from an empty spec", len(got))
	}
}

// List hands out a copy. A caller that mutates the result must not rewrite
// what the connector will report on its next reconcile.
func TestDeclaredListDoesNotAliasItsBacking(t *testing.T) {
	src := NewDeclaredFromSpec([]securityv1alpha1.DeclaredModel{
		{Name: "fraud", Version: "3", URI: "s3://bucket/m.bin"},
	}, nil)

	first, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	first[0].ModelName = "mutated"

	second, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if second[0].ModelName != "fraud" {
		t.Errorf("mutating a listed version changed the source to %q", second[0].ModelName)
	}
}

// A URI no resolver understands must fail at Resolve with the URI named,
// rather than staging nothing and letting the scan report a clean empty dir.
func TestDeclaredResolveRefusesAnUnknownScheme(t *testing.T) {
	src := NewDeclaredFromSpec([]securityv1alpha1.DeclaredModel{
		{Name: "m", Version: "1", URI: "carrier-pigeon://nowhere/m.bin"},
	}, nil)

	versions, err := src.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := src.Resolve(context.Background(), versions[0], t.TempDir()); err == nil {
		t.Fatal("Resolve accepted a scheme no resolver supports")
	}
}

// WriteBack succeeds because there is nothing upstream to annotate. A verdict
// that was reached and recorded on the report has not failed just because the
// list it came from is static.
func TestDeclaredWriteBackIsANoOp(t *testing.T) {
	src := NewDeclaredFromSpec([]securityv1alpha1.DeclaredModel{
		{Name: "m", Version: "1", URI: "s3://b/m.bin"},
	}, nil)
	versions, _ := src.List(context.Background())
	if err := src.WriteBack(context.Background(), versions[0], Verdict{Verdict: "Approved"}); err != nil {
		t.Errorf("WriteBack on a declared source: %v", err)
	}
}

func TestDeclaredName(t *testing.T) {
	if got := NewDeclared(nil, nil).Name(); got != "declared" {
		t.Errorf("Name() = %q, want declared", got)
	}
}
