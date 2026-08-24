package controller

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/registry"
)

func TestModelReportNameIsDeterministic(t *testing.T) {
	first := ModelReportName("fraud-detector", "v1.2.0")
	second := ModelReportName("fraud-detector", "v1.2.0")

	if first != second {
		t.Fatalf("names differ across calls: %q vs %q", first, second)
	}
	if errs := validation.IsDNS1123Subdomain(first); len(errs) > 0 {
		t.Errorf("name %q is not a valid object name: %v", first, errs)
	}
}

// Registry model names are free-form and can be long or contain characters
// Kubernetes rejects. Truncation alone would collide, so long names get a
// content hash.
func TestModelReportNameHandlesHostileInput(t *testing.T) {
	cases := []struct{ name, model, version string }{
		{"long", strings.Repeat("very-long-model-name", 10), "v1"},
		{"uppercase", "Fraud_Detector", "V1.0"},
		{"spaces", "my model", "release 2"},
		{"slashes", "org/team/model", "v1"},
		{"unicode", "modèle-français", "v1"},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ModelReportName(tc.model, tc.version)
			if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
				t.Fatalf("name %q is invalid: %v", got, errs)
			}
			if len(got) > 63 {
				t.Errorf("name %q is %d chars, over the 63 limit", got, len(got))
			}
			if prior, ok := seen[got]; ok {
				t.Errorf("name %q collides with %q", got, prior)
			}
			seen[got] = tc.model + "@" + tc.version
		})
	}
}

func TestLongNamesDoNotCollide(t *testing.T) {
	base := strings.Repeat("a", 100)
	first := ModelReportName(base+"one", "v1")
	second := ModelReportName(base+"two", "v1")

	if first == second {
		t.Fatalf("two distinct long model names produced the same object name %q", first)
	}
}

func TestScanNameIsStable(t *testing.T) {
	first := scanNameFor("detector", "v1", "artifact-7")
	second := scanNameFor("detector", "v1", "artifact-7")
	other := scanNameFor("detector", "v1", "artifact-8")

	if first != second {
		t.Errorf("scan name is not stable: %q vs %q", first, second)
	}
	if first == other {
		t.Error("different artifacts produced the same scan name")
	}
}

func TestNormalizeArtifactURI(t *testing.T) {
	cases := []struct {
		name     string
		artifact registry.ModelArtifact
		want     string
	}{
		{
			name:     "full S3 URI passes through",
			artifact: registry.ModelArtifact{URI: "s3://models/fraud/v1"},
			want:     "s3://models/fraud/v1",
		},
		{
			name:     "OCI URI passes through",
			artifact: registry.ModelArtifact{URI: "oci://registry.example/models/fraud:v1"},
			want:     "oci://registry.example/models/fraud:v1",
		},
		{
			name:     "bare registry reference becomes OCI",
			artifact: registry.ModelArtifact{URI: "registry.example/models/fraud:v1"},
			want:     "oci://registry.example/models/fraud:v1",
		},
		{
			name:     "storage key and path become S3",
			artifact: registry.ModelArtifact{StorageKey: "my-bucket", StoragePath: "models/fraud/v1"},
			want:     "s3://my-bucket/models/fraud/v1",
		},
		{
			name:     "no location yields nothing to scan",
			artifact: registry.ModelArtifact{},
			want:     "",
		},
		{
			name:     "whitespace is trimmed",
			artifact: registry.ModelArtifact{URI: "  s3://models/fraud/v1  "},
			want:     "s3://models/fraud/v1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeArtifactURI(tc.artifact); got != tc.want {
				t.Errorf("normalizeArtifactURI() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMatchesIncludeList(t *testing.T) {
	cases := []struct {
		name     string
		model    string
		patterns []string
		want     bool
	}{
		{"empty list matches everything", "anything", nil, true},
		{"exact match", "fraud-detector", []string{"fraud-detector"}, true},
		{"glob match", "fraud-detector", []string{"fraud-*"}, true},
		{"no match", "recommender", []string{"fraud-*"}, false},
		{"second pattern matches", "recommender", []string{"fraud-*", "recomm*"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesIncludeList(tc.model, tc.patterns); got != tc.want {
				t.Errorf("matchesIncludeList(%q, %v) = %v, want %v", tc.model, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestScanJobNameFitsKubernetesLimit(t *testing.T) {
	name := scanJobName(strings.Repeat("x", 80), "model-inspector")

	if len(name) > 63 {
		t.Errorf("job name is %d chars, over the 63 limit", len(name))
	}
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		t.Errorf("job name %q is invalid: %v", name, errs)
	}
}
