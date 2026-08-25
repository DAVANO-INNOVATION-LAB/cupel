package policy

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

func ex(model, version string) securityv1alpha1.ArtifactException {
	return securityv1alpha1.ArtifactException{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ml"},
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			ModelName: model, ModelVersion: version,
			Reason: "reviewed", Rules: []string{"blockUnsafeModel"},
		},
	}
}

// Evaluate waives whatever rules its exceptions name without asking who they
// were written for, so everything rests on this filter. An exception that
// reaches Evaluate for the wrong model waives that model's findings using
// somebody else's approval.
func TestOnlyExceptionsForThisModelVersionApply(t *testing.T) {
	all := []securityv1alpha1.ArtifactException{
		ex("fraud", "v1"),
		ex("fraud", "v2"),
		ex("spam", "v1"),
		ex("", ""),
		ex("*", "*"),
		ex("fraud", ""),
		ex("", "v1"),
	}

	cases := []struct {
		model, version string
		want           int
	}{
		{"fraud", "v1", 1},
		{"fraud", "v2", 1},
		{"spam", "v1", 1},
		{"fraud", "v3", 0},
		{"other", "v1", 0},
		{"", "v1", 0},
		{"fraud", "", 0},
		{"", "", 0},
		{"*", "*", 1}, // a model genuinely named "*" gets its own exception, nothing more
	}

	for _, tc := range cases {
		got := ExceptionsFor(all, tc.model, tc.version)
		if len(got) != tc.want {
			t.Errorf("%q/%q matched %d exceptions, want %d", tc.model, tc.version, len(got), tc.want)
			for _, g := range got {
				t.Logf("   matched: %q/%q", g.Spec.ModelName, g.Spec.ModelVersion)
			}
		}
	}
}

// A waiver that applies to everything is not a reviewed exception, and the
// characters somebody would reach for are all legal model names.
func TestNoWildcardWaivesEveryModel(t *testing.T) {
	for _, pattern := range []string{"*", "", "**", ".*", "%", "_", "all", "any"} {
		got := ExceptionsFor(
			[]securityv1alpha1.ArtifactException{ex(pattern, pattern)},
			"fraud", "v1")
		if len(got) != 0 {
			t.Errorf("an exception for %q applied to fraud/v1", pattern)
		}
	}
}
