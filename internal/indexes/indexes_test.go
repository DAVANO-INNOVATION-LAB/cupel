package indexes

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Joining on a character that occurs in real names collapses distinct models
// onto one key, and the symptom is one model's findings rendered under
// another's name -- a wrong answer, not a slow one.
func TestModelKeysDoNotCollide(t *testing.T) {
	if ModelKey("fraud-detector", "v1") == ModelKey("fraud", "detector-v1") {
		t.Error("a dash in a model name collides with the separator")
	}
	if ModelKey("a/b", "c") == ModelKey("a", "b/c") {
		t.Error("a slash in a model name collides with the separator")
	}
}

func extractorFor(t *testing.T, obj client.Object, field string) client.IndexerFunc {
	t.Helper()
	for _, d := range Definitions() {
		if d.Field == field && sameKind(d.Object, obj) {
			return d.Extract
		}
	}
	t.Fatalf("no index defined for %T by %s", obj, field)
	return nil
}

func sameKind(a, b client.Object) bool {
	return typeName(a) == typeName(b)
}

func typeName(o client.Object) string {
	switch o.(type) {
	case *securityv1alpha1.ArtifactScan:
		return "scan"
	case *securityv1alpha1.ModelSecurityReport:
		return "msr"
	case *securityv1alpha1.ComplianceReport:
		return "compliance"
	case *securityv1alpha1.ArtifactScanReport:
		return "scanreport"
	}
	return "unknown"
}

func TestScansAreKeyedByTheModelTheyScanned(t *testing.T) {
	extract := extractorFor(t, &securityv1alpha1.ArtifactScan{}, ByModel)
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "s1"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "fraud-detector", ModelVersion: "v3",
		},
	}
	got := extract(scan)
	if len(got) != 1 || got[0] != ModelKey("fraud-detector", "v3") {
		t.Errorf("scan indexed as %v, want %q", got, ModelKey("fraud-detector", "v3"))
	}
}

// An object with no identity must not be indexed under the empty key, or a
// query for ("","") matches every incomplete object in the cluster -- widening
// the answer at exactly the point the index exists to narrow it.
func TestAnIncompleteIdentityIsNotIndexed(t *testing.T) {
	extract := extractorFor(t, &securityv1alpha1.ArtifactScan{}, ByModel)
	for _, tc := range []struct{ model, version string }{
		{"", ""}, {"fraud-detector", ""}, {"", "v3"},
	} {
		scan := &securityv1alpha1.ArtifactScan{
			Spec: securityv1alpha1.ArtifactScanSpec{
				ModelName: tc.model, ModelVersion: tc.version,
			},
		}
		if got := extract(scan); len(got) != 0 {
			t.Errorf("model=%q version=%q indexed as %v, want no key", tc.model, tc.version, got)
		}
	}
}

func TestScanReportsAreKeyedByTheirScan(t *testing.T) {
	extract := extractorFor(t, &securityv1alpha1.ArtifactScanReport{}, ByScan)
	rep := &securityv1alpha1.ArtifactScanReport{ScanRef: "bulk-model-019"}
	if got := extract(rep); len(got) != 1 || got[0] != "bulk-model-019" {
		t.Errorf("report indexed as %v, want [bulk-model-019]", got)
	}
	if got := extract(&securityv1alpha1.ArtifactScanReport{}); len(got) != 0 {
		t.Errorf("a report naming no scan indexed as %v, want no key", got)
	}
}

// A definition that is declared but never covers its kind is an index the
// server queries and the cache does not have.
func TestEveryQueriedIndexIsDefined(t *testing.T) {
	want := map[string]string{
		"scan":       ByModel,
		"msr":        ByModel,
		"compliance": ByModel,
		"scanreport": ByScan,
	}
	got := map[string]string{}
	for _, d := range Definitions() {
		got[typeName(d.Object)] = d.Field
	}
	for kind, field := range want {
		if got[kind] != field {
			t.Errorf("%s is not indexed by %q (got %q)", kind, field, got[kind])
		}
	}
}
