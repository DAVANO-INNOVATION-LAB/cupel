package naming

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func assertValidName(t *testing.T, name string) {
	t.Helper()
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		t.Errorf("name %q is not a valid DNS-1123 label: %v", name, errs)
	}
	if len(name) > MaxNameLength {
		t.Errorf("name %q is %d chars, over the %d limit", name, len(name), MaxNameLength)
	}
}

func TestNamesAreValidForHostileInput(t *testing.T) {
	inputs := []struct{ model, version string }{
		{"fraud-detector", "v1.0.0"},
		{"Fraud_Detector", "V1.0"},
		{"org/team/model", "release 2"},
		{"modèle-français", "v1"},
		{strings.Repeat("long", 40), "v1"},
		{"", ""},
		{"---", "---"},
		{"UPPERCASE", "1.0.0+build.5"},
	}

	for _, in := range inputs {
		t.Run(in.model+"@"+in.version, func(t *testing.T) {
			assertValidName(t, ModelReport(in.model, in.version))
			assertValidName(t, Scan(in.model, in.version, "artifact-1"))
			assertValidName(t, ScanJob(ModelReport(in.model, in.version), "model-inspector"))
		})
	}
}

// The bug this guards: appending the scanner to an already-maximal scan name
// and truncating gave every scanner the same Job name, so only the first Job
// was ever created and the scan waited forever on reports that never came.
func TestScanJobNamesAreDistinctPerScanner(t *testing.T) {
	scanName := Scan(strings.Repeat("a-very-long-model-name", 4), "v1.0.0-rc1", "artifact-1")

	seen := map[string]string{}
	for _, scanner := range []string{"clamav", "trivy", "grype", "syft", "trufflehog", "model-inspector", "provenance"} {
		job := ScanJob(scanName, scanner)
		assertValidName(t, job)
		if prior, ok := seen[job]; ok {
			t.Fatalf("scanner %q produced the same Job name as %q: %s", scanner, prior, job)
		}
		seen[job] = scanner
	}
}

func TestScanJobAndScanReportAgree(t *testing.T) {
	// The controller looks for reports the runner writes; if these two ever
	// diverge, results silently never get collected.
	scanName := Scan("detector", "v1", "artifact-1")
	if ScanJob(scanName, "clamav") != ScanReport(scanName, "clamav") {
		t.Error("job and report naming diverged")
	}
}

func TestDistinctInputsDoNotCollide(t *testing.T) {
	base := strings.Repeat("x", 90)
	names := map[string]string{}

	for _, suffix := range []string{"alpha", "beta", "gamma", "delta"} {
		name := ModelReport(base+suffix, "v1")
		if prior, ok := names[name]; ok {
			t.Fatalf("%q and %q both produced %q", suffix, prior, name)
		}
		names[name] = suffix
	}
}

// Two model names that sanitize to the same string must still be told apart,
// or a scan of one would overwrite the report of the other.
func TestNamesThatSanitizeIdenticallyStillDiffer(t *testing.T) {
	long := strings.Repeat("model", 20)
	first := ModelReport(long+"/team-a", "v1")
	second := ModelReport(long+"/team-b", "v1")

	if first == second {
		t.Fatalf("distinct models collided on %q", first)
	}
}

func TestNamesAreDeterministic(t *testing.T) {
	// The operator and the admission webhook derive this independently, so the
	// same inputs have to give the same name every time and in every process.
	first := ModelReport("detector", "v1")
	for range 5 {
		if got := ModelReport("detector", "v1"); got != first {
			t.Fatalf("ModelReport() returned %q then %q for the same input", first, got)
		}
	}
	// Still readable: the fingerprint is a suffix, not a replacement.
	if !strings.HasPrefix(first, "msr-detector-v1-") {
		t.Errorf("name %q lost the readable part", first)
	}
	if len(first) > MaxNameLength {
		t.Errorf("name %q is %d characters, over the limit", first, len(first))
	}
}

func TestSanitizeCollapsesSeparatorRuns(t *testing.T) {
	if got := Sanitize("my///model___name"); got != "my-model-name" {
		t.Errorf("Sanitize() = %q, want %q", got, "my-model-name")
	}
}

func TestSanitizeLabelIsValid(t *testing.T) {
	label := SanitizeLabel(strings.Repeat("Model_Name/", 20))
	if errs := validation.IsValidLabelValue(label); len(errs) > 0 {
		t.Errorf("label %q is invalid: %v", label, errs)
	}
}

func TestEmptyInputYieldsUsableName(t *testing.T) {
	assertValidName(t, ModelReport("", ""))
	if got := Sanitize(""); got != "unnamed" {
		t.Errorf("Sanitize(\"\") = %q, want %q", got, "unnamed")
	}
}
