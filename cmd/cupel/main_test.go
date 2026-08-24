package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
	"time"
)

// evaluate mirrors runInspect's core: inspect a path, then feed the findings
// through the policy engine. Tests assert on the verdict the CLI would map to
// an exit code, without spawning a subprocess.
func evaluate(t *testing.T, path string) policy.Evaluation {
	t.Helper()
	report, err := inspector.Inspect(path, inspector.DefaultLimits())
	if err != nil {
		t.Fatalf("inspect %s: %v", path, err)
	}
	result := securityv1alpha1.ScannerResult{
		Scanner:    "model-inspector",
		Status:     "Passed",
		Findings:   int32(len(report.Findings)),
		Severities: countSeverities(report.Findings),
	}
	if len(report.Findings) > 0 {
		result.Status = "Failed"
	}
	return policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: path, Format: primaryFormat(report.Formats)},
		nil, nil, time.Now(),
	)
}

func TestInspectVerdicts(t *testing.T) {
	dir := t.TempDir()

	// A malicious pickle: GLOBAL-form reference to os.system. Using the
	// inline "module\nattr\n" encoding keeps the fixture Python-free.
	evil := filepath.Join(dir, "evil.pkl")
	writeFile(t, evil, []byte("\x80\x04cos\nsystem\nq\x00."))

	// A clean safetensors header: 8-byte little-endian length + minimal JSON.
	good := filepath.Join(dir, "model.safetensors")
	header := []byte(`{"__metadata__":{}}`)
	buf := make([]byte, 8+len(header))
	buf[0] = byte(len(header))
	copy(buf[8:], header)
	writeFile(t, good, buf)

	if v := evaluate(t, evil).Verdict; v != securityv1alpha1.VerdictQuarantined {
		t.Errorf("evil pickle: verdict = %q, want Quarantined", v)
	}
	if v := evaluate(t, good).Verdict; v != securityv1alpha1.VerdictApproved {
		t.Errorf("clean safetensors: verdict = %q, want Approved", v)
	}
}

func TestCountSeverities(t *testing.T) {
	findings := []securityv1alpha1.Finding{
		{Severity: "Critical"}, {Severity: "High"}, {Severity: "High"},
		{Severity: "Medium"}, {Severity: "Low"}, {Severity: "weird"},
	}
	got := countSeverities(findings)
	if got.Critical != 1 || got.High != 2 || got.Medium != 1 || got.Low != 1 || got.Unknown != 1 {
		t.Errorf("countSeverities = %+v", got)
	}
}

func TestJSONOutputShape(t *testing.T) {
	// The JSON contract is what CI gates parse; guard the field names.
	out := jsonOutput{Verdict: "Quarantined", RiskScore: 60}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"verdict", "riskScore", "severities", "findings", "cupelVersion"} {
		if _, ok := round[key]; !ok {
			t.Errorf("JSON output missing %q field", key)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A file that could execute code and was never read must deny an Approved
// verdict. Reporting it only in a coverage line meant a 548MB unread pickle
// came back "Approved, risk 0/100" — the exact shape of a scanner that is
// worse than none, because it certifies what it did not look at.
func TestUnreadExecutableFilesDenyApproval(t *testing.T) {
	cov := &resolver.Coverage{
		FetchedWhole: []string{"config.json"},
		HeaderOnly:   []string{"model.safetensors"},
		Skipped: map[string]string{
			"pytorch_model.bin": "548118077 bytes exceeds the fetch limit",
			"README.md":         "not interesting",
		},
	}

	gaps := coverageGaps(cov)
	if len(gaps) != 1 {
		t.Fatalf("got %d gap findings, want 1 (the pickle, not the README)", len(gaps))
	}
	if gaps[0].Location != "pytorch_model.bin" {
		t.Errorf("flagged %q, want the unread pickle", gaps[0].Location)
	}
	if gaps[0].Severity != "High" {
		t.Errorf("severity = %q; must be high enough to deny Approved", gaps[0].Severity)
	}

	// The finding has to survive into a verdict, not just exist.
	sev := countSeverities(gaps)
	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{{
			Scanner: "model-inspector", Status: "Failed",
			Findings: int32(len(gaps)), Severities: sev,
		}},
		securityv1alpha1.ArtifactRef{URI: "hf://x/y"},
		nil, nil, time.Now(),
	)
	if eval.RiskScore == 0 {
		t.Error("an unread executable file contributed nothing to the risk score")
	}

	// A header-sampled safetensors is genuinely covered: the format cannot
	// execute code, so sampling it is not a gap.
	if len(coverageGaps(&resolver.Coverage{HeaderOnly: []string{"model.safetensors"}})) != 0 {
		t.Error("a header-sampled safetensors was treated as an unscanned risk")
	}
	if coverageGaps(nil) != nil {
		t.Error("a complete local scan reported coverage gaps")
	}
}

func TestExecutableFormatsAreRecognisedBroadly(t *testing.T) {
	for _, n := range []string{"a.pkl", "b.bin", "c.pt", "d.py", "e.h5", "f.zip", "g.so", "h.onnx"} {
		if !resolver.CanExecuteCode(n) {
			t.Errorf("%s is not treated as executable-capable; an unread one would pass as clean", n)
		}
	}
	for _, n := range []string{"model.safetensors", "notes.md", "vocab.txt", "config.yaml"} {
		if resolver.CanExecuteCode(n) {
			t.Errorf("%s treated as executable-capable; that forces needless full downloads", n)
		}
	}
}
