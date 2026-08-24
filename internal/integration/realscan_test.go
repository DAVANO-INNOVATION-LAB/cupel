package integration

import (
	"path/filepath"
	"testing"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/results"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// realOutputs are verbatim reports from the scanner images in scanners/,
// captured against a model artifact planted with an EICAR file, vulnerable
// dependency pins, and live-looking credentials.
var realOutputs = []struct {
	scanner string
	format  string
	file    string
}{
	{"clamav", scanners.FormatClamAV, "real_clamav.txt"},
	{"trivy", scanners.FormatTrivyJSON, "real_trivy.json"},
	{"trufflehog", scanners.FormatTrufflehog, "real_trufflehog.json"},
	{"syft", scanners.FormatSyftSPDX, "real_syft_spdx.json"},
}

// parseRealScanners walks the captured reports the way the publish step does,
// producing the ScannerResult list the controller hands to the policy engine.
func parseRealScanners(t *testing.T) []securityv1alpha1.ScannerResult {
	t.Helper()

	var out []securityv1alpha1.ScannerResult
	for _, o := range realOutputs {
		path := filepath.Join("..", "results", "testdata", o.file)
		parsed, err := results.Parse(o.format, path)
		if err != nil {
			t.Fatalf("parse %s output: %v", o.scanner, err)
		}

		status := "Passed"
		if parsed.Severities.Total() > 0 {
			status = "Failed"
		}
		out = append(out, securityv1alpha1.ScannerResult{
			Scanner:    o.scanner,
			Status:     status,
			Findings:   parsed.Severities.Total(),
			Severities: parsed.Severities,
		})
	}
	return out
}

// The full pipeline on real scanner output: an artifact carrying malware,
// critical CVEs, and live-looking credentials must be quarantined, and the
// reason must name every dimension that failed.
func TestRealScannerOutputProducesQuarantineVerdict(t *testing.T) {
	scannerResults := parseRealScanners(t)

	limit := int32(0)
	pol := &securityv1alpha1.ArtifactScanPolicy{
		Spec: securityv1alpha1.ArtifactScanPolicySpec{
			Enforcement: "Enforce",
			Rules: securityv1alpha1.PolicyRules{
				MaxCriticalCVEs: &limit,
				BlockMalware:    boolPtr(true),
				BlockSecrets:    boolPtr(true),
				RequireSBOM:     true,
			},
		},
	}

	eval := policy.Evaluate(scannerResults, securityv1alpha1.ArtifactRef{Format: "safetensors"},
		pol, nil, time.Now())

	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Fatalf("verdict = %q, want Quarantined (violations: %v)", eval.Verdict, eval.Violations)
	}
	if eval.RiskScore != 100 {
		t.Errorf("risk score = %d, want 100 with confirmed malware present", eval.RiskScore)
	}
	if eval.MalwareStatus != policy.StatusDetected {
		t.Errorf("malware = %q, want Detected from the real ClamAV report", eval.MalwareStatus)
	}
	if eval.SecretsStatus != policy.StatusDetected {
		t.Errorf("secrets = %q, want Detected from the real TruffleHog report", eval.SecretsStatus)
	}
	if eval.CVEs.Critical == 0 {
		t.Error("no critical CVEs reached the verdict from the real Trivy report")
	}

	// Every failing dimension should appear, so an operator reading the report
	// sees the whole picture rather than only the first rule that tripped.
	rules := map[string]bool{}
	for _, v := range eval.Violations {
		rules[v.Rule] = true
	}
	for _, want := range []string{
		policy.RuleBlockMalware,
		policy.RuleBlockSecrets,
		policy.RuleMaxCriticalCVEs,
	} {
		if !rules[want] {
			t.Errorf("violation %q missing; got %v", want, eval.Violations)
		}
	}
}

// The SBOM requirement must be satisfied by Syft having run, even though the
// SBOM itself contributes no findings. Otherwise requireSBOM would fail on
// every artifact, including clean ones.
func TestRealSyftRunSatisfiesSBOMRequirement(t *testing.T) {
	scannerResults := parseRealScanners(t)

	eval := policy.Evaluate(scannerResults, securityv1alpha1.ArtifactRef{},
		&securityv1alpha1.ArtifactScanPolicy{
			Spec: securityv1alpha1.ArtifactScanPolicySpec{
				Rules: securityv1alpha1.PolicyRules{RequireSBOM: true},
			},
		}, nil, time.Now())

	for _, v := range eval.Violations {
		if v.Rule == policy.RuleRequireSBOM {
			t.Fatalf("requireSBOM failed even though Syft ran and produced an SBOM: %v", v)
		}
	}
}

func boolPtr(v bool) *bool { return &v }
