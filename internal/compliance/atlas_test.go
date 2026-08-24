package compliance

import (
	"strings"
	"testing"
)

func TestDeprecatedTechniquesResolve(t *testing.T) {
	// AML.T0058 "Publish Poisoned Models" was retired in ATLAS 2026.07. A
	// mapping still citing it must resolve, not silently match nothing.
	got, ok := ReplacementFor("AML.T0058")
	if !ok || got != "AML.T0115.001" {
		t.Fatalf("AML.T0058 should resolve to AML.T0115.001, got %q ok=%v", got, ok)
	}

	tech, found := ATLASTechnique("AML.T0058")
	if !found {
		t.Fatal("looking up a deprecated ID should follow the replacement")
	}
	if tech.ID != "AML.T0115.001" {
		t.Fatalf("got %s", tech.ID)
	}
}

// Every technique name must be from the current release. The pre-2025 names
// used "ML"; ATLAS renamed them all to "AI". Shipping an old name cites a
// technique that no longer exists.
func TestNoRetiredMLNames(t *testing.T) {
	retired := []string{
		"ML Supply Chain Compromise",
		"Unsafe ML Artifacts",
		"Backdoor ML Model",
		"Poison Training Data",
		"Erode ML Model Integrity",
		"Acquire Public ML Artifacts",
		"Full ML Model Access",
		"Exfiltration via ML Inference API",
		"ML Intellectual Property Theft",
	}
	for _, tech := range ATLASTechniques() {
		for _, old := range retired {
			if tech.Name == old {
				t.Errorf("%s carries the retired name %q", tech.ID, old)
			}
		}
	}
}

// The out-of-scope entries are the honest boundary of the product. If somebody
// later "improves" coverage by flipping one of these to Detected without the
// capability behind it, this catches it.
func TestWeightPoisoningIsNotClaimed(t *testing.T) {
	for _, id := range []string{"AML.T0018.000", "AML.T0020", "AML.T0043.004"} {
		tech, ok := ATLASTechnique(id)
		if !ok {
			t.Fatalf("%s should be in the mapping, as a documented gap", id)
		}
		if tech.Coverage != CoverageOutOfScope {
			t.Errorf("%s (%s) is claimed as %s. A model backdoored in its weights is "+
				"byte-identical to a clean one; no static scanner can detect it.",
				id, tech.Name, tech.Coverage)
		}
		if tech.Rationale == "" {
			t.Errorf("%s is out of scope with no reason given", id)
		}
		if len(tech.Findings) > 0 {
			t.Errorf("%s is out of scope but claims findings %v", id, tech.Findings)
		}
	}
}

// Rug pull and reputation inflation sound like supply-chain scanning and are
// not. Buyers will assume they are covered, so the mapping must say otherwise.
func TestRegistryHistoryTechniquesAreOutOfScope(t *testing.T) {
	for _, id := range []string{"AML.T0109", "AML.T0111"} {
		tech, ok := ATLASTechnique(id)
		if !ok {
			t.Fatalf("%s should be documented", id)
		}
		if tech.Coverage != CoverageOutOfScope {
			t.Errorf("%s needs registry time-series, not artifact inspection", id)
		}
	}
}

// AML.T0018.001 had its meaning reused: it was "Inject Payload" and is now
// "Modify AI Model Architecture". A name-only find-and-replace would leave a
// mapping that is wrong rather than merely stale.
func TestReusedIDCarriesAWarning(t *testing.T) {
	tech, ok := ATLASTechnique("AML.T0018.001")
	if !ok {
		t.Fatal("AML.T0018.001 should be mapped")
	}
	if tech.Name != "Modify AI Model Architecture" {
		t.Fatalf("AML.T0018.001 is now Modify AI Model Architecture, got %q", tech.Name)
	}
	if !strings.Contains(tech.Rationale, "AML.T0018.002") {
		t.Error("the rationale should point at where Inject Payload went, or a stale " +
			"mapping will look correct")
	}
}

func TestEveryTechniqueHasARationale(t *testing.T) {
	for _, tech := range ATLASTechniques() {
		if tech.Rationale == "" {
			t.Errorf("%s (%s) has no rationale", tech.ID, tech.Name)
		}
		if tech.Coverage != CoverageOutOfScope && len(tech.Findings) == 0 {
			t.Errorf("%s claims %s coverage but names no evidence", tech.ID, tech.Coverage)
		}
	}
}

func TestMitigationsResolve(t *testing.T) {
	for _, tech := range ATLASTechniques() {
		for _, m := range tech.Mitigations {
			if _, ok := MitigationName(m); !ok {
				t.Errorf("%s references unknown mitigation %s", tech.ID, m)
			}
		}
	}
}

func TestCoverageSummaryIsHonest(t *testing.T) {
	s := SummarizeATLASCoverage()
	if s.Total != s.Detected+s.Partial+s.OutOfScope {
		t.Fatal("the summary must account for every technique")
	}
	if s.OutOfScope == 0 {
		t.Fatal("a coverage map with nothing out of scope is not a coverage map")
	}
	if s.Version != ATLASVersion {
		t.Fatal("the summary must name the ATLAS release it was built against")
	}
}

// A mapping may only cite a finding ID the scanner actually emits. Claiming a
// technique through an ID that nothing produces is the fail-open pattern
// applied to compliance output: it reads as coverage and detects nothing.
//
// AML.T0018.003 cited "cupel-GGUF", which appeared in no scanner.
func TestEveryCitedFindingPrefixCanActuallyBeEmitted(t *testing.T) {
	// Prefixes the inspector and scanners genuinely produce, plus scanner
	// names used as evidence markers.
	emitted := map[string]bool{
		"cupel-PICKLE": true, "cupel-COVERAGE": true, "cupel-PROV": true,
		"cupel-FORMAT": true, "cupel-IO": true, "cupel-LINK": true,
		"cupel-EXEC": true, "cupel-HF": true, "cupel-PY": true,
		"cupel-ONNX": true, "cupel-ZIP": true, "cupel-ELF": true,
		"cupel-KERAS": true, "cupel-TF": true, "cupel-AIBOM": true,
		"clamav": true, "trivy": true, "grype": true, "syft": true,
		"trufflehog": true, "model-inspector": true, "provenance": true,
		"tessera": true,
	}
	for _, tech := range ATLASTechniques() {
		for _, f := range tech.Findings {
			if !emitted[f] {
				t.Errorf("%s cites %q, which no scanner emits — that is a claim of coverage "+
					"with nothing behind it", tech.ID, f)
			}
		}
	}
}
