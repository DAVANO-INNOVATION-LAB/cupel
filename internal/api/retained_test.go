package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Findings arrive one report per scanner. Reporting the redaction of whichever
// report happened to be last understates how much is hidden, and it understates
// it precisely for the reader least able to check by another route.
func TestRedactionCountsHiddenFindingsFromEveryScanner(t *testing.T) {
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-fraud", Namespace: "team-a"},
		Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "fraud", ModelVersion: "v1"},
	}
	mk := func(name, scanner string, ids ...string) *securityv1alpha1.ArtifactScanReport {
		rep := &securityv1alpha1.ArtifactScanReport{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
			Scanner:    scanner, ScanRef: "scan-fraud",
		}
		for _, id := range ids {
			rep.Findings = append(rep.Findings, securityv1alpha1.Finding{
				ID: id, Severity: "High", Location: "weights.bin",
			})
		}
		return rep
	}
	s := testServer(t,
		report("fraud", "team-a", "Quarantined"), scan,
		mk("asr-a", "model-inspector", "A-1", "A-2", "A-3"),
		mk("asr-b", "tessera", "B-1"),
	)

	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet,
		"/api/findings?model=fraud&version=v1", nil), "reader", "viewers")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Findings  []any `json:"findings"`
		Redaction struct {
			HiddenFindings int `json:"hiddenFindings"`
		} `json:"redaction"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("a viewer received %d findings", len(got.Findings))
	}
	if got.Redaction.HiddenFindings != 4 {
		t.Errorf("reported %d hidden findings, want 4 — a per-scanner count "+
			"overwrote the total instead of adding to it",
			got.Redaction.HiddenFindings)
	}
}

// Scan reports are collected with the scan that made them; the verdict is kept
// deliberately longer. Once the scans are gone, an empty finding list is true
// and useless: it reads as "this model is clean" when the truth is that the
// evidence expired.
func TestPrunedScansReportWhatTheVerdictStillKnows(t *testing.T) {
	msr := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: "msr-old", Namespace: "team-a"},
		Spec: securityv1alpha1.ModelSecurityReportSpec{
			ModelName: "fraud", ModelVersion: "v1", ScanRef: "scan-long-gone",
		},
		Status: securityv1alpha1.ModelSecurityReportStatus{
			Verdict: "Quarantined", RiskScore: 90,
			AIBOMRef: "scan-long-gone-tessera",
			Scanners: []securityv1alpha1.ScannerResult{
				{Scanner: "model-inspector", Status: "Failed", Findings: 2},
				{Scanner: "tessera", Status: "Failed", Findings: 1},
			},
		},
	}
	s := testServer(t, msr) // no ArtifactScan, no ArtifactScanReports

	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet,
		"/api/findings?model=fraud&version=v1", nil), "soc", "secops")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Retained *struct {
			Findings int  `json:"findings"`
			AIBOM    bool `json:"aibom"`
		} `json:"retained"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Retained == nil {
		t.Fatal("a pruned model version reported nothing at all; the panel would " +
			"claim it was clean")
	}
	if got.Retained.Findings != 3 {
		t.Errorf("retained %d findings, want 3", got.Retained.Findings)
	}

	// The same distinction for the bill of materials: produced-then-pruned must
	// not be reported as never-produced, which sends somebody to fix a policy
	// that was correct.
	req = loggedIn(t, s, httptest.NewRequest(http.MethodGet,
		"/api/bom?model=fraud&version=v1", nil), "soc", "secops")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Errorf("a pruned bill of materials returned %d, want 410: %s",
			rec.Code, rec.Body.String())
	}
}
