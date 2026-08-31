package controller

import (
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// The counts live per-scanner and the admission gate only ever sees the
// report, so an approval can only state its own coverage if the aggregate is
// carried up. A scanner reporting unread parts that nothing sums is a scanner
// whose warning stops at the scan.
func TestTotalUnexaminedSumsEveryScanner(t *testing.T) {
	got := totalUnexamined([]securityv1alpha1.ScannerResult{
		{Scanner: "inspector", Unexamined: securityv1alpha1.SeverityCounts{High: 1, Low: 2}},
		{Scanner: "clamav", Unexamined: securityv1alpha1.SeverityCounts{Critical: 3, Unknown: 1}},
		{Scanner: "trivy"},
	})

	want := securityv1alpha1.SeverityCounts{Critical: 3, High: 1, Low: 2, Unknown: 1}
	if got != want {
		t.Errorf("totalUnexamined = %+v, want %+v", got, want)
	}
}

func TestTotalUnexaminedOfNothingIsZero(t *testing.T) {
	if got := totalUnexamined(nil); got != (securityv1alpha1.SeverityCounts{}) {
		t.Errorf("totalUnexamined(nil) = %+v, want zero", got)
	}
}
