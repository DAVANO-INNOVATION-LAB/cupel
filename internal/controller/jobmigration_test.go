package controller

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
)

// A scan already running when the operator is upgraded has a Job named the way
// the previous version derived it. Computing only the current name would find
// nothing and start a second Job for work already in flight — doubling the
// scanner load on every scan open at the moment of the upgrade.
func TestAJobFromBeforeTheUpgradeIsStillRecognised(t *testing.T) {
	const scan, scanner = "scan-fraud-detector-v3", "model-inspector"

	names := scanJobNames(scan, scanner)
	if len(names) != 2 {
		t.Fatalf("a reader is offered %d names, want the current one and the legacy one: %v",
			len(names), names)
	}
	if names[0] != naming.ScanJob(scan, scanner) {
		t.Error("the current name is not offered first")
	}
	if names[1] != naming.LegacyStable("", scan, scanner) {
		t.Error("the second name is not the one the previous version derived")
	}
	t.Logf("current %s", names[0])
	t.Logf("legacy  %s", names[1])
}

// Two scanners on one scan must still get separate Jobs, under either scheme.
func TestJobNamesStayDistinctPerScanner(t *testing.T) {
	const scan = "scan-fraud-detector-v3"
	seen := map[string]string{}
	for _, scanner := range []string{"clamav", "trivy", "syft", "trufflehog", "model-inspector"} {
		for _, n := range scanJobNames(scan, scanner) {
			if prev, dup := seen[n]; dup && prev != scanner {
				t.Errorf("%s and %s share the Job name %s", prev, scanner, n)
			}
			seen[n] = scanner
		}
	}
}
