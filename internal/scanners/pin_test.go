package scanners

import (
	"os"
	"regexp"
	"testing"
)

// The scanner images are pinned rather than floating, which is right: :latest
// would silently change what a recorded verdict means. Pinning by hand is not
// right — this constant sat three releases behind while each of them published
// images at the new version that nothing pulled.
func TestTheScannerPinMatchesTheRelease(t *testing.T) {
	chart, err := os.ReadFile("../../deploy/helm/cupel/Chart.yaml")
	if err != nil {
		t.Skipf("chart not readable: %v", err)
	}
	m := regexp.MustCompile(`(?m)^appVersion:\s*"?([0-9][^"\s]*)"?`).FindSubmatch(chart)
	if m == nil {
		t.Fatal("the chart declares no appVersion to pin against")
	}
	if want := string(m[1]); ImageTag != want {
		t.Errorf("scanner images are pinned to %q but this release is %q; either advance "+
			"the pin or stop publishing images nothing pulls", ImageTag, want)
	}
}
