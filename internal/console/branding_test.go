package console

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// The console carries the product's name and, more importantly, the namespace,
// image and commands somebody is meant to copy. A rename that misses this file
// leaves the interface naming a product that no longer exists and handing out
// commands against resources that were never created.
func TestTheConsoleCarriesNoFormerName(t *testing.T) {
	if i := strings.Index(strings.ToLower(string(IndexHTML)), "assay"); i >= 0 {
		start := max(0, i-60)
		t.Errorf("the console still says the former name: %q",
			string(IndexHTML[start:min(len(IndexHTML), i+60)]))
	}
}

// The console used to carry its own copy of the image tag, kept honest by this
// test failing whenever somebody edited one file and not the other. It now asks
// the API for the tag of the binary actually serving the page, so what needs
// guarding is the opposite: that no literal version creeps back in.
//
// The rest of the chain is enforced elsewhere — internal/scanners pins ImageTag
// to the chart's appVersion, and internal/api hands that to the console at
// sign-in — so a tag hardcoded here would be the one link nothing recomputes.
func TestTheConsoleHardcodesNoImageTag(t *testing.T) {
	if m := regexp.MustCompile(`cupel-operator:[0-9]\S*`).Find(IndexHTML); m != nil {
		t.Errorf("the console pins %q rather than taking the tag the API reports; "+
			"it goes stale on the first release after somebody forgets this file", m)
	}
	if !bytes.Contains(IndexHTML, []byte("cupel-operator:${VERSION")) {
		t.Error("the console no longer interpolates the version the API reports, " +
			"so it is describing some other install")
	}
}

// The values the console hands out have to be the ones the chart deploys.
func TestTheConsoleQuotesTheRealDeployment(t *testing.T) {
	for _, want := range []string{
		"cupel-system", // the release namespace
		"ghcr.io/davano-innovation-lab/cupel-operator", // the published image
	} {
		if !strings.Contains(string(IndexHTML), want) {
			t.Errorf("the console never mentions %q, so what it tells people to run "+
				"does not match what the chart installs", want)
		}
	}
	// A command referencing a binary that is not in the image is worse than no
	// command: it fails after the reader has trusted it.
	if regexp.MustCompile(`\./assay|/assay `).Match(IndexHTML) {
		t.Error("the console hands out a command for a binary the image does not contain")
	}
}
