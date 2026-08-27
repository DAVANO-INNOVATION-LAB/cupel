package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The scan renders a bill of materials into the results volume, which is an
// emptyDir. Without collecting it, the document goes when the pod does — and
// the report is left asserting `produced: true` with nothing behind it.
func TestTheRenderedDocumentsAreCollected(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"model.cdx.json":   `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"model.spdx.json":  `{"spdxVersion":"SPDX-3.0.1"}`,
		"model.sarif.json": `{"version":"2.1.0"}`,
		"tessera.json":     `{"findings":[]}`, // the scanner result, not a document
		"clamav.txt":       "OK",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	docs, err := collectBOMs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"model.cdx.json", "model.spdx.json", "model.sarif.json"} {
		if _, ok := docs[want]; !ok {
			t.Errorf("%s was not collected", want)
		}
	}
	for _, unwanted := range []string{"tessera.json", "clamav.txt"} {
		if _, ok := docs[unwanted]; ok {
			t.Errorf("%s is a scanner result, not a document, and should not be stored", unwanted)
		}
	}
}

// A document too large to store must be left out rather than truncated: half a
// bill of materials is not a bill of materials, and a ConfigMap has a ceiling.
func TestAnOversizedDocumentIsNotTruncated(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", MaxBOMBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "model.cdx.json"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model.spdx.json"), []byte(`{"ok":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	docs, err := collectBOMs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := docs["model.cdx.json"]; ok && len(v) < len(big) {
		t.Error("an oversized document was stored truncated")
	}
	if _, ok := docs["model.spdx.json"]; !ok {
		t.Error("one oversized document dropped the others with it")
	}
}

// Nothing to collect is not an error: most scanners render no documents.
func TestNoDocumentsIsNotAFailure(t *testing.T) {
	docs, err := collectBOMs(t.TempDir())
	if err != nil || len(docs) != 0 {
		t.Fatalf("empty directory gave docs=%v err=%v", docs, err)
	}
	if docs, err := collectBOMs("/nonexistent-by-design"); err != nil || docs != nil {
		t.Fatalf("missing directory gave docs=%v err=%v", docs, err)
	}
}
