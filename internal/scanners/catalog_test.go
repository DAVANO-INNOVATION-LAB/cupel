package scanners

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every Cupel scanner image takes exactly two positional arguments: the staged
// artifact directory and the output file. The catalog and the images have to
// agree on that, and nothing at runtime would catch a mismatch — the scanner
// would just fail inside a Job and the scan would stall.
func TestExternalScannerArgsMatchTheEntrypointContract(t *testing.T) {
	for _, name := range Available() {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if UsesOperatorImage(def) {
			continue // runner-backed scanners use their own flag interface
		}

		t.Run(name, func(t *testing.T) {
			if len(def.Args) != 2 {
				t.Fatalf("args = %v, want exactly [workspace, output]", def.Args)
			}
			if def.Args[0] != PlaceholderWorkspace {
				t.Errorf("first arg = %q, want %q", def.Args[0], PlaceholderWorkspace)
			}
			wantOutput := PlaceholderResults + "/" + def.OutputFile
			if def.Args[1] != wantOutput {
				t.Errorf("second arg = %q, want %q so the publish step reads the file the scanner wrote",
					def.Args[1], wantOutput)
			}
			if len(def.Command) != 0 {
				t.Errorf("command = %v, want the image entrypoint to be used", def.Command)
			}
		})
	}
}

// A scanner whose declared output file does not match what its entrypoint
// writes would always parse as an empty, clean result — a silent false
// negative, which is the worst failure a security scanner can have.
func TestEntrypointScriptsWriteTheDeclaredOutputFile(t *testing.T) {
	for _, name := range Available() {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if UsesOperatorImage(def) {
			continue
		}

		script := filepath.Join("..", "..", "scanners", name, "entrypoint.sh")
		content, err := os.ReadFile(script)
		if err != nil {
			if os.IsNotExist(err) {
				t.Logf("%s: no entrypoint yet (scanner image not built)", name)
				continue
			}
			t.Fatalf("read %s: %v", script, err)
		}

		t.Run(name, func(t *testing.T) {
			// The script defaults its output path; that default must name the
			// same file the catalog tells the publish step to read.
			if !strings.Contains(string(content), "/results/"+def.OutputFile) {
				t.Errorf("%s never references /results/%s, which is the file the catalog expects",
					script, def.OutputFile)
			}
		})
	}
}

func TestResolveImageUsesConfiguredRegistry(t *testing.T) {
	def, err := Get("clamav")
	if err != nil {
		t.Fatal(err)
	}

	got := ResolveImage(def, "registry.internal/mirror", "cupel:1.0")
	want := "registry.internal/mirror/scanner-clamav:" + ImageTag
	if got != want {
		t.Errorf("ResolveImage() = %q, want %q", got, want)
	}
}

func TestResolveImageFallsBackToDefaultRegistry(t *testing.T) {
	def, _ := Get("trivy")

	got := ResolveImage(def, "", "cupel:1.0")
	want := DefaultRegistry + "/scanner-trivy:" + ImageTag
	if got != want {
		t.Errorf("ResolveImage() = %q, want %q", got, want)
	}
}

func TestResolveImageTrimsTrailingSlash(t *testing.T) {
	def, _ := Get("syft")

	if got := ResolveImage(def, "registry.internal/mirror/", "cupel:1.0"); strings.Contains(got, "//") {
		t.Errorf("ResolveImage() = %q, want no doubled slash", got)
	}
}

// Runner-backed scanners ship inside the operator image, so they must never
// be resolved against the scanner registry.
func TestRunnerScannersUseTheOperatorImage(t *testing.T) {
	for _, name := range []string{"model-inspector", "provenance"} {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := ResolveImage(def, "registry.internal", "cupel:1.0"); got != "cupel:1.0" {
			t.Errorf("%s resolved to %q, want the operator image", name, got)
		}
	}
}

// Image references must be pinned. A :latest tag would let a recorded verdict
// silently come to mean something different on a later scan.
func TestScannerImagesArePinned(t *testing.T) {
	if ImageTag == "latest" || ImageTag == "" {
		t.Fatalf("ImageTag = %q, want a pinned version", ImageTag)
	}
	for _, name := range Names() {
		def, _ := Get(name)
		if UsesOperatorImage(def) {
			continue
		}
		if strings.Contains(def.Image, ":") {
			t.Errorf("%s: image %q should carry no tag; the tag comes from ImageTag",
				name, def.Image)
		}
	}
}

// The default set has to cover every dimension the product claims to check.
// Losing one would leave a whole class of risk silently unscanned.
func TestDefaultScannersCoverTheCoreCategories(t *testing.T) {
	covered := map[Category]bool{}
	for _, name := range Defaults() {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		covered[def.Category] = true
	}

	for _, required := range []Category{
		CategoryMalware, CategoryCVE, CategorySBOM, CategorySecret, CategoryModel,
	} {
		if !covered[required] {
			t.Errorf("no default scanner covers category %q", required)
		}
	}
}

// The catalog is what validates a policy's scanner list. Entries that have no
// image built passed that validation and then produced a Job that could only
// ImagePullBackOff, so the scan hung instead of the policy being rejected.
func TestUnbuiltScannersAreRejectedNotScheduled(t *testing.T) {
	var unbuilt []string
	for _, name := range Names() {
		if catalog[name].Unbuilt {
			unbuilt = append(unbuilt, name)
		}
	}
	// The catalog currently names only scanners that ship, so this loop is
	// usually empty. The invariants below are the ones that must hold either
	// way, so they run unconditionally rather than behind a skip.
	for _, name := range unbuilt {
		if _, err := Get(name); err == nil {
			t.Errorf("Get(%q) succeeded for a scanner with no image; a policy naming it would hang a scan", name)
		}
	}

	// Available must be the set that can actually run.
	for _, name := range Available() {
		if catalog[name].Unbuilt {
			t.Errorf("Available() returned unbuilt scanner %q", name)
		}
		if _, err := Get(name); err != nil {
			t.Errorf("Available() returned %q but Get rejects it: %v", name, err)
		}
	}

	// Defaults must never include something that cannot run.
	for _, name := range Defaults() {
		if _, err := Get(name); err != nil {
			t.Errorf("default scanner %q is not usable: %v", name, err)
		}
	}
}

// The catalog no longer ships an unbuilt entry, so the guard in Get and the
// filter in Available had no test exercising them — the rejection path could
// have been deleted or inverted and every test would still pass. A synthetic
// entry keeps the guard covered independently of what the real catalog holds.
func TestUnbuiltGuardRejectsSyntheticEntry(t *testing.T) {
	const name = "test-unbuilt-fixture"
	if _, exists := catalog[name]; exists {
		t.Fatalf("fixture name %q collides with a real catalog entry", name)
	}
	catalog[name] = Definition{
		Name:     name,
		Category: CategoryMalware,
		Image:    "scanner-does-not-exist",
		Unbuilt:  true,
	}
	t.Cleanup(func() { delete(catalog, name) })

	if _, err := Get(name); err == nil {
		t.Error("Get accepted an unbuilt scanner; a policy naming it would hang a scan in ImagePullBackOff")
	}
	if slices.Contains(Available(), name) {
		t.Error("Available() offered an unbuilt scanner")
	}
	if slices.Contains(Defaults(), name) {
		t.Error("Defaults() included an unbuilt scanner")
	}
	// Names is the full declared set, so the entry must still be visible there;
	// otherwise the guard would be hiding the catalog rather than gating it.
	if !slices.Contains(Names(), name) {
		t.Error("Names() dropped a declared scanner; the guard should gate use, not hide declarations")
	}
}
