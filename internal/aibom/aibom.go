// Package aibom produces an AI bill of materials for a staged model artifact.
//
// It is a thin adapter over github.com/DAVANO-INNOVATION-LAB/tessera, which
// reads a model's own binary headers — GGUF, safetensors, ONNX — and renders
// them as CycloneDX 1.6 ML-BOM and SPDX 3.0.1. Tessera is imported rather than
// shelled out to: it has no third-party dependencies and never touches the
// network, so embedding it adds nothing to the scan pod's attack surface and
// keeps the analysis in the same process that reports on it.
//
// This is a different document from the SBOM syft produces. Syft inventories
// the *packages* around a model; this describes the model itself — its
// parameters, precision, tensor shapes, licence, declared lineage, and the
// per-file hashes that pin those claims to bytes. The two are complementary
// and Cupel keeps them as separate categories so a policy can require either.
//
// The findings it returns include drift: places where the model's sidecar
// declarations disagree with the weights they describe. A config advertising a
// precision the tensors do not carry is not a parse error, it is a statement
// about the artifact that nothing else in the scanner set can make.
package aibom

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Finding IDs this package emits in its own right. Everything else in a report
// carries a TESS-* identifier and comes from the analysis itself.
const (
	// FindingNoModel means nothing in the workspace was a model format the
	// analyser understands, so no bill of materials was produced.
	FindingNoModel = "cupel-AIBOM-001"
	// FindingPartial means more than one model was staged and only the
	// primary one is described.
	FindingPartial = "cupel-AIBOM-002"
	// FindingUnparsed means a model file was found and could not be read.
	FindingUnparsed = "cupel-AIBOM-003"
)

// Category is the finding category an AIBOM finding carries when the analysis
// offers nothing finer, so the policy engine can tell them from container-SBOM
// output.
const Category = "aibom"

// CategoryDrift marks a finding reporting that the model's own declarations
// disagree with the weights they describe. It is the one class of finding no
// other scanner in the set can produce, and the drift gate counts it by name.
const CategoryDrift = "drift"

// maxSearchDepth bounds the walk that looks for a model directory. A staged
// artifact is a model repository, not a filesystem, and an unbounded walk over
// a hostile archive is the kind of thing this scanner exists to report.
const maxSearchDepth = 6

// Report is what the runner writes out: the findings in Cupel's shape, plus
// the rendered documents and enough of the description to be read directly.
type Report struct {
	Findings []securityv1alpha1.Finding `json:"findings"`
	// Format is the model container that was described (gguf, safetensors,
	// onnx), empty when no model was found.
	Format string `json:"format,omitempty"`
	// ModelPath is where in the workspace the described model was found,
	// relative to the workspace root.
	ModelPath string `json:"modelPath,omitempty"`
	// Files is how many physical files the model was made of.
	Files int `json:"files,omitempty"`
	// TensorCount is the model's tensor count as measured, not as declared.
	TensorCount int `json:"tensorCount,omitempty"`
	// MeasuredParameters is the parameter count summed from the tensor
	// shapes — what the EU AI Act Annex XI calls "the number of parameters".
	// It is measured, not read off a label, which is the whole point: the
	// label is the thing it gets checked against.
	MeasuredParameters int64 `json:"measuredParameters,omitempty"`
	// Architecture and Precision are the two facts a reviewer asks for first.
	Architecture string `json:"architecture,omitempty"`
	Precision    string `json:"precision,omitempty"`
	// Quantization is GGUF's general.file_type, the only place the quant
	// suffix survives.
	Quantization string `json:"quantization,omitempty"`
	// Licenses are the SPDX identifiers the artifact resolved to.
	Licenses []string `json:"licenses,omitempty"`
	// Generated reports whether a bill of materials was actually produced.
	// A report with no findings and no document is not a clean result, and
	// this is the field that distinguishes the two.
	Generated bool `json:"generated"`
	// AdditionalModels names other model files found in the workspace that
	// this document does not describe.
	AdditionalModels []string `json:"additionalModels,omitempty"`
}

// Documents are the rendered bills of materials.
type Documents struct {
	CycloneDX []byte
	SPDX      []byte
}

// Options bound the analysis. The zero value uses the analyser's own defaults.
type Options struct {
	// MaxFileSize caps bytes held in memory for a single file.
	MaxFileSize int64
	// MaxFiles caps the physical files gathered for one model.
	MaxFiles int
	// GeneratedAt is stamped into both documents. It is a parameter rather
	// than a clock read so the same artifact renders byte-identically twice,
	// which is what makes a bill of materials diffable across scans.
	GeneratedAt time.Time
}

// Generate analyses the model staged under workspace and renders it.
//
// It returns a report even when nothing could be described. That is deliberate:
// a scanner that exits cleanly with no output is indistinguishable from one
// that examined a model and found it sound, and the whole argument for this
// tool is that its claims are checkable. "No bill of materials was produced"
// is itself a finding.
func Generate(ctx context.Context, workspace string, opts Options) (*Report, *Documents, error) {
	stampVersion()
	report := &Report{}

	candidates, err := findModels(workspace)
	if err != nil {
		return nil, nil, err
	}
	if len(candidates) == 0 {
		report.Findings = append(report.Findings, securityv1alpha1.Finding{
			ID:       FindingNoModel,
			Title:    "No model artifact was described",
			Severity: "Medium",
			Category: Category,
			Location: ".",
			Description: "Nothing in the staged artifact was a GGUF, safetensors or ONNX " +
				"file, so no AI bill of materials was produced. This is reported rather " +
				"than passed silently: a scan with no bill of materials is not the same " +
				"as a model whose bill of materials is clean, and a policy requiring one " +
				"must be able to tell the difference. Formats that hold weights in a " +
				"pickle (.bin, .pt, .ckpt) are covered by the model-inspector scanner " +
				"instead, which reports what they execute rather than what they contain.",
		})
		return report, nil, nil
	}

	primary := candidates[0]
	rel := relative(workspace, primary)
	report.ModelPath = rel

	if len(candidates) > 1 {
		others := make([]string, 0, len(candidates)-1)
		for _, c := range candidates[1:] {
			others = append(others, relative(workspace, c))
		}
		report.AdditionalModels = others
		report.Findings = append(report.Findings, securityv1alpha1.Finding{
			ID:       FindingPartial,
			Title:    "Only the primary model is described",
			Severity: "Medium",
			Category: Category,
			Location: rel,
			Description: fmt.Sprintf(
				"The artifact stages %d models and this bill of materials describes %s. "+
					"The others are named but not analysed: %s. A document that covers "+
					"part of an artifact reads as covering all of it unless it says "+
					"otherwise.", len(candidates), rel, strings.Join(others, ", ")),
		})
	}

	art, err := tessera.Analyze(ctx, primary, analyzeOptions(opts)...)
	if err != nil {
		report.Findings = append(report.Findings, securityv1alpha1.Finding{
			ID:       FindingUnparsed,
			Title:    "Model could not be described",
			Severity: "High",
			Category: Category,
			Location: rel,
			Description: fmt.Sprintf(
				"A model file was found and could not be read: %v. An artifact that "+
					"defeats the parser still loads in the framework that consumes it, "+
					"so this is reported at a severity a policy will not approve by "+
					"default (MITRE ATLAS AML.T0076, Corrupt AI Model).", err),
		})
		return report, nil, nil
	}

	report.Findings = append(report.Findings, translate(art.Findings, rel)...)
	report.Format = string(art.Format)
	report.Files = len(art.Files)
	report.TensorCount = art.TensorCount
	report.MeasuredParameters = art.Params.MeasuredParameters
	report.Architecture = art.Params.Architecture
	report.Precision = art.Params.DType
	report.Quantization = art.Params.Quantization
	for _, l := range art.Licenses {
		if l.SPDXID != "" {
			report.Licenses = append(report.Licenses, l.SPDXID)
		}
	}

	at := opts.GeneratedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	cdx, err := tessera.CycloneDX(art, at)
	if err != nil {
		return nil, nil, fmt.Errorf("render CycloneDX: %w", err)
	}
	spdx, err := tessera.SPDX(art, at)
	if err != nil {
		return nil, nil, fmt.Errorf("render SPDX: %w", err)
	}
	report.Generated = true
	return report, &Documents{CycloneDX: cdx, SPDX: spdx}, nil
}

// stampVersion tells the analyser which build of itself is making the claims.
//
// Both the CISA 2026 minimum elements and the G7 AI profile require the
// producing tool's name and version, and the default is the literal string
// "dev", which identifies nothing. The value is read from the compiled-in
// module version rather than passed at build time, so it cannot drift from
// what is actually running.
func stampVersion() {
	versionOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			return
		}
		for _, dep := range info.Deps {
			if dep.Path == tesseraModule && dep.Version != "" {
				tessera.Version = dep.Version
				return
			}
		}
	})
}

const tesseraModule = "github.com/DAVANO-INNOVATION-LAB/tessera"

var versionOnce sync.Once

func analyzeOptions(opts Options) []tessera.Option {
	var out []tessera.Option
	if opts.MaxFileSize > 0 {
		out = append(out, tessera.WithMaxFileSize(opts.MaxFileSize))
	}
	if opts.MaxFiles > 0 {
		out = append(out, tessera.WithMaxFiles(opts.MaxFiles))
	}
	// Hashing is never skipped here. The hash is what binds a component to
	// specific bytes, and both the CISA 2026 and the G7 minimum elements name
	// it as required — a document without it identifies nothing.
	return out
}

// translate carries analysis findings into Cupel's vocabulary.
//
// The two Finding shapes are field-identical, so this copies rather than
// converts. What it does add is the category and a workspace-relative location,
// because a finding whose location is an absolute path inside a dead scan pod
// cannot be acted on by whoever reads the report.
func translate(findings []tessera.Finding, modelPath string) []securityv1alpha1.Finding {
	out := make([]securityv1alpha1.Finding, 0, len(findings))
	dir := filepath.Dir(modelPath)
	for _, f := range findings {
		loc := f.Location
		if loc == "" {
			loc = modelPath
		} else if !filepath.IsAbs(loc) && dir != "." && dir != "" {
			loc = filepath.Join(dir, loc)
		}
		// The analyser's own category is preserved. Cupel's policy engine
		// buckets whole scanners by category, so this field is free to carry
		// the finer distinction — and CategoryDrift is the one the drift gate
		// counts on. Falling back to the scanner's own category keeps every
		// finding attributable.
		cat := f.Category
		if cat == "" {
			cat = Category
		}
		out = append(out, securityv1alpha1.Finding{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			Category:    cat,
			Location:    loc,
			Description: f.Description,
		})
	}
	return out
}

// findModels returns directories holding a model the analyser can describe,
// most-shallow first, so the model at the root of a staged repository wins over
// one nested in a subdirectory of examples.
func findModels(workspace string) ([]string, error) {
	root, err := os.Stat(workspace)
	if err != nil {
		return nil, err
	}
	if !root.IsDir() {
		if _, ok := tessera.Detect(workspace); ok {
			return []string{workspace}, nil
		}
		return nil, nil
	}

	seen := map[string]bool{}
	var dirs []string
	err = filepath.WalkDir(workspace, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is not fatal to the rest of the walk. It
			// is visible in the inspector's own coverage finding, which is the
			// scanner that owns that claim.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if depth(workspace, path) > maxSearchDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".gguf", ".ggml", ".safetensors", ".onnx":
		default:
			return nil
		}
		dir := filepath.Dir(path)
		if seen[dir] {
			return nil
		}
		seen[dir] = true
		dirs = append(dirs, dir)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(dirs, func(i, j int) bool {
		di, dj := depth(workspace, dirs[i]), depth(workspace, dirs[j])
		if di != dj {
			return di < dj
		}
		return dirs[i] < dirs[j]
	})
	return dirs, nil
}

func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(filepath.Separator)))
}

func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
