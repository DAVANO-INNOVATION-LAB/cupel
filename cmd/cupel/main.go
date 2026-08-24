// Command cupel is the standalone Cupel CLI. It runs the same model-format
// inspector and policy engine the in-cluster operator uses, with no cluster
// required:
//
//	cupel inspect <path>   scan a model file or directory and print a verdict
//	cupel version          print the build version
//
// Exit codes are made for CI gates: 0 the artifact was Approved, 2 the
// verdict is ReviewRequired, 3 the verdict is Quarantined, and 1 means the
// scan itself failed. A finding is not an error: the scan completing with a
// bad verdict exits with the verdict's code, never 1.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
)

// isURI distinguishes a remote artifact from a local path. A Windows drive
// letter is not a scheme, so require more than one character before "://".
func isURI(s string) bool {
	i := strings.Index(s, "://")
	return i > 1
}

// version is stamped by the linker: -ldflags "-X main.version=v0.2.0".
var version = "dev"

const (
	exitApproved       = 0
	exitError          = 1
	exitReviewRequired = 2
	exitQuarantined    = 3
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "inspect":
		os.Exit(runInspect(os.Args[2:]))
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cupel - supply-chain scanner for ML model artifacts

Usage:
  cupel inspect <path|uri> [--json] [--max-files N]
  cupel version

cupel inspect scans a model for the ways an artifact can execute code: unsafe
serialization (pickle and friends), archive escapes, executable payloads, and
configs that hand execution to model-supplied code.

<path|uri> is a local file or directory, or a remote artifact:

  hf://owner/name            Hugging Face, pinned to the current commit
  hf://owner/name@revision   a branch, tag or commit
  https://huggingface.co/... the URL as pasted from a browser
  s3://bucket/prefix         object storage (also ODF and MinIO)
  oci://registry/repo:tag    an OCI registry
  pvc://claim/path           a PersistentVolumeClaim, in-cluster

A remote model is staged to a temporary directory and removed afterwards. Very
large tensor files are sampled at their header rather than downloaded whole —
safetensors cannot execute code, so the header is the whole attack surface —
and anything not read in full is listed under "coverage" so a partial scan is
never mistaken for a clean one.

Exit codes: 0 Approved, 2 ReviewRequired, 3 Quarantined, 1 scan error.
`)
}

// jsonOutput is the machine-readable result of cupel inspect.
type jsonOutput struct {
	Path         string                          `json:"path"`
	Verdict      string                          `json:"verdict"`
	RiskScore    int32                           `json:"riskScore"`
	FilesScanned int                             `json:"filesScanned"`
	Formats      []string                        `json:"formats,omitempty"`
	Severities   securityv1alpha1.SeverityCounts `json:"severities"`
	Violations   []string                        `json:"violations,omitempty"`
	Findings     []securityv1alpha1.Finding      `json:"findings"`
	Coverage     *resolver.Coverage              `json:"coverage,omitempty"`
	Version      string                          `json:"cupelVersion"`
}

func runInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the full report as JSON")
	maxFiles := fs.Int("max-files", 0, "cap on files examined (0 = default limits)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: cupel inspect <path|uri> [--json] [--max-files N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitError
	}
	target := fs.Arg(0)

	// A remote URI is staged into a temporary directory first, so the same
	// inspector runs over local files and over a model that is still sitting
	// on someone else's hub. That is the case a security engineer actually
	// has: deciding whether an artifact is safe to bring in at all.
	path := target
	var coverage *resolver.Coverage
	if isURI(target) {
		staged, err := os.MkdirTemp("", "cupel-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "cupel inspect: %v\n", err)
			return exitError
		}
		defer os.RemoveAll(staged)

		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		reg := resolver.NewRegistry()
		if !reg.Supports(target) {
			fmt.Fprintf(os.Stderr, "cupel inspect: no resolver for %q\n", target)
			return exitError
		}
		fmt.Fprintf(os.Stderr, "staging %s ...\n", target)
		artifact, err := reg.Resolve(ctx, target, staged)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cupel inspect: %v\n", err)
			return exitError
		}
		path = staged
		coverage = artifact.Coverage
		// The resolved URI carries the pinned revision, so the report names
		// the exact bytes rather than a moving branch.
		target = artifact.URI
	} else if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "cupel inspect: %v\n", err)
		return exitError
	}

	limits := inspector.DefaultLimits()
	if *maxFiles > 0 {
		limits.MaxFiles = *maxFiles
	}

	report, err := inspector.Inspect(path, limits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cupel inspect: %v\n", err)
		return exitError
	}

	// A file that could execute code and was never read is an unknown, and an
	// unknown must not score as clean. Emitting it as a finding is what makes
	// it reach the verdict: reporting it only in the coverage line meant a
	// 548MB unread pickle came back Approved at risk 0.
	report.Findings = append(report.Findings, coverageGaps(coverage)...)

	severities := countSeverities(report.Findings)

	// Feed the findings through the same policy engine the operator runs, so
	// the CLI's verdict is the verdict a cluster would reach with the default
	// (nil) policy.
	result := securityv1alpha1.ScannerResult{
		Scanner:    "model-inspector",
		Status:     "Passed",
		Findings:   int32(len(report.Findings)),
		Severities: severities,
	}
	if len(report.Findings) > 0 {
		result.Status = "Failed"
	}
	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: path, Format: primaryFormat(report.Formats)},
		nil, nil, time.Now(),
	)

	if *jsonOut {
		out := jsonOutput{
			Path:         target,
			Verdict:      eval.Verdict,
			RiskScore:    eval.RiskScore,
			FilesScanned: report.FilesScanned,
			Formats:      report.Formats,
			Severities:   severities,
			Findings:     report.Findings,
			Coverage:     coverage,
			Version:      version,
		}
		for _, v := range eval.Violations {
			out.Violations = append(out.Violations, v.String())
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "cupel inspect: %v\n", err)
			return exitError
		}
	} else {
		printHuman(target, report, severities, eval, coverage)
	}

	switch eval.Verdict {
	case securityv1alpha1.VerdictQuarantined:
		return exitQuarantined
	case securityv1alpha1.VerdictReviewRequired:
		return exitReviewRequired
	default:
		return exitApproved
	}
}

// coverageGaps turns unread executable files into findings.
//
// High rather than Critical: the file was not read, so there is no evidence it
// is malicious — only an absence of evidence that it is safe. High is enough
// to deny an Approved verdict, which is the whole point.
func coverageGaps(cov *resolver.Coverage) []securityv1alpha1.Finding {
	if cov == nil {
		return nil
	}
	var out []securityv1alpha1.Finding
	for _, f := range cov.UnreadExecutable() {
		out = append(out, securityv1alpha1.Finding{
			ID:       "TESS-COVERAGE-001",
			Title:    "Executable-capable file was not scanned",
			Severity: "High",
			Category: "model",
			Location: f,
			Description: fmt.Sprintf(
				"%s was not read (%s), and its format can execute code when the model is loaded. "+
					"This artifact has not been cleared; raise the fetch limits or scan it locally.",
				f, cov.Skipped[f]),
		})
	}
	return out
}

// severityRank orders findings most-severe-first in human output.
var severityRank = map[string]int{
	"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4,
}

func printHuman(path string, report *inspector.Report, severities securityv1alpha1.SeverityCounts, eval policy.Evaluation, cov *resolver.Coverage) {
	fmt.Printf("cupel %s — %s\n", version, path)
	fmt.Printf("scanned %d file(s)", report.FilesScanned)
	if len(report.Formats) > 0 {
		fmt.Printf(", formats: %v", report.Formats)
	}
	fmt.Println()

	if len(report.Findings) == 0 {
		fmt.Println("\nno findings")
	} else {
		findings := append([]securityv1alpha1.Finding(nil), report.Findings...)
		sort.SliceStable(findings, func(i, j int) bool {
			return severityRank[findings[i].Severity] < severityRank[findings[j].Severity]
		})
		fmt.Println()
		for _, f := range findings {
			fmt.Printf("  [%-8s] %s  %s\n", f.Severity, f.ID, f.Title)
			if f.Location != "" {
				fmt.Printf("             at %s\n", f.Location)
			}
			fmt.Printf("             %s\n", f.Description)
		}
		fmt.Printf("\nfindings: %d critical, %d high, %d medium, %d low\n",
			severities.Critical, severities.High, severities.Medium, severities.Low)
	}

	for _, v := range eval.Violations {
		fmt.Printf("policy violation: %s\n", v)
	}
	// A partial fetch has to say so next to the verdict. "No findings" over
	// files that were never read is not a clean result, and this is the line
	// that stops it being read as one.
	if cov != nil && !cov.Complete() {
		fmt.Printf("\ncoverage: %s\n", cov.Summary())
		if len(cov.Skipped) > 0 {
			fmt.Println("  not read:")
			for f, why := range cov.Skipped {
				fmt.Printf("    %s — %s\n", f, why)
			}
		}
	}

	fmt.Printf("\nverdict: %s (risk score %d/100)\n", eval.Verdict, eval.RiskScore)
}

func countSeverities(findings []securityv1alpha1.Finding) securityv1alpha1.SeverityCounts {
	var counts securityv1alpha1.SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			counts.Critical++
		case "High":
			counts.High++
		case "Medium":
			counts.Medium++
		case "Low":
			counts.Low++
		default:
			counts.Unknown++
		}
	}
	return counts
}

// primaryFormat picks the format for the ArtifactRef when the artifact
// contains exactly one recognized model format; a mixed artifact stays
// unlabeled rather than mislabeled.
func primaryFormat(formats []string) string {
	if len(formats) == 1 {
		return formats[0]
	}
	return ""
}
