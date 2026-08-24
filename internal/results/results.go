// Package results is a thin adapter over tessera's scanner-output ingestion.
//
// The parsers moved into the library for the same reason everything else did:
// reading ClamAV's log or Trivy's JSON is computation, not orchestration, and a
// second copy here would be free to disagree about what counts as a Critical.
// What remains is the conversion into the custom-resource types the runner
// writes back to the cluster.
package results

import (
	"context"

	"github.com/DAVANO-INNOVATION-LAB/tessera"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Parsed is one scanner's output, normalized.
type Parsed struct {
	Findings   []securityv1alpha1.Finding
	Severities securityv1alpha1.SeverityCounts
	// Drift counts the findings whose category marks them as a disagreement
	// between what the artifact declares and what it contains. They are also
	// counted in Severities; this is a view of the same findings, not a
	// second set.
	Drift securityv1alpha1.SeverityCounts
	// Produced reports whether a document-producing scanner emitted one.
	// Nil when the scanner does not produce a document.
	Produced *bool
	// Absent records that there was no output file at all. A clean scanner may
	// legitimately write none, and so may one that crashed before writing; only
	// the runner, which saw the exit code, can tell those apart.
	Absent bool
}

// Output formats that can be read.
const (
	FormatTessera    = tessera.FormatTessera
	FormatClamAV     = tessera.FormatClamAV
	FormatTrivyJSON  = tessera.FormatTrivyJSON
	FormatGrypeJSON  = tessera.FormatGrypeJSON
	FormatSyftSPDX   = tessera.FormatSyftSPDX
	FormatTrufflehog = tessera.FormatTrufflehog
)

// Parse reads a scanner's output file and normalizes it.
//
// An error is returned rather than an empty result, because the caller has to
// be able to tell a scanner that found nothing from one whose output could not
// be read. Those are opposite facts and they look identical once the findings
// list is empty.
func Parse(format, path string) (*Parsed, error) {
	p, err := tessera.Ingest(context.Background(), format, path)
	if err != nil {
		return nil, err
	}
	out := &Parsed{
		Severities: fromCounts(p.Severities),
		Drift:      fromCounts(p.Drift),
		Produced:   p.Produced,
		Absent:     p.Absent,
	}
	out.Findings = make([]securityv1alpha1.Finding, 0, len(p.Findings))
	for _, f := range p.Findings {
		out.Findings = append(out.Findings, securityv1alpha1.Finding{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			Category:    f.Category,
			Location:    f.Location,
			Description: f.Description,
		})
	}
	return out, nil
}

func fromCounts(c tessera.SeverityCounts) securityv1alpha1.SeverityCounts {
	return securityv1alpha1.SeverityCounts{
		Critical: c.Critical, High: c.High, Medium: c.Medium,
		Low: c.Low, Unknown: c.Unknown,
	}
}
