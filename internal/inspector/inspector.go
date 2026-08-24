// Package inspector is a thin adapter over tessera's artifact walk.
//
// The analysis used to live here. It moved into the library because it is
// artifact analysis rather than orchestration: nothing in it needed an API
// server, and keeping it here meant the same pickle opcode table existed in two
// repositories, free to disagree. What remains is the boundary — the walk's
// findings converted into the custom-resource shape the operator's controllers,
// policies and reports are written against.
package inspector

import (
	"context"

	"github.com/DAVANO-INNOVATION-LAB/tessera"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Report is the inspector's output in the operator's own vocabulary.
type Report struct {
	Findings     []securityv1alpha1.Finding `json:"findings"`
	FilesScanned int                        `json:"filesScanned"`
	Formats      []string                   `json:"formats,omitempty"`
	// Truncated records that the file cap was reached, so part of the artifact
	// was never examined. A clean report over a truncated walk is not a clean
	// artifact, and the difference has to survive into the verdict.
	Truncated bool `json:"truncated,omitempty"`
}

// Limits bound the walk so a hostile artifact cannot exhaust the scan pod.
type Limits = tessera.InspectLimitSet

// DefaultLimits are the limits used when none are supplied.
func DefaultLimits() Limits { return tessera.InspectLimits() }

// Inspect walks the staged artifact at root and reports model-level risks.
func Inspect(root string, limits Limits) (*Report, error) {
	// InspectLimited rather than Inspect: the option-based entry point can only
	// express a file cap, and dropping the archive and decompression bounds
	// here would leave every caller on the defaults while appearing to accept
	// their limits.
	rep, err := tessera.InspectLimited(context.Background(), root, limits)
	if err != nil {
		return nil, err
	}
	out := &Report{
		FilesScanned: rep.FilesScanned,
		Formats:      rep.Formats,
		Truncated:    rep.Truncated,
	}
	// The two Finding types are field-for-field identical, which is not an
	// accident — the custom-resource type is where this one came from. They are
	// copied rather than aliased so the API's kubebuilder validation stays
	// attached to the resource and the library stays free of it.
	out.Findings = make([]securityv1alpha1.Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
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
