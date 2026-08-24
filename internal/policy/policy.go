// Package policy is a thin adapter over tessera's gate.
//
// The decision moved into the library because none of it needed Kubernetes: a
// threshold comparison is computation, and keeping it here meant the rule that
// decides whether a model may be admitted existed in two repositories, free to
// disagree. What remains is the conversion between the custom-resource types
// the controllers speak and the plain types the gate takes.
package policy

import (
	"time"

	"github.com/DAVANO-INNOVATION-LAB/tessera"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Evaluation and Violation are the library's types directly. They are aliases
// rather than copies because every field the controllers read is already there
// — the library's version is where this one came from — and a parallel struct
// would be one more thing to keep in step.
type (
	Evaluation = tessera.GateResult
	Violation  = tessera.GateViolation
)

// Rule names a violation can carry.
const (
	RuleMaxCriticalCVEs   = tessera.RuleMaxCriticalCVEs
	RuleMaxHighCVEs       = tessera.RuleMaxHighCVEs
	RuleBlockMalware      = tessera.RuleBlockMalware
	RuleBlockSecrets      = tessera.RuleBlockSecrets
	RuleBlockUnsafeModel  = tessera.RuleBlockUnsafeModel
	RuleRequireSignature  = tessera.RuleRequireSignature
	RuleRequireSBOM       = tessera.RuleRequireSBOM
	RuleRequireAIBOM      = tessera.RuleRequireAIBOM
	RuleBlockModelDrift   = tessera.RuleBlockModelDrift
	RuleRequireProvenance = tessera.RuleRequireProvenance
	RuleAllowedFormats    = tessera.RuleAllowedFormats
	RuleBlockedFormats    = tessera.RuleBlockedFormats
	RuleScanIncomplete    = tessera.RuleScanIncomplete
)

// Category outcomes reported alongside a verdict.
const (
	StatusClean    = tessera.StatusClean
	StatusDetected = tessera.StatusDetected
	StatusUnknown  = tessera.StatusUnknown
)

// Evaluate applies a policy to scan results for an artifact. A nil policy uses
// the library's conservative defaults: block malware, secrets and unsafe model
// formats; allow CVEs.
func Evaluate(
	results []securityv1alpha1.ScannerResult,
	artifact securityv1alpha1.ArtifactRef,
	pol *securityv1alpha1.ArtifactScanPolicy,
	exceptions []securityv1alpha1.ArtifactException,
	now time.Time,
) Evaluation {
	return tessera.Gate(
		toResults(results),
		tessera.GateArtifact{
			URI:       artifact.URI,
			Digest:    artifact.Digest,
			MediaType: artifact.MediaType,
			Format:    artifact.Format,
			SizeBytes: artifact.SizeBytes,
		},
		toRules(pol),
		toExceptions(exceptions),
		now,
	)
}

func toResults(in []securityv1alpha1.ScannerResult) []tessera.ScannerResult {
	out := make([]tessera.ScannerResult, 0, len(in))
	for _, r := range in {
		out = append(out, tessera.ScannerResult{
			Scanner:    r.Scanner,
			Status:     r.Status,
			Findings:   r.Findings,
			Severities: toCounts(r.Severities),
			Drift:      toCounts(r.Drift),
			Produced:   r.Produced,
			Message:    r.Message,
		})
	}
	return out
}

func toCounts(c securityv1alpha1.SeverityCounts) tessera.SeverityCounts {
	return tessera.SeverityCounts{
		Critical: c.Critical, High: c.High, Medium: c.Medium,
		Low: c.Low, Unknown: c.Unknown,
	}
}

// toRules unwraps the resource. A nil policy stays nil rather than becoming an
// empty rule set: the library reads nil as "use the defaults", and an empty
// struct would read as "every threshold deliberately unset", which disables the
// protections instead of applying them.
func toRules(pol *securityv1alpha1.ArtifactScanPolicy) *tessera.GateRules {
	if pol == nil {
		return nil
	}
	r := pol.Spec.Rules
	return &tessera.GateRules{
		MaxCriticalCVEs:   r.MaxCriticalCVEs,
		MaxHighCVEs:       r.MaxHighCVEs,
		BlockMalware:      r.BlockMalware,
		BlockSecrets:      r.BlockSecrets,
		BlockUnsafeModel:  r.BlockUnsafeModel,
		BlockModelDrift:   r.BlockModelDrift,
		RequireSignature:  r.RequireSignature,
		RequireProvenance: r.RequireProvenance,
		RequireSBOM:       r.RequireSBOM,
		RequireAIBOM:      r.RequireAIBOM,
		AllowedFormats:    r.AllowedFormats,
		BlockedFormats:    r.BlockedFormats,
	}
}

func toExceptions(in []securityv1alpha1.ArtifactException) []tessera.GateException {
	out := make([]tessera.GateException, 0, len(in))
	for _, e := range in {
		ex := tessera.GateException{
			FindingIDs:    e.Spec.FindingIDs,
			Rules:         e.Spec.Rules,
			Reason:        e.Spec.Reason,
			ScannedDigest: e.Spec.ScannedDigest,
		}
		if e.Spec.ExpiresAt != nil {
			t := e.Spec.ExpiresAt.Time
			ex.ExpiresAt = &t
		}
		out = append(out, ex)
	}
	return out
}

// FromCounts converts the library's tally back into the resource type.
//
// The two structs are field-identical, which is why the conversion is dull, but
// Go will not assign one to the other and should not: the resource type carries
// kubebuilder validation that the library type deliberately does not.
func FromCounts(c tessera.SeverityCounts) securityv1alpha1.SeverityCounts {
	return securityv1alpha1.SeverityCounts{
		Critical: c.Critical, High: c.High, Medium: c.Medium,
		Low: c.Low, Unknown: c.Unknown,
	}
}
