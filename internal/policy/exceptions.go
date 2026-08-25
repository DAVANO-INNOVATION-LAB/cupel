package policy

import (
	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// ExceptionsFor narrows a namespace's exceptions to the ones that apply to a
// model version.
//
// Evaluate trusts that its exceptions argument has already been scoped: it
// waives whatever rules the exceptions name, without checking who they were
// written for. That trust is fine and the two callers honour it, but each had
// written the same filter separately — and a third caller getting it wrong
// would waive one team's findings using another team's approval, with nothing
// to show for it in any report. One implementation, one test.
//
// An exception naming no model matches nothing. There is no wildcard, on
// purpose: a waiver that applies to everything is not a reviewed exception, and
// the character somebody would reach for is a legal model name.
func ExceptionsFor(all []securityv1alpha1.ArtifactException, model, version string) []securityv1alpha1.ArtifactException {
	if model == "" || version == "" {
		return nil
	}
	var matching []securityv1alpha1.ArtifactException
	for _, ex := range all {
		if ex.Spec.ModelName == model && ex.Spec.ModelVersion == version {
			matching = append(matching, ex)
		}
	}
	return matching
}
