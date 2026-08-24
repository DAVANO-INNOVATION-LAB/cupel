package authz

import (
	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Redaction describes what was withheld, so the console can say "3 findings
// hidden" rather than silently showing a shorter list. Silence would let a
// reader mistake a redacted view for a clean model, which is the one
// misreading this whole package exists to prevent.
type Redaction struct {
	// HiddenFindings is how many findings the subject may not see at all.
	HiddenFindings int `json:"hiddenFindings,omitempty"`
	// DetailWithheld is true when findings were returned without their
	// location and description.
	DetailWithheld bool `json:"detailWithheld,omitempty"`
	// Reason is a short, non-leaking explanation for the UI.
	Reason string `json:"reason,omitempty"`
}

// FindingView is a finding as a particular subject is allowed to see it.
//
// It is a separate type from securityv1alpha1.Finding on purpose. Returning
// the API type with some fields blanked invites a future field being added to
// the API and silently flowing through to everyone; a distinct type means each
// new field is a deliberate decision to expose.
type FindingView struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
	Scanner  string `json:"scanner,omitempty"`

	// Location and Description carry the exploit path. Present only for
	// subjects holding CapViewFindingPath.
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`

	// Redacted marks a row whose detail was withheld, so the UI can show that
	// something exists without pretending it has been shown in full.
	Redacted bool `json:"redacted,omitempty"`
}

// RedactFindings returns the findings a subject may see, at the detail level
// their roles allow.
//
// namespace is the tenant the findings belong to; a subject outside that
// tenant receives nothing at all rather than a redacted list, because even the
// count of findings against a named model is information about that model.
func RedactFindings(
	s Subject,
	namespace string,
	findings []securityv1alpha1.Finding,
	scanner string,
) ([]FindingView, Redaction) {
	if !s.CanSeeNamespace(namespace) {
		return nil, Redaction{
			HiddenFindings: len(findings),
			DetailWithheld: true,
			Reason:         "outside your assigned tenants",
		}
	}
	if !s.Can(CapViewFindings) {
		return nil, Redaction{
			HiddenFindings: len(findings),
			DetailWithheld: true,
			Reason:         "your role does not include finding detail",
		}
	}

	full := s.Can(CapViewFindingPath)
	views := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		v := FindingView{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Category: f.Category,
			Scanner:  scanner,
		}
		if full {
			v.Location = f.Location
			v.Description = f.Description
		} else {
			v.Redacted = true
		}
		views = append(views, v)
	}

	red := Redaction{}
	if !full && len(views) > 0 {
		red.DetailWithheld = true
		red.Reason = "location and description are limited to security and model-owner roles"
	}
	return views, red
}

// ModelView is a model's posture as a subject may see it. Every field here is
// safe for anyone who can see the tenant at all: it says what was decided, not
// how the model is exploitable.
type ModelView struct {
	ModelName    string `json:"modelName"`
	ModelVersion string `json:"modelVersion"`
	Namespace    string `json:"namespace"`
	Verdict      string `json:"verdict,omitempty"`
	RiskScore    int32  `json:"riskScore"`
	Malware      string `json:"malware,omitempty"`
	Secrets      string `json:"secrets,omitempty"`
	LastScanTime string `json:"lastScanTime,omitempty"`

	// Severities is a count per level. Counts are deliberately visible to
	// every role that can see the tenant: knowing a model has two critical
	// findings is what makes a verdict actionable, and it does not say what
	// they are.
	Severities securityv1alpha1.SeverityCounts `json:"severities"`
}

// FilterModels returns only the models a subject's scope permits, and reports
// how many were withheld.
//
// The count of withheld models is shown rather than hidden: a security team
// needs to know their view is partial, and the number alone reveals nothing
// about the models themselves.
func FilterModels(s Subject, models []ModelView) ([]ModelView, Redaction) {
	if !s.Can(CapViewInventory) {
		return nil, Redaction{
			HiddenFindings: len(models),
			Reason:         "your role does not include the model inventory",
		}
	}
	visible := make([]ModelView, 0, len(models))
	hidden := 0
	for _, m := range models {
		if s.CanSeeNamespace(m.Namespace) {
			visible = append(visible, m)
			continue
		}
		hidden++
	}
	red := Redaction{}
	if hidden > 0 {
		red.HiddenFindings = hidden
		red.Reason = "models outside your assigned tenants are not shown"
	}
	return visible, red
}
