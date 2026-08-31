package webhook

import (
	"context"
	"strings"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// The case this whole field exists for. An approval over an artifact that was
// only partly read must not be reported the same way as one over an artifact
// that was read entirely — otherwise the two are indistinguishable to the
// operator and to the audit trail, which is the fail-open the scan policy's
// blockUnexamined already guards one level down.
func TestApprovalOverAnUnreadArtifactSaysSo(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Unexamined = securityv1alpha1.SeverityCounts{High: 2, Low: 1}
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if !resp.Allowed {
		t.Fatalf("gate denied on unexamined coverage; that is the scan policy's call, not the gate's: %s",
			resp.Result.Message)
	}
	if !strings.Contains(resp.Result.Message, "partially read") {
		t.Errorf("admission message does not say the artifact was partly read: %q", resp.Result.Message)
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("no warning attached to an approval over an unread artifact")
	}
	w := strings.Join(resp.Warnings, " ")
	if !strings.Contains(w, "3") {
		t.Errorf("warning does not report how much went unread: %q", w)
	}
	if !strings.Contains(w, "blockUnexamined") {
		t.Errorf("warning does not name the control that would refuse it: %q", w)
	}
}

// The ordinary case must stay quiet. A warning on every admission is a warning
// nobody reads, which would undo the point of the one above.
func TestFullyExaminedApprovalIsUnadorned(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", nil))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if !resp.Allowed {
		t.Fatalf("approved model was denied: %s", resp.Result.Message)
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("fully examined approval carried warnings: %v", resp.Warnings)
	}
	if strings.Contains(resp.Result.Message, "partially read") {
		t.Errorf("fully examined approval claims partial coverage: %q", resp.Result.Message)
	}
}

// Unexamined coverage must not rescue a denial. A quarantined model is denied
// whether or not part of it was readable.
func TestUnexaminedDoesNotOverrideADenial(t *testing.T) {
	gate := newGate(t, report("fraud", "v1", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
		r.Status.Unexamined = securityv1alpha1.SeverityCounts{High: 5}
	}))

	resp := gate.Handle(context.Background(), deployment(map[string]string{
		AnnotationModel:   "fraud",
		AnnotationVersion: "v1",
	}))

	if resp.Allowed {
		t.Fatal("a quarantined model was admitted because part of it went unread")
	}
}

func TestTotalCounts(t *testing.T) {
	got := totalCounts(securityv1alpha1.SeverityCounts{
		Critical: 1, High: 2, Medium: 3, Low: 4, Unknown: 5,
	})
	if got != 15 {
		t.Errorf("totalCounts = %d, want 15", got)
	}
	if totalCounts(securityv1alpha1.SeverityCounts{}) != 0 {
		t.Error("empty counts did not total zero")
	}
}
