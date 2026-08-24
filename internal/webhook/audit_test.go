package webhook

import (
	"context"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

func recordingGate(t *testing.T, objects ...runtime.Object) (*ModelGate, *audit.Recorder) {
	t.Helper()
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	rec := &audit.Recorder{Client: c, Namespace: testNamespace}
	return &ModelGate{Client: c, Recorder: rec, ReportNamespace: testNamespace}, rec
}

func chainOf(t *testing.T, gate *ModelGate) []securityv1alpha1.AuditRecord {
	t.Helper()
	list := &securityv1alpha1.AuditRecordList{}
	if err := gate.Client.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

// The event an authorizing official asks about first is when a model was
// refused production. audit.DeploymentDecision and the DeploymentBlocked type
// existed from the start and nothing called them.
func TestDeniedDeploymentIsRecorded(t *testing.T) {
	gate, _ := recordingGate(t, report("fraud", "v3", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))

	req := deployment(map[string]string{AnnotationModel: "fraud", AnnotationVersion: "v3"})
	req.UserInfo = authenticationv1.UserInfo{Username: "alice@davano.net"}
	resp := gate.Handle(context.Background(), req)
	if resp.Allowed {
		t.Fatal("a quarantined model must be denied")
	}

	records := chainOf(t, gate)
	if len(records) != 1 {
		t.Fatalf("expected one audit record, got %d", len(records))
	}
	r := records[0]
	if r.Spec.Type != string(audit.EventDeploymentBlocked) {
		t.Errorf("type %q", r.Spec.Type)
	}
	if r.Spec.Actor != "alice@davano.net" {
		t.Errorf("the record must name who tried, got %q", r.Spec.Actor)
	}
	if !strings.Contains(r.Spec.Subject, "fraud") {
		t.Errorf("subject %q", r.Spec.Subject)
	}
	if r.Spec.Hash == "" || r.Spec.PrevHash == "" {
		t.Error("the record must be sealed into the chain")
	}
}

// An ordinary approval is already implied by the VerdictIssued record it rests
// on, and recording one per pod would turn a scale-up into API contention
// inside a webhook.
func TestOrdinaryApprovalIsNotRecorded(t *testing.T) {
	gate, _ := recordingGate(t, report("fraud", "v1", nil))

	resp := gate.Handle(context.Background(),
		deployment(map[string]string{AnnotationModel: "fraud", AnnotationVersion: "v1"}))
	if !resp.Allowed {
		t.Fatalf("an approved model must be admitted: %v", resp.Result)
	}
	if n := len(chainOf(t, gate)); n != 0 {
		t.Fatalf("a routine approval should not append to the chain, got %d records", n)
	}
}

// The admissions that must be recorded are the ones nobody can reconstruct:
// they happened despite something.
func TestAdmissionsThatHappenedAnywayAreRecorded(t *testing.T) {
	cases := map[string]struct {
		annotations map[string]string
		wantDetail  string
	}{
		"unscanned model": {
			annotations: map[string]string{AnnotationModel: "unknown", AnnotationVersion: "v9"},
			wantDetail:  "no security report",
		},
		"skip annotation": {
			annotations: map[string]string{AnnotationModel: "fraud", AnnotationSkip: "true"},
			wantDetail:  "skip-validation",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gate, _ := recordingGate(t)
			resp := gate.Handle(context.Background(), deployment(tc.annotations))
			if !resp.Allowed {
				t.Fatalf("expected admission, got %v", resp.Result)
			}
			records := chainOf(t, gate)
			if len(records) != 1 {
				t.Fatalf("expected one record, got %d", len(records))
			}
			if records[0].Spec.Type != string(audit.EventDeploymentAdmitted) {
				t.Errorf("type %q", records[0].Spec.Type)
			}
			if !strings.Contains(records[0].Spec.Detail["reason"], tc.wantDetail) {
				t.Errorf("reason %q should mention %q",
					records[0].Spec.Detail["reason"], tc.wantDetail)
			}
		})
	}
}

// A workload serving a model it will not name is admitted with a warning, and
// that admission is exactly the kind nothing else in the trail explains.
func TestUnidentifiedModelAdmissionIsRecorded(t *testing.T) {
	gate, _ := recordingGate(t)
	resp := gate.Handle(context.Background(), servingDeployment(t, map[string]any{
		"containers": []any{map[string]any{
			"name": "server", "image": "vllm/vllm-openai:v0.7.0",
			"args": []any{"--model", "/models/llama3"},
		}},
	}))
	if !resp.Allowed {
		t.Fatal("without RequireReport this admits")
	}
	records := chainOf(t, gate)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if !strings.Contains(records[0].Spec.Detail["reason"], "does not identify") {
		t.Errorf("reason %q", records[0].Spec.Detail["reason"])
	}
	// The subject has to be something, or the record cannot be found later.
	if records[0].Spec.Subject == "" {
		t.Error("a record with no subject cannot be looked up")
	}
}

// Losing the paper trail must not change the decision. A gate that errors
// because it could not write a record hands the failurePolicy a decision it
// was never asked to make.
func TestAuditFailureDoesNotChangeTheDecision(t *testing.T) {
	gate, _ := recordingGate(t, report("fraud", "v3", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))
	// A recorder pointed at a client that cannot serve AuditRecords.
	gate.Recorder = &audit.Recorder{
		Client:    fake.NewClientBuilder().Build(),
		Namespace: testNamespace,
	}

	resp := gate.Handle(context.Background(),
		deployment(map[string]string{AnnotationModel: "fraud", AnnotationVersion: "v3"}))
	if resp.Allowed {
		t.Fatal("a failed audit write must not turn a denial into an admission")
	}
	if resp.Result != nil && resp.Result.Code >= 500 {
		t.Fatalf("a failed audit write must not become a webhook error, got %d", resp.Result.Code)
	}
}

// A cluster without the audit CRDs runs with no recorder at all, and the gate
// still gates.
func TestGateWorksWithoutARecorder(t *testing.T) {
	gate := newGate(t, report("fraud", "v3", func(r *securityv1alpha1.ModelSecurityReport) {
		r.Status.Verdict = securityv1alpha1.VerdictQuarantined
	}))
	gate.ReportNamespace = testNamespace
	resp := gate.Handle(context.Background(),
		deployment(map[string]string{AnnotationModel: "fraud", AnnotationVersion: "v3"}))
	if resp.Allowed {
		t.Fatal("the gate must still deny with no recorder configured")
	}
}
