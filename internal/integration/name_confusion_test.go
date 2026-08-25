package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

// One model's verdict must never be applied to a different model.
//
// Object names are derived from registry identifiers, and deriving them loses
// information: "acme/fraud" and "acme-fraud" flatten to the same string. Before
// this was checked, a workload for a model that had never been scanned was
// admitted with the message "model acme/fraud version v1 approved (risk score
// 3)" — naming the attacker's model in an approval it had not earned, so even
// the audit trail read as legitimate.
func TestAVerdictIsNotInheritedByANeighbouringName(t *testing.T) {
	scheme := admissionScheme(t)
	ctx := context.Background()

	const approved, attacker = "acme-fraud", "acme/fraud"

	nameA := controller.ModelReportName(approved, "v1")
	nameB := controller.ModelReportName(attacker, "v1")
	if nameA != nameB {
		t.Logf("names no longer collide (%s vs %s); the derivation was fixed", nameA, nameB)
	} else {
		t.Logf("both models derive report name %s", nameA)
	}

	report := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: nameA, Namespace: "ml"},
		Spec: securityv1alpha1.ModelSecurityReportSpec{
			ModelName: approved, ModelVersion: "v1",
		},
	}
	report.Status.Verdict = "Approved"
	report.Status.RiskScore = 3
	report.Status.LastScanTime = &metav1.Time{Time: time.Now()}

	for _, tc := range []struct {
		name          string
		requireReport bool
		wantAdmitted  bool
	}{
		{"with require-report off, the operator's default", false, true},
		{"with require-report on", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := &cupelwebhook.ModelGate{
				Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
				RequireReport: tc.requireReport,
			}
			if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
				t.Fatal(err)
			}
			resp := gate.Handle(ctx, deploymentFor(t, attacker, "v1"))
			msg := resp.Result.Message
			t.Logf("admitted=%v reason=%q", resp.Allowed, msg)

			// The point is not whether it was admitted — that is the operator's
			// choice — but that it was never treated as approved.
			if strings.Contains(msg, "approved") {
				t.Errorf("the attacker's model was reported as approved on the strength "+
					"of a different model's scan: %q", msg)
			}
			if resp.Allowed != tc.wantAdmitted {
				t.Errorf("admitted=%v, want %v (%q)", resp.Allowed, tc.wantAdmitted, msg)
			}
		})
	}
}

// The legitimate model must still find its own report.
func TestTheModelTheReportIsAboutStillPasses(t *testing.T) {
	scheme := admissionScheme(t)

	report := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.ModelReportName("acme-fraud", "v1"), Namespace: "ml",
		},
		Spec: securityv1alpha1.ModelSecurityReportSpec{
			ModelName: "acme-fraud", ModelVersion: "v1",
		},
	}
	report.Status.Verdict = "Approved"
	report.Status.RiskScore = 3
	report.Status.LastScanTime = &metav1.Time{Time: time.Now()}

	gate := &cupelwebhook.ModelGate{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
		RequireReport: true,
	}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	resp := gate.Handle(context.Background(), deploymentFor(t, "acme-fraud", "v1"))
	if !resp.Allowed {
		t.Fatalf("the model the report is actually about was refused: %q", resp.Result.Message)
	}
}

// A blocked model must not be admitted because a neighbour was approved.
func TestABlockedModelCannotBeRescuedByANeighbour(t *testing.T) {
	scheme := admissionScheme(t)

	// Both flatten to the same object name; the approved one wrote last.
	shared := controller.ModelReportName("acme-fraud", "v1")
	report := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: shared, Namespace: "ml"},
		Spec: securityv1alpha1.ModelSecurityReportSpec{
			ModelName: "acme-fraud", ModelVersion: "v1",
		},
	}
	report.Status.Verdict = "Approved"
	report.Status.RiskScore = 2
	report.Status.LastScanTime = &metav1.Time{Time: time.Now()}

	gate := &cupelwebhook.ModelGate{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
		RequireReport: true,
	}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	resp := gate.Handle(context.Background(), deploymentFor(t, "acme/fraud", "v1"))
	if resp.Allowed {
		t.Fatalf("a model with no report of its own was admitted using a neighbour's: %q",
			resp.Result.Message)
	}
}
