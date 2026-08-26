package webhook

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
)

var freshNow = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func reportAged(t *testing.T, verdict string, age time.Duration, withScanTime bool) *securityv1alpha1.ModelSecurityReport {
	t.Helper()
	r := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.ModelReportName("m", "v1"), Namespace: testNamespace,
		},
		Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: "m", ModelVersion: "v1"},
	}
	r.Status.Verdict = verdict
	r.Status.RiskScore = 3
	if withScanTime {
		r.Status.LastScanTime = &metav1.Time{Time: freshNow.Add(-age)}
	}
	return r
}

func gateWith(t *testing.T, report *securityv1alpha1.ModelSecurityReport, max time.Duration) *ModelGate {
	t.Helper()
	scheme := testScheme(t)
	g := &ModelGate{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
		RequireReport: true,
		MaxReportAge:  max,
		Now:           func() time.Time { return freshNow },
	}
	if err := g.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	return g
}

// Off by default: an install that does not ask for freshness must behave
// exactly as it did before this existed.
func TestWithNoLimitAnApprovalNeverExpires(t *testing.T) {
	g := gateWith(t, reportAged(t, "Approved", 10*365*24*time.Hour, true), 0)
	resp := g.Handle(context.Background(), deployment(map[string]string{AnnotationModel: "m", AnnotationVersion: "v1"}))
	if !resp.Allowed {
		t.Fatalf("a ten-year-old approval was refused with no limit set: %q", resp.Result.Message)
	}
}

func TestAnApprovalOlderThanTheLimitIsRefused(t *testing.T) {
	for _, limit := range []struct {
		name string
		max  time.Duration
	}{
		{"180 days", 180 * 24 * time.Hour},
		{"365 days", 365 * 24 * time.Hour},
	} {
		t.Run(limit.name, func(t *testing.T) {
			within := gateWith(t, reportAged(t, "Approved", limit.max-24*time.Hour, true), limit.max)
			if r := within.Handle(context.Background(), deployment(map[string]string{AnnotationModel: "m", AnnotationVersion: "v1"})); !r.Allowed {
				t.Errorf("a scan one day inside the limit was refused: %q", r.Result.Message)
			}

			beyond := gateWith(t, reportAged(t, "Approved", limit.max+24*time.Hour, true), limit.max)
			r := beyond.Handle(context.Background(), deployment(map[string]string{AnnotationModel: "m", AnnotationVersion: "v1"}))
			if r.Allowed {
				t.Fatal("a scan one day past the limit was admitted")
			}
			if !strings.Contains(r.Result.Message, "rescan") {
				t.Errorf("the refusal does not say what to do about it: %q", r.Result.Message)
			}
		})
	}
}

// Staleness may only take an approval away. A denial that has gone stale is
// still a denial, and must not be reported as an expiry.
func TestStalenessDoesNotRescueADenial(t *testing.T) {
	for _, verdict := range []string{"Quarantined", "ReviewRequired"} {
		g := gateWith(t, reportAged(t, verdict, 5*365*24*time.Hour, true), 180*24*time.Hour)
		r := g.Handle(context.Background(), deployment(map[string]string{AnnotationModel: "m", AnnotationVersion: "v1"}))
		if r.Allowed {
			t.Errorf("a stale %s verdict admitted the workload", verdict)
		}
		if strings.Contains(r.Result.Message, "freshness") {
			t.Errorf("a %s verdict was reported as an expiry rather than a refusal: %q",
				verdict, r.Result.Message)
		}
	}
}

// An approval that cannot be dated cannot be shown to be fresh. Under an
// explicit limit the honest answer is to refuse it, not to assume.
func TestAnUndatedApprovalIsRefusedUnderALimit(t *testing.T) {
	g := gateWith(t, reportAged(t, "Approved", 0, false), 180*24*time.Hour)
	r := g.Handle(context.Background(), deployment(map[string]string{AnnotationModel: "m", AnnotationVersion: "v1"}))
	if r.Allowed {
		t.Fatal("an approval with no scan time was admitted under a freshness limit")
	}

	// ...but with no limit configured it must still behave as before.
	off := gateWith(t, reportAged(t, "Approved", 0, false), 0)
	if r := off.Handle(context.Background(), deployment(map[string]string{AnnotationModel: "m", AnnotationVersion: "v1"})); !r.Allowed {
		t.Fatal("an undated approval was refused with no limit set")
	}
}
