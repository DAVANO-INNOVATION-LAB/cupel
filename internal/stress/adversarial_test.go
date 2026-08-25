//go:build stress

package stress

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

// Known limitation, recorded so it cannot be mistaken for working.
//
// An approval has no expiry. A model version is a mutable pointer in most
// registries — a branch, a tag — so the bytes behind an approved name can be
// replaced after the approval was given, and the verdict still stands.
//
// There is a partial guard: the gate compares digests when the workload and the
// report both state one. Workloads usually state nothing, because the digest in
// a registry reference is whatever the registry claimed, and that is generally
// empty. So in the common case there is nothing to compare and nothing to
// expire.
//
// Bounding it is a decision, not a patch: any maximum age refuses workloads
// that are admitted today. This test says out loud what the current answer is.
func TestApprovalsHaveNoMaximumAge(t *testing.T) {
	scheme := stressScheme(t)

	for _, age := range []time.Duration{
		time.Hour, 30 * 24 * time.Hour, 365 * 24 * time.Hour, 10 * 365 * 24 * time.Hour,
	} {
		rep := &securityv1alpha1.ModelSecurityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: controller.ModelReportName("m", "v1"), Namespace: "ml",
			},
			Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: "m", ModelVersion: "v1"},
		}
		rep.Status.Verdict = "Approved"
		rep.Status.RiskScore = 1
		rep.Status.LastScanTime = &metav1.Time{Time: time.Now().Add(-age)}

		gate := &cupelwebhook.ModelGate{
			Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(rep).Build(),
			RequireReport: true,
		}
		if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
			t.Fatal(err)
		}
		resp := gate.Handle(context.Background(), gateRequest(t, "m", "v1"))
		t.Logf("approval from %-6s ago -> admitted=%v", roughly(age), resp.Allowed)

		if !resp.Allowed {
			t.Errorf("a %s-old approval is now refused — the limitation is closed and this "+
				"test should be replaced by one asserting the bound", roughly(age))
		}
	}
}

func roughly(d time.Duration) string {
	switch {
	case d >= 365*24*time.Hour:
		return fmt.Sprintf("%dy", int(d.Hours()/24/365))
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	default:
		return d.String()
	}
}

// An exception waives findings. It must waive them only for what it names, and
// only while it is valid.
//
// The two halves are enforced in different places, which is why both are
// checked here through the path the controllers actually take: scope by the
// filter that selects which exceptions are even considered, expiry by the gate
// itself.
func TestExceptionsAreBoundedByScopeAndTime(t *testing.T) {
	findings := []securityv1alpha1.ScannerResult{{
		Scanner: "model-inspector", Status: "Passed", Findings: 1,
		Severities: securityv1alpha1.SeverityCounts{Critical: 1},
	}}
	artifact := securityv1alpha1.ArtifactRef{URI: "pvc://claim/m"}

	strict := &securityv1alpha1.ArtifactScanPolicy{}
	strict.Spec.Rules = securityv1alpha1.PolicyRules{BlockUnsafeModel: boolp(true)}

	base := policy.Evaluate(findings, artifact, strict, nil, time.Now())
	t.Logf("with no exception: verdict=%s violations=%d", base.Verdict, len(base.Violations))
	if base.Verdict == "Approved" {
		t.Fatal("precondition: a critical model finding under BlockUnsafeModel should not approve")
	}

	mk := func(model, version string, expires *metav1.Time) securityv1alpha1.ArtifactException {
		e := securityv1alpha1.ArtifactException{
			ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ml"},
			Spec: securityv1alpha1.ArtifactExceptionSpec{
				ModelName: model, ModelVersion: version, Reason: "reviewed",
				Rules: []string{"blockUnsafeModel"},
			},
		}
		e.Spec.ExpiresAt = expires
		return e
	}
	past := &metav1.Time{Time: time.Now().Add(-24 * time.Hour)}
	future := &metav1.Time{Time: time.Now().Add(24 * time.Hour)}

	cases := []struct {
		name      string
		exception securityv1alpha1.ArtifactException
		mayWaive  bool
	}{
		{"for this model, unexpired", mk("m", "v1", future), true},
		{"for this model, expired yesterday", mk("m", "v1", past), false},
		{"for a different model", mk("other", "v1", future), false},
		{"for a different version", mk("m", "v2", future), false},
		{"for no model at all", mk("", "", future), false},
		{"model name as a wildcard", mk("*", "*", future), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The controllers narrow the namespace's exceptions before the
			// policy ever sees them. Going straight to Evaluate would skip the
			// half of the enforcement that lives in that filter.
			scoped := policy.ExceptionsFor(
				[]securityv1alpha1.ArtifactException{tc.exception}, "m", "v1")

			eval := policy.Evaluate(findings, artifact, strict, scoped, time.Now())
			waived := eval.Verdict == "Approved" || len(eval.Waived) > 0
			t.Logf("considered=%d verdict=%s violations=%d waived=%d",
				len(scoped), eval.Verdict, len(eval.Violations), len(eval.Waived))

			if waived && !tc.mayWaive {
				t.Errorf("an exception %s suppressed the finding", tc.name)
			}
			if !waived && tc.mayWaive {
				t.Errorf("a valid exception %s did not apply", tc.name)
			}
		})
	}
}

// The gate reads objects it did not create. Anything it cannot make sense of
// has to end in a decision, not a panic.
func TestMalformedAdmissionInputIsHandled(t *testing.T) {
	scheme := stressScheme(t)
	gate := &cupelwebhook.ModelGate{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
	}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}

	huge := strings.Repeat("a", 1<<20)
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty object", []byte(``)},
		{"empty json", []byte(`{}`)},
		{"json null", []byte(`null`)},
		{"not json at all", []byte(`<xml/>`)},
		{"truncated json", []byte(`{"apiVersion":"apps/v1","kind":"Deploy`)},
		{"an array where an object belongs", []byte(`[1,2,3]`)},
		{"deeply nested", []byte(strings.Repeat(`{"a":`, 2000) + `1` + strings.Repeat(`}`, 2000))},
		{"a megabyte model name", mustJSON(deploymentWith(map[string]string{
			cupelwebhook.AnnotationModel: huge, cupelwebhook.AnnotationVersion: "v1"}))},
		{"null bytes in the model name", mustJSON(deploymentWith(map[string]string{
			cupelwebhook.AnnotationModel: "a\x00b", cupelwebhook.AnnotationVersion: "v1"}))},
		{"newlines in the model name", mustJSON(deploymentWith(map[string]string{
			cupelwebhook.AnnotationModel: "a\nadmitted: true\nb", cupelwebhook.AnnotationVersion: "v1"}))},
		{"unicode right-to-left override", mustJSON(deploymentWith(map[string]string{
			cupelwebhook.AnnotationModel: "safe‮gnorw", cupelwebhook.AnnotationVersion: "v1"}))},
		{"empty annotations", mustJSON(deploymentWith(map[string]string{}))},
		{"only a version", mustJSON(deploymentWith(map[string]string{
			cupelwebhook.AnnotationVersion: "v1"}))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan admission.Response, 1)
			var perr any
			go func() {
				defer func() { perr = recover(); close(done) }()
				done <- gate.Handle(context.Background(), admission.Request{
					AdmissionRequest: admissionv1.AdmissionRequest{
						Operation: admissionv1.Create, Namespace: "ml",
						Object: runtime.RawExtension{Raw: tc.raw},
					}})
			}()

			select {
			case resp := <-done:
				t.Logf("allowed=%v", resp.Allowed)
			case <-time.After(15 * time.Second):
				t.Fatal("the gate did not answer in 15s: a malformed object hangs admission")
			}
			if perr != nil {
				t.Fatalf("the gate panicked on malformed input: %v", perr)
			}
		})
	}
}

func deploymentWith(annotations map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "serving", Namespace: "ml", Annotations: annotations,
		},
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("fixture will not marshal: %v", err))
	}
	return b
}

func boolp(b bool) *bool { return &b }
