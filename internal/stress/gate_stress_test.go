//go:build stress

package stress

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/maintenance"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

func gateRequest(t testing.TB, model, version string) admission.Request {
	t.Helper()
	// The kind, the annotation placement and the report name all have to be
	// right or the gate fails closed on a decode error and the test measures
	// nothing. This mirrors the integration test, which learned that the hard
	// way.
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "serving", Namespace: "ml",
			Annotations: map[string]string{
				cupelwebhook.AnnotationModel:   model,
				cupelwebhook.AnnotationVersion: version,
			},
		},
	}
	raw, err := json.Marshal(dep)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Namespace: "ml",
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

// A rollout admits many pods at once. The gate is in the same process as the
// manager and shares its client, so this is where a slow path becomes a stalled
// deployment — or, with failurePolicy Ignore, a silently open gate.
func TestGateUnderConcurrentAdmission(t *testing.T) {
	scheme := stressScheme(t)

	const models = 200
	objs := make([]client.Object, 0, models)
	for i := 0; i < models; i++ {
		name := fmt.Sprintf("model-%03d", i)
		rep := &securityv1alpha1.ModelSecurityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: controller.ModelReportName(name, "v1"), Namespace: "ml",
			},
			Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: name, ModelVersion: "v1"},
		}
		if i%2 == 0 {
			rep.Status.Verdict = "Blocked"
			rep.Status.RiskScore = 90
		} else {
			rep.Status.Verdict = "Approved"
			rep.Status.RiskScore = 5
		}
		rep.Status.LastScanTime = &metav1.Time{Time: time.Now()}
		objs = append(objs, rep)
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	recorder := &audit.Recorder{Client: c, Namespace: "ml"}
	gate := &cupelwebhook.ModelGate{Client: c, Recorder: recorder}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}

	const workers, each = 32, 40
	var allowed, denied, wrong int64

	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				idx := (w*each + i) % models
				name := fmt.Sprintf("model-%03d", idx)
				resp := gate.Handle(context.Background(), gateRequest(t, name, "v1"))
				shouldBlock := idx%2 == 0
				if resp.Allowed {
					atomic.AddInt64(&allowed, 1)
					if shouldBlock {
						atomic.AddInt64(&wrong, 1)
					}
				} else {
					atomic.AddInt64(&denied, 1)
					if !shouldBlock {
						atomic.AddInt64(&wrong, 1)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := int64(workers * each)
	t.Logf("%d admissions across %d workers in %s (%.0f/s): %d allowed, %d denied",
		total, workers, elapsed.Round(time.Millisecond),
		float64(total)/elapsed.Seconds(), allowed, denied)

	if wrong > 0 {
		t.Fatalf("%d admissions got the wrong answer under concurrency: the gate is not "+
			"deciding consistently", wrong)
	}

	// The chain records every denial and every admission that happened despite
	// something — not ordinary approvals, which the verdict record already
	// implies and which would put chain contention on the webhook's hot path.
	records, cp, err := recorder.Chain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("audit chain holds %d records for %d decisions (%d denials, %d ordinary approvals)",
		len(records), total, denied, allowed)

	if v := audit.VerifyFrom(records, cp.Anchor(), cp); !v.Valid {
		t.Fatalf("the chain written under admission load does not verify: %v", v.Problems)
	}
	if int64(len(records)) != denied {
		t.Errorf("%d denials were issued but %d reached the audit chain: %d refusals are "+
			"unrecorded", denied, len(records), denied-int64(len(records)))
	}
	for _, r := range records {
		if r.Type != audit.EventDeploymentBlocked {
			t.Errorf("unexpected record type %q in the chain", r.Type)
			break
		}
	}
}

// Retention at the size a long-running cluster actually reaches.
func TestRetentionAtClusterScale(t *testing.T) {
	scheme := stressScheme(t)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	// Three years of a busy cluster: 500 model versions a week.
	const weeks, perWeek = 156, 500
	objs := make([]client.Object, 0, weeks*perWeek)
	for w := 0; w < weeks; w++ {
		done := metav1.NewTime(now.Add(-time.Duration(weeks-w) * 7 * 24 * time.Hour))
		for i := 0; i < perWeek; i++ {
			s := &securityv1alpha1.ArtifactScan{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("s-%03d-%03d", w, i), Namespace: "ml",
				},
				Spec: securityv1alpha1.ArtifactScanSpec{
					ModelName: fmt.Sprintf("m-%03d-%03d", w, i), ModelVersion: "v1",
				},
			}
			s.Status.Phase = "Completed"
			s.Status.CompletionTime = &done
			objs = append(objs, s)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	p := &maintenance.Pruner{Client: c, Now: func() time.Time { return now }}
	start := time.Now()
	pruned, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	var left securityv1alpha1.ArtifactScanList
	if err := c.List(context.Background(), &left); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d scans (three years at %d/week): pruned %d in %s, %d remain",
		len(objs), perWeek, pruned, elapsed.Round(time.Millisecond), len(left.Items))

	if elapsed > 60*time.Second {
		t.Errorf("retention took %s over %d objects: it would not finish inside a "+
			"maintenance window", elapsed, len(objs))
	}
	// Ninety days is about thirteen weeks.
	if len(left.Items) > 14*perWeek {
		t.Errorf("%d scans left, expected about %d", len(left.Items), 13*perWeek)
	}
}
