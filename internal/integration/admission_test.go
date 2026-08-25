package integration

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

// The chain nothing tested: a real model on disk, through the real scanner, the
// real policy gate, into a real ModelSecurityReport, past the real admission
// webhook.
//
// Both halves existed. The integration tests ran a model through the scanner and
// stopped at a verdict; the webhook tests started from a report someone typed.
// Between them sat the only claim that distinguishes this from every other
// scanner in the field — that it refuses to let the workload start — and nothing
// exercised it end to end.
//
// This runs the whole path over a generated corpus, because one malicious model
// proves the wiring and a few thousand prove it holds.

// modelSpec describes one artifact to build and what should become of it.
type modelSpec struct {
	name string
	// hostile marks a model that must not reach a workload.
	hostile bool
	files   map[string][]byte
}

func maliciousPickleBytes() []byte {
	return []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")
}

// cleanSafetensors is a real header over inert weight bytes.
func cleanSafetensors() []byte {
	hdr := []byte(`{"__metadata__":{"format":"pt","license":"mit"},` +
		`"w":{"dtype":"F16","shape":[8,8],"data_offsets":[0,128]}}`)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(len(hdr)))
	return append(append(buf, hdr...), make([]byte, 128)...)
}

// corpus builds a mix weighted toward the dangerous, because the failure that
// matters is a hostile model admitted, not a clean one refused.
func corpus(n int) []modelSpec {
	out := make([]modelSpec, 0, n)
	for i := 0; i < n; i++ {
		s := modelSpec{name: fmt.Sprintf("m%05d", i), files: map[string][]byte{}}
		switch i % 5 {
		case 0: // pickle weights: executes on load
			s.hostile = true
			s.files["pytorch_model.bin"] = maliciousPickleBytes()
			s.files["config.json"] = []byte(`{"model_type":"llama"}`)
		case 1: // remote code enabled
			s.hostile = true
			s.files["model.safetensors"] = cleanSafetensors()
			s.files["config.json"] = []byte(`{"model_type":"llama","trust_remote_code":true}`)
		case 2: // a pickle sitting beside safe weights
			s.hostile = true
			s.files["model.safetensors"] = cleanSafetensors()
			s.files["tokenizer.pkl"] = maliciousPickleBytes()
			s.files["config.json"] = []byte(`{"model_type":"llama"}`)
		case 3: // both at once
			s.hostile = true
			s.files["pytorch_model.bin"] = maliciousPickleBytes()
			s.files["config.json"] = []byte(`{"model_type":"llama","trust_remote_code":true}`)
		default: // clean
			s.files["model.safetensors"] = cleanSafetensors()
			s.files["config.json"] = []byte(`{"model_type":"llama","torch_dtype":"float16"}`)
		}
		out = append(out, s)
	}
	return out
}

func writeSpec(t *testing.T, root string, s modelSpec) string {
	t.Helper()
	dir := filepath.Join(root, s.name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range s.files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func admissionScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	sc := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(sc); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(sc); err != nil {
		t.Fatal(err)
	}
	return sc
}

// deploymentFor builds an admission request for a workload referencing a model.
func deploymentFor(t *testing.T, model, version string) admission.Request {
	t.Helper()
	// Three things had to be right here before this test measured anything,
	// and each was wrong in turn: the kind (the decoder fails closed without
	// it), the report name (the gate derives it), and where the annotations
	// live — on the workload's own metadata, which is what obj.GetAnnotations
	// reads, not on the pod template.
	dep := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "serving",
			Namespace: "ml",
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

func TestHostileModelsAreRefusedAdmissionEndToEnd(t *testing.T) {
	const n = 3000
	root := t.TempDir()
	specs := corpus(n)
	scheme := admissionScheme(t)

	var (
		hostile, clean            int
		blocked, admitted         int
		cleanBlocked, cleanPassed int
		start                     = time.Now()
	)

	for _, s := range specs {
		dir := writeSpec(t, root, s)

		// 1. the real scanner
		result := runInspectorStage(t, dir)

		// 2. the real policy gate
		eval := policy.Evaluate(
			[]securityv1alpha1.ScannerResult{result},
			securityv1alpha1.ArtifactRef{URI: "pvc://claim/" + s.name},
			nil, nil, time.Now(),
		)

		// 3. a report carrying that verdict, as the controller would write it
		// The name the gate derives, not one of our choosing. Getting this
		// wrong made an earlier run report every hostile model admitted: the
		// report was never found, so the gate took its no-report path and
		// allowed the workload.
		report := &securityv1alpha1.ModelSecurityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      controller.ModelReportName(s.name, "v1"),
				Namespace: "ml",
			},
			Spec: securityv1alpha1.ModelSecurityReportSpec{
				ModelName: s.name, ModelVersion: "v1",
			},
		}
		report.Status.Verdict = eval.Verdict
		report.Status.RiskScore = eval.RiskScore
		report.Status.LastScanTime = &metav1.Time{Time: time.Now()}

		// 4. the real admission webhook
		gate := &cupelwebhook.ModelGate{
			Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
		}
		if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
			t.Fatal(err)
		}
		resp := gate.Handle(context.Background(), deploymentFor(t, s.name, "v1"))

		if s.hostile {
			hostile++
			if resp.Allowed {
				admitted++
				if admitted <= 3 {
					t.Errorf("HOSTILE MODEL ADMITTED: %s verdict=%s risk=%d",
						s.name, eval.Verdict, eval.RiskScore)
				}
			} else {
				blocked++
			}
		} else {
			clean++
			if resp.Allowed {
				cleanPassed++
			} else {
				cleanBlocked++
			}
		}
	}

	t.Logf("%d models in %s", n, time.Since(start).Round(time.Millisecond))
	t.Logf("hostile: %d  blocked: %d  ADMITTED: %d", hostile, blocked, admitted)
	t.Logf("clean:   %d  admitted: %d  blocked: %d", clean, cleanPassed, cleanBlocked)

	if admitted != 0 {
		t.Fatalf("%d hostile models reached a workload", admitted)
	}
	if blocked != hostile {
		t.Fatalf("blocked %d of %d hostile models", blocked, hostile)
	}
}

// A control, so the test above cannot pass for a trivial reason.
//
// With no report present the gate takes its no-report path, which admits unless
// a report is required. If the main test's blocking came from anything other
// than the verdict, this would block too — and it must not.
func TestWithoutAReportTheGateTakesItsNoReportPath(t *testing.T) {
	root := t.TempDir()
	s := corpus(1)[0] // a pickle model: as hostile as they get
	writeSpec(t, root, s)
	scheme := admissionScheme(t)

	gate := &cupelwebhook.ModelGate{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
	}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	resp := gate.Handle(context.Background(), deploymentFor(t, s.name, "v1"))
	if !resp.Allowed {
		t.Fatalf("with no report the gate denied: %q — the main test's blocking "+
			"may not be coming from the verdict", resp.Result.Message)
	}
	if !strings.Contains(resp.Result.Message, "no Cupel security report") {
		t.Errorf("unexpected admit reason: %q", resp.Result.Message)
	}
}
