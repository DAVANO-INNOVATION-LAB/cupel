package webhook

import (
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func objectFrom(t *testing.T, doc string) *unstructured.Unstructured {
	t.Helper()
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal([]byte(doc), &obj.Object); err != nil {
		t.Fatal(err)
	}
	return obj
}

// The case the gate used to admit with "nothing for cupel to validate": a
// plain Deployment with no annotations, a serving runtime image, and a claim
// full of weights mounted into it.
func TestDeploymentServingFromAPersistentVolumeIsSeen(t *testing.T) {
	obj := objectFrom(t, `{
	  "kind": "Deployment",
	  "spec": {"template": {"spec": {
	    "containers": [{
	      "name": "server",
	      "image": "vllm/vllm-openai:v0.7.0",
	      "volumeMounts": [{"name": "weights", "mountPath": "/models/llama3"}]
	    }],
	    "volumes": [{"name": "weights", "persistentVolumeClaim": {"claimName": "model-store"}}]
	  }}}
	}`)

	evidence := discoverModelEvidence(obj)
	if len(evidence) == 0 {
		t.Fatal("a vLLM image with weights mounted at /models is a model-serving workload")
	}
	// It must not resolve to a model: nothing here names one, and a guess
	// would address another model's report.
	if ref := refFromEvidence(evidence); ref.Model != "" {
		t.Errorf("nothing names a model, so none should be derived; got %+v", ref)
	}
}

// A storage URI in the environment is the case the gate can act on: it names
// something a resolver could have fetched, so it resolves to the same report
// name a KServe workload would.
func TestStorageURIInEnvironmentResolvesToAModel(t *testing.T) {
	obj := objectFrom(t, `{
	  "kind": "Deployment",
	  "spec": {"template": {"spec": {"containers": [{
	    "name": "server",
	    "image": "quay.io/example/serve:1",
	    "env": [{"name": "STORAGE_URI", "value": "s3://bucket/fraud/v3"}]
	  }]}}}
	}`)

	ref := refFromEvidence(discoverModelEvidence(obj))
	if ref.Model != "fraud" || ref.Version != "v3" {
		t.Fatalf("expected fraud/v3, got %+v", ref)
	}
}

// A bare filesystem path and a Hugging Face identifier both split into a
// plausible model and version under the KServe convention and would address
// the wrong report. Admitting a workload on another model's clean verdict is
// worse than admitting it with a warning.
func TestAmbiguousModelReferencesDoNotResolve(t *testing.T) {
	for _, value := range []string{"/models/llama3", "meta-llama/Llama-3-8B", "llama3:8b"} {
		obj := objectFrom(t, `{
		  "kind": "Deployment",
		  "spec": {"template": {"spec": {"containers": [{
		    "name": "server", "image": "vllm/vllm-openai:v0.7.0",
		    "args": ["--model", "`+value+`"]
		  }]}}}
		}`)
		evidence := discoverModelEvidence(obj)
		if len(evidence) == 0 {
			t.Errorf("%s: --model is evidence of a model-serving workload", value)
		}
		if ref := refFromEvidence(evidence); ref.Model != "" {
			t.Errorf("%s resolved to %+v; it is not a storage URI and must not be guessed at",
				value, ref)
		}
	}
}

// An environment variable set from a ConfigMap or Secret is still evidence,
// and its value must not be invented.
func TestValueFromIsEvidenceWithoutAValue(t *testing.T) {
	obj := objectFrom(t, `{
	  "kind": "Deployment",
	  "spec": {"template": {"spec": {"containers": [{
	    "name": "server", "image": "quay.io/example/serve:1",
	    "env": [{"name": "MODEL_URI", "valueFrom": {"configMapKeyRef": {"name": "cfg", "key": "uri"}}}]
	  }]}}}
	}`)

	evidence := discoverModelEvidence(obj)
	if len(evidence) != 1 {
		t.Fatalf("expected one piece of evidence, got %v", evidence)
	}
	if !strings.Contains(evidence[0].Detail, "cannot read") {
		t.Errorf("the response should say the value was unreadable, got %q", evidence[0].Detail)
	}
	if evidence[0].URI != "" {
		t.Error("a value Cupel cannot read must not become a URI")
	}
}

// An initContainer that stages the model is how a great many serving pods are
// built, and it is not in the containers list.
func TestInitContainersAreExamined(t *testing.T) {
	obj := objectFrom(t, `{
	  "kind": "StatefulSet",
	  "spec": {"template": {"spec": {
	    "initContainers": [{
	      "name": "fetch", "image": "amazon/aws-cli",
	      "env": [{"name": "MODEL_URI", "value": "s3://bucket/fraud/v3"}]
	    }],
	    "containers": [{"name": "server", "image": "quay.io/example/serve:1"}]
	  }}}
	}`)

	ref := refFromEvidence(discoverModelEvidence(obj))
	if ref.Model != "fraud" {
		t.Fatalf("an initContainer staging the model must be seen, got %+v", ref)
	}
}

func TestPodAndCronJobShapesAreUnderstood(t *testing.T) {
	pod := objectFrom(t, `{
	  "kind": "Pod",
	  "spec": {"containers": [{"name": "s", "image": "ollama/ollama:latest"}]}
	}`)
	if len(discoverModelEvidence(pod)) == 0 {
		t.Error("a bare Pod running a serving runtime must be seen")
	}

	cron := objectFrom(t, `{
	  "kind": "CronJob",
	  "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{
	    "name": "batch", "image": "quay.io/example/x:1",
	    "env": [{"name": "MODEL_URI", "value": "s3://bucket/fraud/v3"}]
	  }]}}}}}
	}`)
	if refFromEvidence(discoverModelEvidence(cron)).Model != "fraud" {
		t.Error("a CronJob's nested pod template must be read")
	}
}

// The false-positive side. A workload that serves no model must stay silent,
// or every Deployment in the cluster gets a warning and the warning stops
// meaning anything.
func TestOrdinaryWorkloadsProduceNoEvidence(t *testing.T) {
	for name, doc := range map[string]string{
		"web server": `{"kind":"Deployment","spec":{"template":{"spec":{"containers":[
			{"name":"web","image":"nginx:1.27","volumeMounts":[{"name":"c","mountPath":"/etc/nginx"}]}]}}}}`,
		"database": `{"kind":"StatefulSet","spec":{"template":{"spec":{
			"containers":[{"name":"db","image":"postgres:17","env":[{"name":"POSTGRES_DB","value":"app"}]}],
			"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"pgdata"}}]}}}}`,
		"no pod spec": `{"kind":"ConfigMap","data":{"a":"b"}}`,
	} {
		if evidence := discoverModelEvidence(objectFrom(t, doc)); len(evidence) != 0 {
			t.Errorf("%s should produce no evidence, got %v", name, evidence)
		}
	}
}

// The message an operator reads has to stay readable when a pod has many
// containers.
func TestEvidenceDescriptionIsBounded(t *testing.T) {
	evidence := []Evidence{
		{Kind: "image", Detail: "a"}, {Kind: "image", Detail: "b"},
		{Kind: "image", Detail: "c"}, {Kind: "image", Detail: "d"},
		{Kind: "image", Detail: "e"},
	}
	got := describeEvidence(evidence)
	if !strings.Contains(got, "and 2 more") {
		t.Fatalf("long evidence lists should be truncated, got %q", got)
	}
}
