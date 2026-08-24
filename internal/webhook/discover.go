package webhook

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Model discovery for workloads that never opted in.
//
// The gate used to read a model reference from annotations, understand KServe
// InferenceServices natively, and admit everything else with "no model
// reference; nothing for cupel to validate". That sentence is a claim, and for
// a plain Deployment mounting a PVC full of weights it is false: there is a
// model, the gate simply could not see it.
//
// This file makes the workload's intent visible. Where a storage location is
// discoverable the reference is built from it and the workload is gated like
// any other. Where intent is clear but identity is not, that is reported as
// its own outcome — "serving something Cupel cannot identify" is a different
// fact from "serving nothing", and collapsing them is how a gate ends up
// enforcing on the subset of traffic that volunteered.

// Evidence is one reason to believe a workload serves a model.
type Evidence struct {
	// Kind is the shape of the evidence: image, env, arg, volume.
	Kind string
	// Detail names what was found, for the admission response.
	Detail string
	// URI is a storage location, when the evidence carried one.
	URI string
}

func (e Evidence) String() string { return e.Kind + " " + e.Detail }

// servingImages are substrings of container images whose entire purpose is to
// load a model and serve it. Matching on substring rather than a pinned list
// of references is deliberate: these are mirrored, retagged and rebuilt
// constantly, and a registry-qualified allow-list would go stale into
// permissiveness.
var servingImages = []string{
	"vllm", "tritonserver", "triton-inference", "text-generation-inference",
	"tgi", "mlserver", "torchserve", "kserve", "seldon", "ollama",
	"sglang", "lorax", "ray-llm", "openvino_model_server", "ovms",
	"huggingface-text-generation", "text-embeddings-inference",
}

// modelEnvVars name a model or the place one is loaded from. The value is
// carried through as a candidate storage URI, because for most of these it is
// exactly that.
var modelEnvVars = []string{
	"STORAGE_URI", "MODEL_URI", "MODEL_PATH", "MODEL_DIR", "MODEL_REPOSITORY",
	"MODEL_ID", "MODEL_NAME", "HF_MODEL_ID", "HUGGING_FACE_HUB_MODEL_ID",
	"MODEL_STORE", "SERVED_MODEL_NAME", "OLLAMA_MODELS",
}

// modelArgs are command-line flags that name a model to a serving runtime.
var modelArgs = []string{
	"--model", "--model-id", "--model-path", "--model-repository",
	"--model-store", "--model-name", "--served-model-name",
}

// modelMountHints are path fragments that say a mounted volume holds a model.
var modelMountHints = []string{"/model", "/models", "/mnt/model", "/opt/ml/model", "/weights"}

// discoverModelEvidence reports why a workload looks like it serves a model.
//
// It reads the pod template of the common workload kinds and the pod spec of a
// bare Pod. It does not resolve anything: a PersistentVolumeClaim's contents
// are not knowable at admission time, and pretending otherwise would be worse
// than reporting the uncertainty.
func discoverModelEvidence(obj *unstructured.Unstructured) []Evidence {
	spec, found := podSpecOf(obj)
	if !found {
		return nil
	}

	var evidence []Evidence
	for _, key := range []string{"containers", "initContainers"} {
		containers, _, _ := unstructured.NestedSlice(spec, key)
		for _, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			evidence = append(evidence, evidenceFromContainer(container)...)
		}
	}
	evidence = append(evidence, evidenceFromVolumes(spec)...)

	sort.SliceStable(evidence, func(i, j int) bool {
		// Evidence carrying a location sorts first, because it is the only
		// kind the gate can act on.
		return evidence[i].URI != "" && evidence[j].URI == ""
	})
	return evidence
}

func evidenceFromContainer(container map[string]any) []Evidence {
	var evidence []Evidence

	if image, ok := container["image"].(string); ok && image != "" {
		lower := strings.ToLower(image)
		for _, name := range servingImages {
			if strings.Contains(lower, name) {
				evidence = append(evidence, Evidence{
					Kind: "image", Detail: fmt.Sprintf("%q is a model-serving runtime", image)})
				break
			}
		}
	}

	env, _, _ := unstructured.NestedSlice(container, "env")
	for _, raw := range env {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := entry["name"].(string)
		if !containsFold(modelEnvVars, name) {
			continue
		}
		// Only a literal value is usable. A valueFrom pointing at a ConfigMap
		// or Secret is still evidence the workload serves a model, but its
		// value is not readable here and must not be guessed at.
		value, _ := entry["value"].(string)
		evidence = append(evidence, Evidence{
			Kind:   "env",
			Detail: envDetail(name, value, entry),
			URI:    value,
		})
	}

	for _, field := range []string{"args", "command"} {
		args, _, _ := unstructured.NestedStringSlice(container, field)
		for i, arg := range args {
			flag, value := splitFlag(arg)
			if !containsFold(modelArgs, flag) {
				continue
			}
			if value == "" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				value = args[i+1]
			}
			evidence = append(evidence, Evidence{
				Kind: field, Detail: fmt.Sprintf("%s %s", flag, value), URI: value})
		}
	}

	// A volume mounted at a model path is evidence even when nothing names it,
	// which is the case this whole file exists for.
	mounts, _, _ := unstructured.NestedSlice(container, "volumeMounts")
	for _, raw := range mounts {
		mount, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		path, _ := mount["mountPath"].(string)
		if !looksLikeModelPath(path) {
			continue
		}
		name, _ := mount["name"].(string)
		evidence = append(evidence, Evidence{
			Kind:   "volume",
			Detail: fmt.Sprintf("volume %q mounted at %s", name, path),
		})
	}
	return evidence
}

func evidenceFromVolumes(spec map[string]any) []Evidence {
	var evidence []Evidence
	volumes, _, _ := unstructured.NestedSlice(spec, "volumes")
	for _, raw := range volumes {
		volume, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		claim, found, _ := unstructured.NestedString(volume, "persistentVolumeClaim", "claimName")
		if !found || claim == "" {
			continue
		}
		if !looksLikeModelPath(claim) {
			continue
		}
		evidence = append(evidence, Evidence{
			Kind:   "volume",
			Detail: fmt.Sprintf("persistent volume claim %q", claim),
		})
	}
	return evidence
}

func envDetail(name, value string, entry map[string]any) string {
	if value != "" {
		return fmt.Sprintf("%s=%s", name, value)
	}
	if _, ok := entry["valueFrom"]; ok {
		return fmt.Sprintf("%s is set from a reference Cupel cannot read at admission time", name)
	}
	return name
}

// podSpecOf finds the pod specification inside whichever workload kind this is.
func podSpecOf(obj *unstructured.Unstructured) (map[string]any, bool) {
	for _, path := range [][]string{
		{"spec", "template", "spec"},                        // Deployment, StatefulSet, DaemonSet, Job, ReplicaSet
		{"spec", "jobTemplate", "spec", "template", "spec"}, // CronJob
		{"spec"}, // Pod
	} {
		spec, found, err := unstructured.NestedMap(obj.Object, path...)
		if err != nil || !found {
			continue
		}
		if _, hasContainers := spec["containers"]; hasContainers {
			return spec, true
		}
	}
	return nil, false
}

// storageSchemes are the location forms a resolver can act on. They are the
// same set the fetch step understands, so a reference derived here names
// something Cupel could actually have scanned.
var storageSchemes = []string{
	"s3://", "gs://", "oci://", "http://", "https://", "pvc://",
	"hdfs://", "abfss://", "azure://", "mlflow-artifacts:/", "models:/",
}

func isStorageURI(uri string) bool {
	lower := strings.ToLower(uri)
	for _, scheme := range storageSchemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}
	return false
}

func looksLikeModelPath(path string) bool {
	lower := strings.ToLower(path)
	for _, hint := range modelMountHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func splitFlag(arg string) (flag, value string) {
	if idx := strings.Index(arg, "="); idx > 0 {
		return arg[:idx], arg[idx+1:]
	}
	return arg, ""
}

func containsFold(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

// describeEvidence renders evidence for an admission response, bounded so a
// workload with fifty containers cannot produce an unreadable message.
func describeEvidence(evidence []Evidence) string {
	const max = 3
	parts := make([]string, 0, max)
	for i, e := range evidence {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(evidence)-max))
			break
		}
		parts = append(parts, e.String())
	}
	return strings.Join(parts, "; ")
}

// refFromEvidence builds a model reference from discovered evidence.
//
// Only a scheme-qualified storage URI produces one, and the model and version
// are derived exactly the way a KServe storage URI is, so a discovered
// workload and a declared one resolve to the same report name.
//
// Everything else deliberately yields nothing. A bare path like /models/llama3
// or a Hugging Face identifier like meta-llama/Llama-3-8B would split into a
// plausible-looking model and version under the same rule and address a report
// that describes a different artifact — and a workload admitted on another
// model's clean verdict is a worse outcome than one admitted with a warning
// that nothing was checked. The uncertainty is reported instead.
func refFromEvidence(evidence []Evidence) ModelRef {
	for _, e := range evidence {
		if !isStorageURI(e.URI) {
			continue
		}
		model, version := modelFromStorageURI(e.URI)
		if model == "" {
			continue
		}
		return ModelRef{
			Model:      model,
			Version:    version,
			StorageURI: e.URI,
			Digest:     digestFromURI(e.URI),
		}
	}
	return ModelRef{}
}
