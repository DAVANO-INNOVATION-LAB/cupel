package controller

import (
	"fmt"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// Paths inside the scan pod.
const (
	workspacePath = "/workspace"
	resultsPath   = "/results"
	tmpPath       = "/tmp"
	// Must match resolver.PVCResolver's default MountRoot.
	pvcMountRoot = "/mnt/pvc"
)

// pvcClaimOf returns the claim name from a pvc://claim/path URI.
func pvcClaimOf(uri string) (string, bool) {
	const scheme = "pvc://"
	if !strings.HasPrefix(uri, scheme) {
		return "", false
	}
	rest := strings.TrimPrefix(uri, scheme)
	claim, _, _ := strings.Cut(rest, "/")
	if claim == "" {
		return "", false
	}
	return claim, true
}

// Labels Cupel puts on scan Jobs so the controller can find them again.
const (
	LabelScan      = "security.davano.io/scan"
	LabelScanner   = "security.davano.io/scanner"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// LabelTrigger records why a scan exists, so the console and kubectl can
	// filter on it without parsing the spec.
	LabelTrigger = "security.davano.io/trigger"
	ManagerName  = "cupel-operator"

	// AnnotationArtifactDigest carries the digest the fetch step measured,
	// from the scan report the publish step writes back up to the model
	// report the admission gate reads. Must match the key cmd/runner sets.
	AnnotationArtifactDigest = "security.davano.io/artifact-digest"
)

// JobConfig holds the cluster-level settings the orchestrator needs.
type JobConfig struct {
	// OperatorImage is the Cupel image, used for the fetch and publish steps
	// and for scanners implemented by the Cupel runner.
	OperatorImage string
	// ScannerRegistry is the host and namespace holding the scanner images.
	// Air-gapped clusters set this to their mirror. Empty uses the default.
	ScannerRegistry string
	// ServiceAccount the scan pods run as.
	ServiceAccount string
	// PullSecret is mounted as a Docker config for OCI artifact pulls.
	PullSecret string
	// StorageSecret projects S3 credentials into the fetch step.
	StorageSecret string
	// WorkspaceSize is the emptyDir size limit for staged artifacts.
	WorkspaceSize resource.Quantity
	// TmpSize is the emptyDir size limit for scanner scratch space.
	TmpSize resource.Quantity
	// TTLSecondsAfterFinished garbage-collects completed scan Jobs.
	TTLSecondsAfterFinished int32
}

// buildScanJob assembles the Job for one scanner against one artifact.
//
// The pod runs three steps in order:
//
//	fetch (init)   resolve the artifact URI and stage bytes into /workspace
//	scan  (init)   run the scanner over /workspace, writing to /results
//	publish        parse /results and create the ArtifactScanReport
//
// Using init containers for fetch and scan means the publish step only runs
// after both have finished, and it is the single place that talks to the API
// server — the scanner containers themselves get no cluster credentials.
func buildScanJob(scan *securityv1alpha1.ArtifactScan, def scanners.Definition, spec *securityv1alpha1.ScannerSpec, cfg JobConfig) (*batchv1.Job, error) {
	if cfg.OperatorImage == "" {
		return nil, fmt.Errorf("operator image is not configured")
	}

	image := scanners.ResolveImage(def, cfg.ScannerRegistry, cfg.OperatorImage)
	args := def.Args
	command := def.Command
	timeout := int64(1800)

	if spec != nil {
		if spec.Image != "" {
			image = spec.Image
		}
		if len(spec.Args) > 0 {
			args = spec.Args
		}
		if spec.TimeoutSeconds != nil {
			timeout = *spec.TimeoutSeconds
		}
	}

	args = substitutePaths(args)
	command = substitutePaths(command)

	// Sized for what a sampled fetch actually stages, not for a whole model.
	//
	// The resolvers read header-inspectable formats by range — a safetensors
	// header is kilobytes, whatever the tensor data behind it weighs — and pull
	// whole only the small files that can execute code. Reserving fifty
	// gigabytes for that was sizing the workspace for a download that no longer
	// happens, and it made every scan pod look enormous to a node.
	//
	// Still generous: a pickle is read in full and real ones run to gigabytes.
	workspaceSize := cfg.WorkspaceSize
	if workspaceSize.IsZero() {
		workspaceSize = resource.MustParse("12Gi")
	}

	// Bounded so a scanner that streams an artifact into /tmp cannot fill the
	// node's ephemeral storage.
	tmpSize := cfg.TmpSize
	if tmpSize.IsZero() {
		tmpSize = resource.MustParse("4Gi")
	}

	volumes := []corev1.Volume{
		{
			Name: "workspace",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &workspaceSize},
			},
		},
		{
			Name:         "results",
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		},
		{
			// Scanner containers run with a read-only root filesystem, but
			// every one of these tools needs scratch space: Trivy for its
			// cache, ClamAV for temporary extraction, Syft for unpacking.
			// A writable /tmp is what lets the hardening hold.
			Name: "tmp",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &tmpSize},
			},
		},
	}
	mounts := []corev1.VolumeMount{
		{Name: "workspace", MountPath: workspacePath},
		{Name: "results", MountPath: resultsPath},
		{Name: "tmp", MountPath: tmpPath},
	}

	// The pod's service account token is projected by hand into the publish
	// step alone, and automounting is turned off for the pod as a whole.
	//
	// Without this the kubelet injects the token into every container,
	// including the scan step that parses hostile model bytes — which is the
	// one container that must not hold a credential. That token can create
	// ArtifactScanReports, so a scanner escape could forge a clean verdict for
	// any model and walk it straight through the admission gate.
	//
	// The projection uses the standard in-cluster paths, so client-go's
	// ctrl.GetConfig() in the publish step still finds everything it needs.
	volumes = append(volumes, corev1.Volume{
		Name: "kube-api-access",
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Path:              "token",
							ExpirationSeconds: ptr(int64(3600)),
						},
					},
					{
						ConfigMap: &corev1.ConfigMapProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "kube-root-ca.crt"},
							Items:                []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}},
						},
					},
					{
						DownwardAPI: &corev1.DownwardAPIProjection{
							Items: []corev1.DownwardAPIVolumeFile{{
								Path:     "namespace",
								FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
							}},
						},
					},
				},
			},
		},
	})
	publishMounts := append(append([]corev1.VolumeMount{}, mounts...), corev1.VolumeMount{
		Name:      "kube-api-access",
		MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
		ReadOnly:  true,
	})

	// fetch gets everything the other steps get, plus whatever the artifact's
	// scheme and the cluster's registry configuration require. Built as its own
	// copy and only ever appended to: rebuilding it from `mounts` in a later
	// branch silently dropped an earlier one.
	fetchMounts := append([]corev1.VolumeMount{}, mounts...)

	// A pvc:// artifact lives on a claim the fetch step has to be able to read.
	// The resolver expects it at pvcMountRoot/<claim>, and without this the URI
	// resolves to a path that is simply not present in the pod — so the scheme
	// failed at runtime despite being implemented.
	if claim, ok := pvcClaimOf(scan.Spec.Artifact.URI); ok {
		volumes = append(volumes, corev1.Volume{
			Name: "artifact-pvc",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claim,
					ReadOnly:  true,
				},
			},
		})
		fetchMounts = append(fetchMounts, corev1.VolumeMount{
			Name:      "artifact-pvc",
			MountPath: pvcMountRoot + "/" + claim,
			ReadOnly:  true,
		})
	}

	if cfg.PullSecret != "" {
		volumes = append(volumes, corev1.Volume{
			Name: "pull-secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: cfg.PullSecret,
					Items: []corev1.KeyToPath{
						{Key: corev1.DockerConfigJsonKey, Path: "config.json"},
					},
				},
			},
		})
		fetchMounts = append(fetchMounts,
			corev1.VolumeMount{Name: "pull-secret", MountPath: "/docker", ReadOnly: true})
	}

	// The provenance scanner needs public trust material. It is optional: a
	// cluster with no TrustedPublishers must still be able to run every other
	// scanner, and the verifier reports the missing configuration itself.
	scanMounts := append([]corev1.VolumeMount{}, mounts...)
	if def.Category == scanners.CategoryProvenance {
		volumes = append(volumes, corev1.Volume{
			Name: "trust-policy",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: TrustPolicyConfigMap},
					Optional:             ptr(true),
				},
			},
		})
		scanMounts = append(scanMounts, corev1.VolumeMount{
			Name: "trust-policy", MountPath: TrustPolicyMountPath, ReadOnly: true,
		})
	}

	fetchEnv := []corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: "/docker"}}
	if cfg.StorageSecret != "" {
		fetchEnv = append(fetchEnv, corev1.EnvVar{
			Name: "AWS_ACCESS_KEY_ID",
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: cfg.StorageSecret},
				Key:                  "AWS_ACCESS_KEY_ID",
				Optional:             ptr(true),
			}},
		}, corev1.EnvVar{
			Name: "AWS_SECRET_ACCESS_KEY",
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: cfg.StorageSecret},
				Key:                  "AWS_SECRET_ACCESS_KEY",
				Optional:             ptr(true),
			}},
		}, corev1.EnvVar{
			Name: "AWS_S3_ENDPOINT",
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: cfg.StorageSecret},
				Key:                  "AWS_S3_ENDPOINT",
				Optional:             ptr(true),
			}},
		}, corev1.EnvVar{
			Name: "AWS_REGION",
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: cfg.StorageSecret},
				Key:                  "AWS_DEFAULT_REGION",
				Optional:             ptr(true),
			}},
		})
	}

	scanResources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("200m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
			// The scanner is where the staged workspace actually sits, so it
			// declares the same disk the fetch reserved. Init containers are
			// scheduled on the maximum rather than the sum, so this does not
			// double-count.
			corev1.ResourceEphemeralStorage: workspaceSize,
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("4Gi"),
		},
	}
	if spec != nil && (len(spec.Resources.Requests) > 0 || len(spec.Resources.Limits) > 0) {
		scanResources = spec.Resources
	}

	// Scanner containers process untrusted bytes, so they run with no
	// privileges, no cluster credentials, and a read-only root filesystem.
	hardened := &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		ReadOnlyRootFilesystem:   ptr(true),
		RunAsNonRoot:             ptr(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}

	jobName := scanJobName(scan.Name, def.Name)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: scan.Namespace,
			Labels: map[string]string{
				LabelScan:      scan.Name,
				LabelScanner:   def.Name,
				LabelManagedBy: ManagerName,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr(int32(1)),
			ActiveDeadlineSeconds:   &timeout,
			TTLSecondsAfterFinished: ptr(cfg.TTLSecondsAfterFinished),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						LabelScan:      scan.Name,
						LabelScanner:   def.Name,
						LabelManagedBy: ManagerName,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: cfg.ServiceAccount,
					// Off for the pod; publish mounts the token explicitly.
					AutomountServiceAccountToken: ptr(false),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   ptr(true),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Volumes: volumes,
					InitContainers: []corev1.Container{
						{
							Name:    "fetch",
							Image:   cfg.OperatorImage,
							Command: []string{"/cupel-runner"},
							Args: []string{
								"fetch",
								"--uri", scan.Spec.Artifact.URI,
								"--dest", workspacePath,
								"--metadata", resultsPath + "/artifact.json",
							},
							Env:             fetchEnv,
							VolumeMounts:    fetchMounts,
							SecurityContext: hardened,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
									// Without this the scheduler is blind to disk:
									// emptyDir sizeLimit caps usage but reserves
									// nothing, so several scan pods can land on a
									// node that cannot hold them and the failure
									// arrives as eviction rather than as a
									// placement decision.
									corev1.ResourceEphemeralStorage: workspaceSize,
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"),
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
							},
						},
						{
							Name:            "scan",
							Image:           image,
							Command:         command,
							Args:            args,
							VolumeMounts:    scanMounts,
							SecurityContext: hardened,
							Resources:       scanResources,
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "publish",
							Image:   cfg.OperatorImage,
							Command: []string{"/cupel-runner"},
							Args: []string{
								"publish",
								"--scan", scan.Name,
								"--namespace", scan.Namespace,
								"--scanner", def.Name,
								"--format", def.ResultFormat,
								"--results", resultsPath + "/" + def.OutputFile,
								"--metadata", resultsPath + "/artifact.json",
							},
							VolumeMounts:    publishMounts,
							SecurityContext: hardened,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("500m"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
						},
					},
				},
			},
		},
	}

	return job, nil
}

func substitutePaths(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	for i, arg := range args {
		arg = strings.ReplaceAll(arg, scanners.PlaceholderWorkspace, workspacePath)
		arg = strings.ReplaceAll(arg, scanners.PlaceholderResults, resultsPath)
		out[i] = strings.ReplaceAll(arg, scanners.PlaceholderTrustPolicy,
			TrustPolicyMountPath+"/"+TrustPolicyKey)
	}
	return out
}

func ptr[T any](v T) *T { return &v }
