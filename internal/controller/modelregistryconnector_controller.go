package controller

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/registry"
)

// defaultPollInterval is how often the registry is polled when the connector
// does not specify an interval.
const defaultPollInterval = time.Minute

// ModelRegistryConnectorReconciler polls an OpenShift AI Model Registry,
// creates an ArtifactScan for every model version it has not scanned, and
// writes scan summaries back into the registry.
type ModelRegistryConnectorReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// SecretReader reads credential Secrets without going through the
	// manager's cache.
	//
	// A cached Get on a Secret starts an informer over every Secret in the
	// cluster and holds them all in memory — for a controller that needs one
	// key from one Secret per poll, on a pod limited to 512Mi. It also means a
	// compromised manager leaks far more than it needs. Set this to
	// mgr.GetAPIReader(); it falls back to the cached client when nil so tests
	// keep working with a single fake.
	SecretReader client.Reader

	// NewClient builds a registry client. Overridden in tests.
	NewClient func(registry.Options) RegistryClient
}

// secrets returns the reader used for credential lookups.
func (r *ModelRegistryConnectorReconciler) secrets() client.Reader {
	if r.SecretReader != nil {
		return r.SecretReader
	}
	return r.Client
}

// RegistryClient is the subset of the Model Registry API the connector uses.
type RegistryClient interface {
	Ping(ctx context.Context) error
	ListRegisteredModels(ctx context.Context) ([]registry.RegisteredModel, error)
	ListModelVersions(ctx context.Context, modelID string) ([]registry.ModelVersion, error)
	ListArtifacts(ctx context.Context, versionID string) ([]registry.ModelArtifact, error)
	PatchModelVersionProperties(ctx context.Context, versionID string, props map[string]registry.MetadataValue) error
}

// Annotations Cupel puts on ArtifactScans to correlate them with the registry.
const (
	AnnotationRegistryModelID   = "security.davano.io/registry-model-id"
	AnnotationRegistryVersionID = "security.davano.io/registry-version-id"
	AnnotationArtifactID        = "security.davano.io/registry-artifact-id"
	LabelConnector              = "security.davano.io/connector"
)

// +kubebuilder:rbac:groups=security.davano.io,resources=modelregistryconnectors,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=modelregistryconnectors/status,verbs=get;update;patch
// Read uncached via the API reader, so list/watch (which exist only to feed a
// cache) are not needed.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

// Reconcile polls the registry once and requeues after the poll interval.
func (r *ModelRegistryConnectorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var connector securityv1alpha1.ModelRegistryConnector
	if err := r.Get(ctx, req.NamespacedName, &connector); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !connector.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	interval := defaultPollInterval
	if connector.Spec.PollInterval != nil && connector.Spec.PollInterval.Duration > 0 {
		interval = connector.Spec.PollInterval.Duration
	}

	token, err := r.resolveToken(ctx, &connector)
	if err != nil {
		return r.degrade(ctx, &connector, "AuthSecretUnavailable", err.Error(), interval)
	}

	src, err := r.sourceFor(&connector, token)
	if err != nil {
		return r.degrade(ctx, &connector, "UnknownConnectorType", err.Error(), interval)
	}

	versionCount, scansCreated, syncFailures, err := r.syncSource(ctx, &connector, src)
	if err != nil {
		return r.degrade(ctx, &connector, "ListModelsFailed", err.Error(), interval)
	}
	if scansCreated > 0 {
		logger.Info("created scans from a model source",
			"connector", connector.Name, "source", src.Name(), "scans", scansCreated)
	}

	now := metav1.Now()
	connector.Status.LastSyncTime = &now
	connector.Status.ModelVersions = int32(versionCount)
	connector.Status.ScansCreated += int32(scansCreated)
	metrics.ModelsTracked.WithLabelValues(src.Name(), connector.Name).Set(float64(versionCount))

	// Per-model failures were logged and swallowed, so a connector where every
	// single model failed still reported Connected and Ready — a completely
	// broken sync that looks healthy in `kubectl get`. Partial failure is now
	// its own state: the connector reached the registry, but did not finish.
	if syncFailures > 0 {
		connector.Status.Phase = "Degraded"
		connector.Status.Message = fmt.Sprintf("%d model(s) failed to sync; see operator logs", syncFailures)
		setCondition(&connector.Status.Conditions, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "PartialSyncFailure",
			Message: connector.Status.Message,
		})
	} else {
		connector.Status.Phase = "Connected"
		connector.Status.Message = ""
		setCondition(&connector.Status.Conditions, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionTrue,
			Reason:  "SyncSucceeded",
			Message: fmt.Sprintf("synced %d model version(s) from %s", versionCount, src.Name()),
		})
	}
	if err := r.Status().Update(ctx, &connector); err != nil {
		return ctrl.Result{}, err
	}

	if scansCreated > 0 {
		logger.Info("created scans from registry", "connector", connector.Name, "scans", scansCreated)
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *ModelRegistryConnectorReconciler) resolveToken(ctx context.Context, connector *securityv1alpha1.ModelRegistryConnector) (string, error) {
	ref := connector.Spec.AuthSecretRef
	if ref == nil || ref.Name == "" {
		return "", nil
	}
	var secret corev1.Secret
	if err := r.secrets().Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: connector.Namespace}, &secret); err != nil {
		return "", fmt.Errorf("read auth secret %s: %w", ref.Name, err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("auth secret %s has no key %q", ref.Name, key)
	}
	return strings.TrimSpace(string(value)), nil
}

func (r *ModelRegistryConnectorReconciler) degrade(ctx context.Context, connector *securityv1alpha1.ModelRegistryConnector, reason, message string, interval time.Duration) (ctrl.Result, error) {
	metrics.SourceSyncFailures.WithLabelValues("model-registry", reason).Inc()
	connector.Status.Phase = "Degraded"
	connector.Status.Message = message
	setCondition(&connector.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: message,
	})
	if err := r.Status().Update(ctx, connector); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// normalizeArtifactURI turns a registry artifact record into a URI the
// resolver understands. The registry stores locations inconsistently: some
// artifacts carry a full URI, others only a storage key plus path.
func normalizeArtifactURI(artifact registry.ModelArtifact) string {
	uri := strings.TrimSpace(artifact.URI)
	if uri != "" {
		if strings.Contains(uri, "://") {
			return uri
		}
		// A bare registry reference is an OCI image.
		return "oci://" + uri
	}

	if artifact.StorageKey != "" && artifact.StoragePath != "" {
		return "s3://" + path.Join(artifact.StorageKey, artifact.StoragePath)
	}
	return ""
}

// matchesIncludeList reports whether a model name matches any glob in the
// include list. An empty list matches everything.
func matchesIncludeList(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if ok, err := path.Match(pattern, name); err == nil && ok {
			return true
		}
	}
	return false
}

// SetupWithManager wires the reconciler into the manager.
func (r *ModelRegistryConnectorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ModelRegistryConnector{}).
		Owns(&securityv1alpha1.ArtifactScan{}).
		Named("modelregistryconnector").
		Complete(r)
}
