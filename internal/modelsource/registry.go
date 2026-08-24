package modelsource

import (
	"context"
	"fmt"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/registry"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
)

// ModelRegistry is a Source backed by the OpenShift AI Model Registry. It
// exists to prove the Source interface is not MLflow-shaped: the same three
// operations map cleanly onto the registry Cupel was built around.
//
// The in-cluster connector controller drives write-back from a full
// ModelSecurityReport; this adapter is the cluster-free path (used by the CLI
// and by tests) and writes the summary directly from a Verdict.
type ModelRegistry struct {
	client    *registry.Client
	resolvers *resolver.Registry
}

// NewModelRegistry builds a Source over an OpenShift AI Model Registry.
func NewModelRegistry(opts registry.Options, resolvers *resolver.Registry) *ModelRegistry {
	if resolvers == nil {
		resolvers = resolver.NewRegistry()
	}
	return &ModelRegistry{client: registry.New(opts), resolvers: resolvers}
}

// Name identifies this source.
func (r *ModelRegistry) Name() string { return "model-registry" }

// List walks every registered model, its versions, and their artifacts.
func (r *ModelRegistry) List(ctx context.Context) ([]Version, error) {
	models, err := r.client.ListRegisteredModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("list registered models: %w", err)
	}

	var versions []Version
	for _, model := range models {
		mvs, err := r.client.ListModelVersions(ctx, model.ID)
		if err != nil {
			return nil, fmt.Errorf("list versions of %q: %w", model.Name, err)
		}
		for _, mv := range mvs {
			artifacts, err := r.client.ListArtifacts(ctx, mv.ID)
			if err != nil {
				return nil, fmt.Errorf("list artifacts of %s/%s: %w", model.Name, mv.Name, err)
			}
			for _, artifact := range artifacts {
				if artifact.URI == "" {
					continue
				}
				versions = append(versions, Version{
					ModelName: model.Name,
					Version:   mv.Name,
					VersionID: mv.ID,
					Artifact: securityv1alpha1.ArtifactRef{
						URI:    artifact.URI,
						Format: artifact.ModelFormatName,
					},
					Labels: map[string]string{
						"registry.model_id":    model.ID,
						"registry.version_id":  mv.ID,
						"registry.artifact_id": artifact.ID,
					},
				})
			}
		}
	}
	return versions, nil
}

// Resolve stages the artifact bytes using the storage resolvers.
func (r *ModelRegistry) Resolve(ctx context.Context, v Version, destDir string) (*resolver.Artifact, error) {
	if !r.resolvers.Supports(v.Artifact.URI) {
		return nil, fmt.Errorf("no resolver for artifact URI %q", v.Artifact.URI)
	}
	return r.resolvers.Resolve(ctx, v.Artifact.URI, destDir)
}

// WriteBack records the verdict as custom properties on the model version.
func (r *ModelRegistry) WriteBack(ctx context.Context, v Version, verdict Verdict) error {
	if v.VersionID == "" {
		return fmt.Errorf("model version %s/%s has no registry ID for write-back", v.ModelName, v.Version)
	}
	props := map[string]registry.MetadataValue{
		registry.PropVerdict:   registry.StringProperty(orUnknown(verdict.Verdict)),
		registry.PropRiskScore: registry.IntProperty(int64(verdict.RiskScore)),
	}
	if verdict.Malware != "" {
		props[registry.PropMalware] = registry.StringProperty(verdict.Malware)
	}
	if verdict.Secrets != "" {
		props[registry.PropSecrets] = registry.StringProperty(verdict.Secrets)
	}
	if !verdict.ScanTime.IsZero() {
		props[registry.PropLastScan] = registry.StringProperty(verdict.ScanTime.UTC().Format(time.RFC3339))
	}
	if verdict.ReportRef != "" {
		props[registry.PropReportRef] = registry.StringProperty(verdict.ReportRef)
	}
	return r.client.PatchModelVersionProperties(ctx, v.VersionID, props)
}

// Compile-time proof that both sources satisfy the interface.
var (
	_ Source = (*MLflow)(nil)
	_ Source = (*ModelRegistry)(nil)
)
