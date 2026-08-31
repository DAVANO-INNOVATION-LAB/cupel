package modelsource

import (
	"context"
	"fmt"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
)

// Declared is a Source whose model versions are listed in the connector spec
// rather than discovered from a vendor's API.
//
// It exists because the other two Sources each speak one registry's REST
// dialect, and an organisation running neither had no way in: the pipeline was
// pluggable in the code and closed at the API. A declared source is the general
// case. It names model versions and where their bytes live, and the bytes may
// live behind any scheme the resolver registry supports — OCI, ModelCar, S3,
// PVC, Hugging Face, MLflow, HTTP, Kubeflow. Whatever tracks models upstream
// (Weights & Biases, SageMaker, Vertex, Azure ML, Artifactory, an in-house
// service, a Git repository of manifests) can render that list, so "which
// registries are supported" stops being a question Cupel answers on the
// organisation's behalf.
//
// The trade is explicit and worth stating: discovery is the caller's job. A
// declared source finds nothing on its own, so a version nobody lists is a
// version nobody scans. What it buys is that the scanning, policy, promotion
// and admission path downstream is byte-for-byte the same one the built-in
// registries get.
type Declared struct {
	versions  []Version
	resolvers *resolver.Registry
}

// NewDeclared builds a Source over an explicit list of model versions.
func NewDeclared(versions []Version, resolvers *resolver.Registry) *Declared {
	if resolvers == nil {
		resolvers = resolver.NewRegistry()
	}
	return &Declared{versions: versions, resolvers: resolvers}
}

// NewDeclaredFromSpec builds a Declared source from the connector's model list.
func NewDeclaredFromSpec(models []securityv1alpha1.DeclaredModel, resolvers *resolver.Registry) *Declared {
	versions := make([]Version, 0, len(models))
	for _, m := range models {
		versions = append(versions, Version{
			ModelName: m.Name,
			Version:   m.Version,
			Artifact: securityv1alpha1.ArtifactRef{
				URI:    m.URI,
				Format: m.Format,
			},
			Labels: map[string]string{"declared": "true"},
		})
	}
	return NewDeclared(versions, resolvers)
}

// Name identifies this source.
func (d *Declared) Name() string { return "declared" }

// List returns the declared versions. It never reaches the network: the list
// is the input, so a declared source is reachable by construction and an empty
// spec means nothing to scan rather than a source that failed.
func (d *Declared) List(context.Context) ([]Version, error) {
	out := make([]Version, len(d.versions))
	copy(out, d.versions)
	return out, nil
}

// Resolve stages the artifact bytes using the storage resolvers.
func (d *Declared) Resolve(ctx context.Context, v Version, destDir string) (*resolver.Artifact, error) {
	if !d.resolvers.Supports(v.Artifact.URI) {
		return nil, fmt.Errorf("no resolver for artifact URI %q", v.Artifact.URI)
	}
	return d.resolvers.Resolve(ctx, v.Artifact.URI, destDir)
}

// WriteBack is a no-op.
//
// There is no upstream record to annotate — that is what "declared" means. It
// returns nil rather than an error because a verdict that was reached and
// stored on the ModelSecurityReport has not failed just because the list it
// came from is static, and returning an error here would degrade a connector
// that is working exactly as specified. Anything that needs the verdict reads
// it from the report.
func (d *Declared) WriteBack(context.Context, Version, Verdict) error { return nil }

var _ Source = (*Declared)(nil)
