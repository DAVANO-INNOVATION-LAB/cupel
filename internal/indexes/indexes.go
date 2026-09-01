// Package indexes declares the field indexes the console API reads through.
//
// Without them, every question about one model was answered by listing every
// object of its kind and filtering in Go: serving a single model's findings
// read all of the cluster's scan reports, and finding one bill of materials
// read every scan. The cost of answering scaled with the size of the cluster
// rather than with the size of the answer, which is the shape of a system that
// works in a demo and stops working in production.
package indexes

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Index names. These are scoped per type by the field indexer, so the same
// string naming the same concept on different kinds is deliberate.
const (
	// ByModel keys an object by the model version it concerns.
	ByModel = "cupel.modelIdentity"
	// ByScan keys a scan report by the scan that produced it.
	ByScan = "cupel.scanRef"
)

// separator joins a model name and version into one key.
//
// A unit separator rather than a dash or a slash: both of those occur in real
// model names and versions, and joining with a character that can appear in
// either makes ("a-b", "c") and ("a", "b-c") the same key — one model's
// findings shown under another's name.
const separator = "\x1f"

// ModelKey is the indexed form of a model identity.
func ModelKey(model, version string) string {
	return model + separator + version
}

// Definition is one index: the kind it covers, the field name a query uses,
// and how a key is read off an object.
type Definition struct {
	Object  client.Object
	Field   string
	Extract client.IndexerFunc
}

// modelOf keys an object by the model version it concerns.
//
// An absent identity is not indexed at all rather than indexed under the empty
// key: a lookup for ("", "") would otherwise match every object that happens to
// be missing a name, which is the opposite of narrowing.
func modelOf(model, version string) []string {
	if model == "" || version == "" {
		return nil
	}
	return []string{ModelKey(model, version)}
}

// Definitions is the single description of every index, so the cache the server
// queries and the fake client the tests query are indexed the same way. Defined
// twice, they drift, and the tests then pass against an index the production
// code does not have.
func Definitions() []Definition {
	return []Definition{
		{&securityv1alpha1.ArtifactScan{}, ByModel, func(o client.Object) []string {
			s, ok := o.(*securityv1alpha1.ArtifactScan)
			if !ok {
				return nil
			}
			return modelOf(s.Spec.ModelName, s.Spec.ModelVersion)
		}},
		{&securityv1alpha1.ModelSecurityReport{}, ByModel, func(o client.Object) []string {
			r, ok := o.(*securityv1alpha1.ModelSecurityReport)
			if !ok {
				return nil
			}
			return modelOf(r.Spec.ModelName, r.Spec.ModelVersion)
		}},
		{&securityv1alpha1.ComplianceReport{}, ByModel, func(o client.Object) []string {
			c, ok := o.(*securityv1alpha1.ComplianceReport)
			if !ok {
				return nil
			}
			return modelOf(c.Spec.ModelName, c.Spec.ModelVersion)
		}},
		{&securityv1alpha1.ArtifactScanReport{}, ByScan, func(o client.Object) []string {
			r, ok := o.(*securityv1alpha1.ArtifactScanReport)
			if !ok || r.ScanRef == "" {
				return nil
			}
			return []string{r.ScanRef}
		}},
	}
}

// Register adds every index the API server queries. It is called once, against
// a cache, before that cache is started.
func Register(ctx context.Context, fi client.FieldIndexer) error {
	for _, d := range Definitions() {
		if err := fi.IndexField(ctx, d.Object, d.Field, d.Extract); err != nil {
			return fmt.Errorf("index %T by %s: %w", d.Object, d.Field, err)
		}
	}
	return nil
}
