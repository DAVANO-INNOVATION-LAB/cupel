// Package resolver is a thin adapter over the tessera/fetch module.
//
// Staging an artifact moved into its own module because it never depended on
// Kubernetes and because its dependency tree — an S3 client, an OCI registry
// client — has no business in a library whose value is having none. What stays
// here is the name the controllers already import.
package resolver

import (
	fetch "github.com/DAVANO-INNOVATION-LAB/tessera/fetch"
)

type (
	// Artifact is a staged artifact on local disk.
	Artifact = fetch.Artifact
	// Coverage records what a partial fetch actually read. Nil means the whole
	// artifact was staged; a scan over a partial fetch is not entitled to
	// report a clean result.
	Coverage = fetch.Coverage
	// Resolver fetches one URI scheme.
	Resolver = fetch.Resolver
	// Registry dispatches a URI to the resolver for its scheme.
	Registry = fetch.Registry

	OCIResolver         = fetch.OCIResolver
	ModelCarResolver    = fetch.ModelCarResolver
	S3Resolver          = fetch.S3Resolver
	PVCResolver         = fetch.PVCResolver
	HuggingFaceResolver = fetch.HuggingFaceResolver
	MLflowResolver      = fetch.MLflowResolver
	HTTPResolver        = fetch.HTTPResolver
	// KubeflowResolver reads a Kubeflow Model Registry entry and follows it to
	// the backend holding the bytes. The same registry OpenShift AI ships, so
	// one connector covers both.
	KubeflowResolver = fetch.KubeflowResolver
)

// NewRegistry returns a registry with every built-in resolver registered.
func NewRegistry() *Registry { return fetch.NewRegistry() }

// SchemeOf reports the URI scheme, or an error when there is none. A missing
// scheme is never guessed: doing so would hand a local path to a network
// resolver, or the reverse.
func SchemeOf(uri string) (string, error) { return fetch.SchemeOf(uri) }

// CanExecuteCode reports whether a filename implies a format that runs code on
// load. Fetching such a file is not dangerous; treating it like a safetensors
// afterwards is.
func CanExecuteCode(name string) bool { return fetch.CanExecuteCode(name) }

// ParseHuggingFaceURI splits an hf:// URI into repository and revision.
func ParseHuggingFaceURI(uri string) (repo, revision string, err error) {
	return fetch.ParseHuggingFaceURI(uri)
}

// RewriteMLflowURI turns an MLflow artifact URI into one a resolver can fetch.
func RewriteMLflowURI(artifactURI, trackingURL string) (string, bool) {
	return fetch.RewriteMLflowURI(artifactURI, trackingURL)
}
