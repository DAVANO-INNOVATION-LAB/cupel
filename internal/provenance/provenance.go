// Package provenance is a thin adapter over the tessera/sigstore module.
//
// The verification moved into its own module because it never depended on
// Kubernetes and because its dependency tree — sigstore-go, and transitively an
// AWS SDK — has no business inside a library whose value is having none. What
// stays here is the name the controllers already import.
package provenance

import (
	sigstore "github.com/DAVANO-INNOVATION-LAB/tessera/sigstore"
)

type (
	Policy        = sigstore.Policy
	Publisher     = sigstore.Publisher
	Verifier      = sigstore.Verifier
	Result        = sigstore.Result
	Finding       = sigstore.Finding
	Inventory     = sigstore.Inventory
	Signature     = sigstore.Signature
	SignatureKind = sigstore.SignatureKind
)

// NewVerifier builds a verifier for a policy. An unusable policy is an error
// rather than a verifier that reports everything as unsigned: those two look
// identical from the outside and mean opposite things.
func NewVerifier(policy Policy) (*Verifier, error) { return sigstore.NewVerifier(policy) }

// Discover inventories the signatures and artifacts in a workspace.
func Discover(workspace string) (*Inventory, error) { return sigstore.Discover(workspace) }

// ExecutableFormat reports the model format a filename implies when that format
// can execute code on load, and "" otherwise.
func ExecutableFormat(name string) string { return sigstore.ExecutableFormat(name) }

// Finding identifiers this package can emit.
const (
	FindingVerified          = sigstore.FindingVerified
	FindingUnsigned          = sigstore.FindingUnsigned
	FindingInvalid           = sigstore.FindingInvalid
	FindingUntrustedSigner   = sigstore.FindingUntrustedSigner
	FindingNoTransparencyLog = sigstore.FindingNoTransparencyLog
	FindingPartialCoverage   = sigstore.FindingPartialCoverage
	FindingNotConfigured     = sigstore.FindingNotConfigured
)
