// Package naming derives Kubernetes object names from registry identifiers.
//
// Model and version names come from the Model Registry, so they are
// arbitrary: long, uppercase, and full of characters Kubernetes rejects.
// Every Cupel object name is derived here so the operator and the in-pod
// runner always agree on what a given object is called.
package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// MaxNameLength is the Kubernetes limit for a DNS-1123 label.
const MaxNameLength = 63

// hashLength is how many hex characters of the content hash are appended when
// a name must be shortened. 10 hex chars is 40 bits: collision-free in
// practice for the number of models in any one cluster.
const hashLength = 10

var invalidChars = regexp.MustCompile(`[^a-z0-9-]+`)

// Sanitize converts an arbitrary string into DNS-1123 label characters.
func Sanitize(value string) string {
	cleaned := invalidChars.ReplaceAllString(strings.ToLower(value), "-")
	// Collapse runs of dashes introduced by stripping.
	for strings.Contains(cleaned, "--") {
		cleaned = strings.ReplaceAll(cleaned, "--", "-")
	}
	cleaned = strings.Trim(cleaned, "-")
	if cleaned == "" {
		return "unnamed"
	}
	return cleaned
}

// SanitizeLabel produces a valid label value from an arbitrary string.
func SanitizeLabel(value string) string {
	return truncate(Sanitize(value))
}

// Stable builds a DNS-safe name from a prefix and parts. When the readable
// form would exceed the length limit it is truncated and a hash of the full
// input is appended, so distinct inputs never collide.
func Stable(prefix string, parts ...string) string {
	readable := Sanitize(prefix + "-" + strings.Join(parts, "-"))
	if len(readable) <= MaxNameLength {
		return readable
	}

	// The hash covers the raw parts, not the sanitized form, so two names
	// that sanitize identically still get distinct hashes.
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	suffix := hex.EncodeToString(sum[:])[:hashLength]

	budget := MaxNameLength - hashLength - 1
	if budget < 1 {
		return suffix
	}
	if len(readable) > budget {
		readable = readable[:budget]
	}
	return strings.TrimRight(readable, "-") + "-" + suffix
}

// ModelReport is the ModelSecurityReport name for a model version.
func ModelReport(model, version string) string {
	return Stable("msr", model, version)
}

// Scan is the ArtifactScan name for one artifact of a model version.
func Scan(model, version, artifactID string) string {
	return Stable("scan", model, version, artifactID)
}

// ScanJob is the Job name for one scanner running against one scan.
//
// The scanner name is part of the hashed input rather than appended to an
// already-maximal scan name: appending and truncating would give every
// scanner in a long-named scan the same Job name, and only the first would
// ever be created.
func ScanJob(scanName, scanner string) string {
	return Stable("", scanName, scanner)
}

// ScanReport is the ArtifactScanReport name for one scanner's results.
func ScanReport(scanName, scanner string) string {
	return Stable("", scanName, scanner)
}

func truncate(value string) string {
	if len(value) <= MaxNameLength {
		return value
	}
	return strings.Trim(value[:MaxNameLength], "-")
}
