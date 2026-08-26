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

// Stable builds a DNS-safe name from a prefix and parts.
//
// Every name carries a fingerprint of the exact inputs, because sanitizing
// them throws information away: "acme/fraud", "acme-fraud", "acme.fraud" and
// "Acme_Fraud" all flatten to the same characters. Without the fingerprint two
// different models derive one name, and whichever was written last decides what
// the other one's workloads are allowed to do.
//
// The fingerprint used to be appended only when the readable form overran the
// length limit, which is almost never — so the protection existed for long
// names and nothing else.
func Stable(prefix string, parts ...string) string {
	suffix := fingerprint(parts)

	readable := Sanitize(prefix + "-" + strings.Join(parts, "-"))
	budget := MaxNameLength - hashLength - 1
	if len(readable) > budget {
		readable = readable[:budget]
	}
	readable = strings.TrimRight(readable, "-")
	if readable == "" {
		return suffix
	}
	return readable + "-" + suffix
}

// LegacyStable is how names were derived before they carried a fingerprint.
//
// Kept so a reader can still find an object written by an older operator. It is
// a read path only: nothing writes these names any more, and a lookup that hits
// one is still checked against the object's own contents, so a legacy name that
// collides is caught the same way a current one would be.
func LegacyStable(prefix string, parts ...string) string {
	readable := Sanitize(prefix + "-" + strings.Join(parts, "-"))
	if len(readable) <= MaxNameLength {
		return readable
	}
	suffix := fingerprint(parts)
	budget := MaxNameLength - hashLength - 1
	if budget < 1 {
		return suffix
	}
	if len(readable) > budget {
		readable = readable[:budget]
	}
	return strings.TrimRight(readable, "-") + "-" + suffix
}

// fingerprint covers the raw parts rather than the sanitized form, so two
// inputs that sanitize identically still separate.
func fingerprint(parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:hashLength]
}

// ModelReport is the ModelSecurityReport name for a model version.
func ModelReport(model, version string) string {
	return Stable("msr", model, version)
}

// LegacyModelReport is the pre-fingerprint ModelSecurityReport name.
func LegacyModelReport(model, version string) string {
	return LegacyStable("msr", model, version)
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
