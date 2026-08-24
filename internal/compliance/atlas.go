package compliance

// MITRE ATLAS mapping.
//
// Two things shape this file.
//
// First, ATLAS renamed nearly every technique from "ML" to "AI" between the
// 2024.10 and 2025.03 releases, and retired several IDs outright in 2026.07.
// Shipping the old names would cite techniques that no longer exist. The names
// here are from ATLAS-2026.07, and the deprecated IDs are recorded below so a
// stale mapping is caught rather than silently mismatched.
//
// Second, and more important: ATLAS publishes no detection objects. There is no
// upstream statement of which techniques a scanner can observe. The Coverage
// value on each technique is Cupel's own assessment, and it is deliberately
// conservative. A model backdoored in its weights produces a perfectly valid,
// signature-clean file that no static scanner can distinguish from a clean one.
// Claiming that technique would be a lie that an evaluator catches immediately,
// so it is recorded as out of scope with the reason attached.
const (
	// ATLASVersion is the release these mappings were verified against. Pinned
	// deliberately: ATLAS renames techniques between releases, and tracking
	// "latest" would let an upstream change silently alter what Cupel claims.
	ATLASVersion = "2026.07"
)

// ATLASCoverage is how much of a technique Cupel can observe by inspecting an
// artifact.
type ATLASCoverage string

const (
	// CoverageDetected means static artifact analysis genuinely observes this.
	CoverageDetected ATLASCoverage = "Detected"
	// CoveragePartial means Cupel sees part of the technique. The bounded part
	// is named on the technique so the gap is not left to inference.
	CoveragePartial ATLASCoverage = "Partial"
	// CoverageOutOfScope means no property of a model artifact evidences this.
	// It needs training data, runtime behaviour, registry history, or an
	// organizational control.
	CoverageOutOfScope ATLASCoverage = "OutOfScope"
)

// Technique is one ATLAS technique or sub-technique.
type Technique struct {
	// ID is the ATLAS identifier, e.g. "AML.T0018.002".
	ID string
	// Name as published in ATLASVersion.
	Name string
	// Tactic is the parent tactic name.
	Tactic string
	// Coverage is Cupel's assessment.
	Coverage ATLASCoverage
	// Rationale explains the assessment. For anything not Detected, it says
	// what would be required instead.
	Rationale string
	// Findings are the Cupel finding-ID prefixes or scanner categories that
	// evidence this technique. Empty when Coverage is OutOfScope.
	Findings []string
	// Mitigations are the ATLAS mitigation IDs this technique maps to.
	Mitigations []string
}

// deprecatedTechniques maps retired IDs to their replacements.
//
// Kept so a policy or report carrying an old ID produces a clear message
// rather than silently matching nothing. AML.T0018.001 is the dangerous case:
// the ID was reused for a different concept, so an old mapping is not merely
// stale, it is wrong.
var deprecatedTechniques = map[string]string{
	"AML.T0019": "AML.T0115.000", // Publish Poisoned Datasets
	"AML.T0058": "AML.T0115.001", // Publish Poisoned Models
	"AML.T0104": "AML.T0115.002", // Publish Poisoned AI Agent Tool
	"AML.T0045": "AML.T0048.004", // ML Intellectual Property Theft
}

// ReplacementFor returns the current ID for a retired technique.
func ReplacementFor(id string) (string, bool) {
	replacement, ok := deprecatedTechniques[id]
	return replacement, ok
}

// atlasTechniques are the techniques relevant to model artifact security.
//
// Techniques Cupel cannot see are included on purpose. A coverage map that
// lists only wins reads as complete when it is not; the ones marked
// OutOfScope are the honest boundary of what this tool is.
var atlasTechniques = []Technique{
	// ---------- Genuinely detectable by artifact inspection ----------
	{
		ID: "AML.T0011.000", Name: "Unsafe AI Artifacts", Tactic: "Execution",
		Coverage:    CoverageDetected,
		Findings:    []string{"cupel-PICKLE", "cupel-KERAS", "cupel-TF", "model-inspector"},
		Mitigations: []string{"AML.M0011", "AML.M0013", "AML.M0014", "AML.M0016"},
		Rationale: "Deserialization of a model that executes code on load. The inspector reads pickle " +
			"opcodes directly and reports GLOBAL/STACK_GLOBAL references to callables that run at load time. " +
			"The same technique in the Keras family is covered separately, because it does not go through " +
			"pickle at all: a Lambda layer carries a marshalled code object, a TFSMLayer loads an external " +
			"SavedModel from a path in the config, and an altered config.json names arbitrary modules to " +
			"import — CVE-2026-1462 and CVE-2025-1550 respectively, both of which bypass safe_mode.",
	},
	{
		ID: "AML.T0018.002", Name: "Embed Malware", Tactic: "AI Attack Staging",
		Coverage:    CoverageDetected,
		Findings:    []string{"cupel-PICKLE", "clamav", "model-inspector"},
		Mitigations: []string{"AML.M0013"},
		Rationale: "Malware embedded in a model artifact. Covered by both opcode analysis and " +
			"conventional malware scanning of the staged bytes.",
	},
	{
		ID: "AML.T0112.001", Name: "Machine Compromise: AI Artifacts", Tactic: "Impact",
		Coverage:    CoverageDetected,
		Findings:    []string{"cupel-PICKLE", "clamav"},
		Mitigations: []string{"AML.M0011", "AML.M0016"},
		Rationale:   "Embedded commands or malware in artifacts, including bundled scripts and notebooks.",
	},
	{
		ID: "AML.T0011.001", Name: "Malicious Package", Tactic: "Execution",
		Coverage:    CoverageDetected,
		Findings:    []string{"trivy", "grype", "syft"},
		Mitigations: []string{"AML.M0011", "AML.M0016"},
		Rationale: "Malicious or vulnerable dependencies bundled with the model, found by scanning " +
			"the artifact's package manifests.",
	},
	{
		// This technique is specifically about defeating model scanners, which
		// makes it the one Cupel is most obliged to handle correctly. ATLAS
		// mitigation M0016 requires a scanner that still works on models it
		// cannot fully deserialize — a scanner that skips what it cannot parse
		// is defeated by design. Cupel's coverage-gap findings exist for this.
		ID: "AML.T0076", Name: "Corrupt AI Model", Tactic: "Defense Evasion",
		Coverage:    CoverageDetected,
		Findings:    []string{"cupel-COVERAGE", "cupel-PICKLE"},
		Mitigations: []string{"AML.M0016"},
		Rationale: "A model deliberately made un-deserializable so scanners skip it while it still " +
			"executes on load. Cupel reports unparsed and unread executable files as findings rather " +
			"than passing them over, so a file that defeats the parser cannot also defeat the verdict.",
	},

	// ---------- Partially covered; the bounded part is named ----------
	{
		ID: "AML.T0010", Name: "AI Supply Chain Compromise", Tactic: "Initial Access",
		Coverage:    CoveragePartial,
		Findings:    []string{"cupel-PROV", "cupel-PICKLE", "clamav"},
		Mitigations: []string{"AML.M0014", "AML.M0023", "AML.M0035"},
		Rationale: "Cupel detects the payload a compromise delivers, and signature verification " +
			"detects an artifact that did not come from a trusted publisher. The compromise event " +
			"itself — how the upstream was breached — is not observable here.",
	},
	{
		ID: "AML.T0010.003", Name: "AI Supply Chain Compromise: Model", Tactic: "Initial Access",
		Coverage:    CoveragePartial,
		Findings:    []string{"cupel-PROV", "cupel-PICKLE"},
		Mitigations: []string{"AML.M0008", "AML.M0013", "AML.M0017"},
		Rationale: "Provenance verification establishes whether the model came from a trusted signer. " +
			"A compromised-but-correctly-signed model is not distinguishable by signature alone.",
	},
	{
		ID: "AML.T0010.001", Name: "AI Supply Chain Compromise: AI Software", Tactic: "Initial Access",
		Coverage:    CoveragePartial,
		Findings:    []string{"trivy", "grype", "syft"},
		Mitigations: []string{"AML.M0014", "AML.M0023"},
		Rationale: "Vulnerable or tampered ML framework dependencies are visible in the SBOM and CVE " +
			"scan. A compromised build of a dependency that reports a clean version is not.",
	},
	{
		ID: "AML.T0018.001", Name: "Modify AI Model Architecture", Tactic: "AI Attack Staging",
		Coverage:    CoveragePartial,
		Findings:    []string{"cupel-ONNX", "model-inspector"},
		Mitigations: []string{"AML.M0008"},
		Rationale: "Injected operators or subgraphs are parseable from an ONNX graph. Deciding whether " +
			"an architecture is malicious requires a known-good baseline to compare against, which a " +
			"single artifact does not provide. NOTE: this ID previously meant \"Inject Payload\"; that " +
			"concept is now AML.T0018.002.",
	},
	{
		ID: "AML.T0018.003", Name: "Modify Prompt Construction Logic", Tactic: "AI Attack Staging",
		Coverage:    CoverageOutOfScope,
		Mitigations: nil,
		Rationale: "Chat templates and tool-call formatting live in a GGUF header, and Cupel does not " +
			"read GGUF headers — it records the format as present and produces no finding about it. " +
			"This was previously mapped to a finding ID that nothing emits, which claimed coverage " +
			"that did not exist. Tessera does parse these (TESS-GGUF-010); until Cupel consumes it, " +
			"the honest answer here is no.",
	},
	{
		ID: "AML.T0074", Name: "Masquerading", Tactic: "Defense Evasion",
		Coverage:    CoveragePartial,
		Findings:    []string{"cupel-FORMAT"},
		Mitigations: []string{"AML.M0014"},
		Rationale: "A file whose magic bytes contradict its extension is detectable. Registry namespace " +
			"reuse — a familiar name republished by a different owner — needs registry-side history and " +
			"is invisible in the artifact.",
	},
	{
		ID: "AML.T0115.001", Name: "Publish Poisoned AI Artifacts: Models", Tactic: "Resource Development",
		Coverage:    CoveragePartial,
		Findings:    []string{"cupel-PICKLE", "clamav", "cupel-PROV"},
		Mitigations: []string{"AML.M0008", "AML.M0016"},
		Rationale: "The code-and-malware fraction of a poisoned published model is detectable. Poisoning " +
			"carried in the weights is not — see AML.T0018.000.",
	},

	// ---------- Structurally out of scope ----------
	{
		// The most important admission in this file.
		ID: "AML.T0018.000", Name: "Poison AI Model", Tactic: "AI Attack Staging",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0007", "AML.M0008", "AML.M0025"},
		Rationale: "A model backdoored through its weights is a well-formed, signature-clean file that " +
			"is byte-level indistinguishable from a clean one. No static scanner can detect this. It " +
			"requires behavioural evaluation or training-data provenance.",
	},
	{
		ID: "AML.T0020", Name: "Training Data Poisoning", Tactic: "Resource Development",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0007", "AML.M0025"},
		Rationale: "Requires visibility into the training data, which a supply-chain artifact scanner " +
			"does not have. An AIBOM recording dataset provenance is the partial answer, and it records " +
			"a claim rather than verifying it.",
	},
	{
		ID: "AML.T0043.004", Name: "Craft Adversarial Data: Insert Backdoor Trigger", Tactic: "AI Attack Staging",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0007", "AML.M0008"},
		Rationale:   "A trigger embedded during training leaves no artifact-level signature.",
	},
	{
		ID: "AML.T0031", Name: "Erode AI Model Integrity", Tactic: "Impact",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0003", "AML.M0015"},
		Rationale: "Degradation is observed by monitoring inference behaviour over time, not by " +
			"inspecting a file.",
	},
	{
		ID: "AML.T0024", Name: "Exfiltration via AI Inference API", Tactic: "Exfiltration",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0004", "AML.M0005"},
		Rationale: "An inference-time attack against a deployed endpoint. Nothing in the artifact " +
			"indicates it.",
	},
	{
		ID: "AML.T0051", Name: "LLM Prompt Injection", Tactic: "Defense Evasion",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0020", "AML.M0033"},
		Rationale:   "A runtime input attack. Requires guardrails at the inference boundary.",
	},
	{
		ID: "AML.T0070", Name: "RAG Poisoning", Tactic: "Persistence",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0030", "AML.M0033"},
		Rationale:   "Targets a live retrieval store, not a model artifact.",
	},
	{
		// Called out by name because buyers assume a "supply chain scanner"
		// covers it, and it does not.
		ID: "AML.T0109", Name: "AI Supply Chain Rug Pull", Tactic: "Resource Development",
		Coverage:    CoverageOutOfScope,
		Mitigations: nil,
		Rationale: "A trusted artifact replaced with a malicious one after adoption. Detecting it needs " +
			"version history across time, not a point-in-time scan. Cupel's periodic rescan narrows the " +
			"window — a rescan under a new name preserves the earlier verdict for comparison — but it " +
			"does not detect the pattern itself.",
	},
	{
		ID: "AML.T0111", Name: "AI Supply Chain Reputation Inflation", Tactic: "Resource Development",
		Coverage:    CoverageOutOfScope,
		Mitigations: nil,
		Rationale: "Manufactured popularity signals. Requires download, star and fork time-series from " +
			"the registry. No artifact property reveals it.",
	},
	{
		ID: "AML.T0044", Name: "Full AI Model Access", Tactic: "AI Model Access",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0005", "AML.M0019"},
		Rationale:   "A property of who can reach the model, not of the model. Access control, not scanning.",
	},
	{
		ID: "AML.T0012", Name: "Valid Accounts", Tactic: "Initial Access",
		Coverage:    CoverageOutOfScope,
		Mitigations: []string{"AML.M0005", "AML.M0019"},
		Rationale: "Credential and identity control. Cupel's own RBAC and tenant scoping address the " +
			"console, not this technique in a customer's environment.",
	},
}

// atlasMitigations are the mitigation IDs referenced above.
var atlasMitigations = map[string]string{
	"AML.M0003": "Predictive AI Model Hardening",
	"AML.M0004": "Limit AI Service Query Volume and Rate",
	"AML.M0005": "Control Access to AI Models and Data at Rest",
	"AML.M0007": "Sanitize Training Data",
	"AML.M0008": "Validate AI Model",
	"AML.M0011": "Restrict Library Loading",
	"AML.M0013": "Code Signing",
	"AML.M0014": "Verify AI Artifacts",
	"AML.M0015": "Predictive AI Adversarial Input Detection",
	"AML.M0016": "Vulnerability Scanning",
	"AML.M0017": "AI Model Distribution Methods",
	"AML.M0019": "Control Access to AI Models and Data in Production",
	"AML.M0020": "Generative AI Guardrails",
	"AML.M0023": "AI Bill of Materials",
	"AML.M0025": "Maintain AI Dataset Provenance",
	"AML.M0030": "Restrict AI Agent Tool Invocation on Untrusted Data",
	"AML.M0033": "Input and Output Validation for AI Agent Components",
	"AML.M0035": "AI Red Team",
}

// ATLASTechniques returns the full mapping.
func ATLASTechniques() []Technique {
	out := make([]Technique, len(atlasTechniques))
	copy(out, atlasTechniques)
	return out
}

// ATLASTechnique looks up one technique, following a deprecation if needed.
func ATLASTechnique(id string) (Technique, bool) {
	if replacement, deprecated := ReplacementFor(id); deprecated {
		id = replacement
	}
	for _, t := range atlasTechniques {
		if t.ID == id {
			return t, true
		}
	}
	return Technique{}, false
}

// MitigationName returns the published name of an ATLAS mitigation.
func MitigationName(id string) (string, bool) {
	name, ok := atlasMitigations[id]
	return name, ok
}

// ATLASCoverageSummary counts techniques by coverage level.
type ATLASCoverageSummary struct {
	Version    string `json:"version"`
	Detected   int    `json:"detected"`
	Partial    int    `json:"partial"`
	OutOfScope int    `json:"outOfScope"`
	Total      int    `json:"total"`
}

// SummarizeATLASCoverage reports what Cupel claims across the mapping.
func SummarizeATLASCoverage() ATLASCoverageSummary {
	s := ATLASCoverageSummary{Version: ATLASVersion, Total: len(atlasTechniques)}
	for _, t := range atlasTechniques {
		switch t.Coverage {
		case CoverageDetected:
			s.Detected++
		case CoveragePartial:
			s.Partial++
		case CoverageOutOfScope:
			s.OutOfScope++
		}
	}
	return s
}
