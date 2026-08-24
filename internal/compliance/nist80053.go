package compliance

// NIST SP 800-53 Rev 5 mapping, for the controls Cupel contributes evidence
// toward on the AI model layer.
//
// Two framings matter here and are easy to blur.
//
// First, this is a **subset**, not a baseline. It is the controls an artifact
// scanner speaks to, drawn from the priorities the DoD AI Cybersecurity Risk
// Management Tailoring Guide sets out — which maps MITRE ATLAS threat vectors
// onto CNSSI 1253 and 800-53 and separates an infrastructure layer from a
// model layer. Cupel operates on the model layer. Nothing here says anything
// about the infrastructure controls a system also has to satisfy.
//
// Second, and more important for anyone putting this in front of an
// authorizing official: Cupel *contributes evidence toward* these controls. It
// does not satisfy them. A control is satisfied by a system, assessed by a
// human, in a documented boundary. A scanner produces one input to that. The
// Automation value on each entry says how much of an input, and a control
// marked AutomationNone is here to record that Cupel has nothing to offer it,
// not to pad the list.
//
// CNSSI 1253 is the National Security Systems categorization and overlay on
// top of 800-53; the control identifiers are the same, so a mapping to 800-53
// carries across. The overlay decides which controls apply at which
// impact level, and that is a system decision, not one a tool can make.

// NIST80053R5 is NIST Special Publication 800-53 Revision 5.
const NIST80053R5 Framework = "nist-sp-800-53r5"

// Control families used below. The Function field groups controls in the
// generic catalog machinery; for 800-53 the family is what does that job.
const (
	FamilyAccessControl     Function = "AC"
	FamilyAudit             Function = "AU"
	FamilyAssessment        Function = "CA"
	FamilyConfigurationMgmt Function = "CM"
	FamilyRiskAssessment    Function = "RA"
	FamilySystemAcquisition Function = "SA"
	FamilySystemIntegrity   Function = "SI"
	FamilySupplyChain       Function = "SR"
)

// nist80053r5 are the controls Cupel speaks to.
var nist80053r5 = []Control{
	// ---------------- Supply chain: the closest fit ----------------
	{
		ID: "SR-4", Function: FamilySupplyChain, Category: "SR",
		Text:       "Provenance: document, monitor, and maintain valid provenance of systems, system components, and associated data.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceProvenance, EvidenceInventory},
		Rationale: "Cupel verifies Sigstore signatures against declared trusted publishers and records which " +
			"identity signed which bytes, with partial signature coverage reported as its own finding. It " +
			"establishes provenance for the artifact it scanned; it cannot establish provenance for the data " +
			"the model was trained on, which is the other half of what this control asks for.",
	},
	{
		ID: "SR-11", Function: FamilySupplyChain, Category: "SR",
		Text:       "Component Authenticity: develop and implement anti-counterfeit policy and procedures, including the detection of counterfeit components.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceProvenance},
		Rationale: "Signature verification detects an artifact that did not come from the publisher it claims. " +
			"It does not detect a counterfeit that a trusted publisher was induced to sign.",
	},
	{
		ID: "SR-10", Function: FamilySupplyChain, Category: "SR",
		Text:       "Inspection of Systems or Components: inspect systems or components to detect tampering.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceSecurityScan, EvidenceCoverageGap},
		Rationale: "This is what the scanner does. The coverage record matters as much as the findings: an " +
			"inspection that skipped part of the artifact is a partial inspection and is reported as one.",
	},
	{
		ID: "SR-3", Function: FamilySupplyChain, Category: "SR",
		Text:       "Supply Chain Controls and Processes: establish a process for identifying and addressing weaknesses or deficiencies in the supply chain elements and processes.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidencePolicy, EvidenceVerdict, EvidenceResidualRisk},
		Rationale: "The policy engine and the admission gate are an executable process for addressing a " +
			"deficiency once found. Identifying weaknesses in the supply chain as a whole is organizational.",
	},

	// ---------------- The scanning controls ----------------
	{
		ID: "RA-5", Function: FamilyRiskAssessment, Category: "RA",
		Text:       "Vulnerability Monitoring and Scanning: monitor and scan for vulnerabilities in the system and hosted applications, and when new vulnerabilities are identified and reported.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceSecurityScan, EvidenceScanHistory, EvidenceCoverageGap},
		Rationale: "Scans on registration, on deployment, and on a schedule, with each scan recording why it " +
			"ran. The periodic rescan is what addresses the 'when new vulnerabilities are identified' clause: " +
			"a verdict describes what was known when it ran, and CVE data moves.",
	},
	{
		ID: "SI-3", Function: FamilySystemIntegrity, Category: "SI",
		Text:       "Malicious Code Protection: implement malicious code protection mechanisms to detect and eradicate malicious code.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceSecurityScan},
		Rationale: "Detection only. Cupel refuses a malicious artifact at admission; it does not eradicate " +
			"anything, and the control's remediation clause is met elsewhere.",
	},
	{
		ID: "SI-7", Function: FamilySystemIntegrity, Category: "SI",
		Text:       "Software, Firmware, and Information Integrity: employ integrity verification tools to detect unauthorized changes to software, firmware, and information.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceProvenance, EvidenceVerdict},
		Rationale: "Every verdict is bound to the digest of the bytes that were scanned, and the admission gate " +
			"refuses a workload whose artifact digest does not match the verdict being relied on. An approval " +
			"cannot be replayed onto different bytes published under the same name.",
	},
	{
		ID: "SI-2", Function: FamilySystemIntegrity, Category: "SI",
		Text:       "Flaw Remediation: identify, report, and correct system flaws.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceSecurityScan, EvidenceResidualRisk},
		Rationale: "Identification and reporting are automated, and an accepted risk is recorded with its " +
			"approver. Correcting a flaw in a third-party model means replacing it, which is a human decision.",
	},

	// ---------------- Inventory and configuration ----------------
	{
		ID: "CM-8", Function: FamilyConfigurationMgmt, Category: "CM",
		Text:       "System Component Inventory: develop and document an inventory of system components that accurately reflects the system and is at the level of granularity deemed necessary for tracking and reporting.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceInventory, EvidenceSBOM},
		Rationale: "Every model version a connected source publishes becomes an inventory entry with its " +
			"posture attached, derived from the registry rather than maintained by hand — which is the " +
			"failure mode this control exists to prevent.",
	},
	{
		ID: "CM-14", Function: FamilyConfigurationMgmt, Category: "CM",
		Text:       "Signed Components: prevent the installation of software and firmware components without verification that the component has been digitally signed using a certificate that is recognized and approved by the organization.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceProvenance, EvidenceVerdict},
		Rationale: "The closest fit in the entire catalogue for what the admission gate does. TrustedPublisher " +
			"is the organization's list of recognised certificates, and a policy requiring a signature refuses " +
			"deployment without one — including when the signature covers only part of the artifact.",
	},
	{
		ID: "CM-7", Function: FamilyConfigurationMgmt, Category: "CM",
		Text:       "Least Functionality: configure the system to provide only mission-essential capabilities.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceSecurityScan, EvidencePolicy},
		Rationale: "Cupel reports formats that execute code on load and lets policy refuse them, which is this " +
			"control applied to serialization: safetensors cannot execute anything, and a pickle can.",
	},

	// ---------------- Audit ----------------
	{
		ID: "AU-2", Function: FamilyAudit, Category: "AU",
		Text:       "Event Logging: identify the types of events that the system is capable of logging in support of the audit function.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceScanHistory, EvidenceResidualRisk, EvidenceRevocation},
		Rationale: "Verdicts, admission decisions, accepted risks and policy changes are all recorded as " +
			"events — the decisions an auditor asks about, rather than only the scans.",
	},
	{
		ID: "AU-3", Function: FamilyAudit, Category: "AU",
		Text:       "Content of Audit Records: ensure that audit records contain information that establishes what type of event occurred, when, where, the source, the outcome, and the identity of any individuals or subjects associated with the event.",
		Automation: AutomationFull,
		Evidence:   []EvidenceKind{EvidenceResidualRisk, EvidenceVerdict},
		Rationale: "Each record carries the event, an actor, a subject bound to an artifact digest, and the " +
			"outcome. The approver on an accepted risk comes from the admission webhook rather than the " +
			"submitted object, so the identity is established rather than claimed.",
	},
	{
		ID: "AU-9", Function: FamilyAudit, Category: "AU",
		Text:       "Protection of Audit Information: protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceResidualRisk},
		Rationale: "The audit chain is hash-linked with a published checkpoint, so modification, reordering and " +
			"deletion are all evident. Evident is not prevented: an operator who controls the store can rewrite " +
			"the whole chain, and only an externally anchored checkpoint closes that. The limitation is " +
			"documented in the package rather than implied.",
	},

	// ---------------- Access control ----------------
	{
		ID: "AC-3", Function: FamilyAccessControl, Category: "AC",
		Text:       "Access Enforcement: enforce approved authorizations for logical access to information and system resources.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidencePolicy},
		Rationale: "The console API authenticates every request and returns only what the subject's role and " +
			"tenant scope permit, with findings redacted server-side rather than hidden in the page. This " +
			"covers access to Cupel's own data, not to the models themselves.",
	},
	{
		ID: "AC-6", Function: FamilyAccessControl, Category: "AC",
		Text:       "Least Privilege: employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned organizational tasks.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidencePolicy},
		Rationale: "Five roles, deny-by-default namespace scoping, and an auditor role that sees findings but " +
			"never the exploit path — enough to audit, not enough to attack. Scan pods hold no cluster " +
			"credentials at all; only the publish step gets a token.",
	},

	// ---------------- Assessment and monitoring ----------------
	{
		ID: "CA-7", Function: FamilyAssessment, Category: "CA",
		Text:       "Continuous Monitoring: develop a system-level continuous monitoring strategy and implement continuous monitoring in accordance with the organization-level strategy.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceScanHistory, EvidenceVerdict},
		Rationale: "Rescanning on an interval, and re-deriving a verdict when the exceptions behind it change, " +
			"is continuous monitoring for the model layer. The strategy itself is organizational.",
	},
	{
		ID: "CA-2", Function: FamilyAssessment, Category: "CA",
		Text:       "Control Assessments: assess the controls in the system and its environment of operation to determine the extent to which the controls are implemented correctly, operating as intended, and producing the desired outcome.",
		Automation: AutomationPartial,
		Evidence:   []EvidenceKind{EvidenceVerdict, EvidenceCoverageGap},
		Rationale: "The evidence bundle is built for this: a portable record an assessor can verify offline, " +
			"stating what was checked, what was not, and what the tool structurally cannot assess.",
	},

	// ---------------- Named to record the gap ----------------
	{
		ID: "SA-11", Function: FamilySystemAcquisition, Category: "SA",
		Text:       "Developer Testing and Evaluation: require the developer of the system, system component, or system service to perform testing and evaluation.",
		Automation: AutomationNone,
		Rationale: "Cupel assesses an artifact it is handed. It says nothing about whether the party that built " +
			"the model tested it, which is what this control requires and what a third-party model almost " +
			"never comes with.",
	},
	{
		ID: "SA-15", Function: FamilySystemAcquisition, Category: "SA",
		Text:       "Development Process, Standards, and Tools: require the developer to follow a documented development process and to define quality metrics.",
		Automation: AutomationNone,
		Rationale:  notObservable,
	},
	{
		ID: "RA-3", Function: FamilyRiskAssessment, Category: "RA",
		Text:       "Risk Assessment: conduct a risk assessment, including the likelihood and magnitude of harm from unauthorized access, use, disclosure, disruption, modification, or destruction of the system.",
		Automation: AutomationNone,
		Rationale: "A risk score over an artifact's findings is not a risk assessment of a system. Likelihood " +
			"and magnitude of harm depend on what the model is used for, which Cupel does not know.",
	},
}

// NIST80053 returns the 800-53 Rev 5 subset Cupel contributes evidence toward.
func NIST80053() *Catalog {
	c := &Catalog{
		Framework: NIST80053R5,
		controls:  append([]Control(nil), nist80053r5...),
		byID:      make(map[string]Control, len(nist80053r5)),
	}
	for _, ctrl := range c.controls {
		c.byID[ctrl.ID] = ctrl
	}
	return c
}
