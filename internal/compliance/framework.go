// Package compliance maps Cupel scan evidence onto AI governance frameworks.
//
// The design constraint that shapes everything here: NIST AI RMF 1.0 is a
// voluntary organizational risk-management framework, not a technical control
// baseline. Of its 72 subcategories, most describe things a scanner cannot
// observe — that staff are trained, that a diverse team reviewed a decision,
// that leadership accepted a risk. A tool claiming to "pass" those is
// producing compliance theater that fails the first real audit.
//
// So every control carries an Automation level, and the evaluator will not
// mark a control satisfied on technical evidence unless the control is
// actually evidenceable. Everything else requires a named human attestation
// with a date, or it stays open.
package compliance

// Framework identifies a governance framework Cupel can report against.
type Framework string

// NISTAIRMF10 is NIST AI 100-1, AI Risk Management Framework 1.0.
const NISTAIRMF10 Framework = "nist-ai-rmf-1.0"

// Function is a top-level AI RMF Core function.
type Function string

const (
	FunctionGovern  Function = "GOVERN"
	FunctionMap     Function = "MAP"
	FunctionMeasure Function = "MEASURE"
	FunctionManage  Function = "MANAGE"
)

// Automation describes how much of a control Cupel can evidence on its own.
//
// This is the honest core of the package. A control marked AutomationNone can
// never be satisfied by a scan result — only by a recorded human attestation.
type Automation string

const (
	// AutomationFull means Cupel produces sufficient technical evidence for
	// the control's intent on its own.
	AutomationFull Automation = "Full"
	// AutomationPartial means Cupel evidences part of the control; the rest
	// needs organizational attestation.
	AutomationPartial Automation = "Partial"
	// AutomationNone means the control is organizational or procedural.
	// No scanner can observe it. Attestation is the only path.
	AutomationNone Automation = "None"
)

// Control is one AI RMF subcategory.
type Control struct {
	// ID is the subcategory identifier, e.g. "MEASURE 2.7".
	ID string
	// Function it belongs to.
	Function Function
	// Category is the parent category identifier, e.g. "MEASURE 2".
	Category string
	// Text is the subcategory statement, quoted from AI RMF 1.0.
	Text string
	// Automation is how much Cupel can evidence.
	Automation Automation
	// Evidence names the Cupel signals that speak to this control. Empty for
	// controls Cupel cannot observe.
	Evidence []EvidenceKind
	// Rationale explains the mapping — why this scan evidence speaks to this
	// control, or why nothing Cupel produces can.
	Rationale string
}

// EvidenceKind is a category of signal Cupel can produce from a scan.
type EvidenceKind string

const (
	// EvidenceInventory — a ModelSecurityReport exists for the version.
	EvidenceInventory EvidenceKind = "inventory"
	// EvidenceSecurityScan — malware, CVE, secret, and model-format results.
	EvidenceSecurityScan EvidenceKind = "security-scan"
	// EvidenceSBOM — a generated software bill of materials.
	EvidenceSBOM EvidenceKind = "sbom"
	// EvidenceAIBOM — a generated bill of materials describing the model
	// itself: its architecture, measured parameter count, precision, licence
	// and declared lineage. Distinct from EvidenceSBOM, which enumerates the
	// packages around the model and says nothing about the model.
	EvidenceAIBOM EvidenceKind = "aibom"
	// EvidenceProvenance — signature and trusted-publisher verification.
	EvidenceProvenance EvidenceKind = "provenance"
	// EvidenceSecrets — embedded credential detection.
	EvidenceSecrets EvidenceKind = "secrets"
	// EvidencePolicy — the ArtifactScanPolicy governing the scan.
	EvidencePolicy EvidenceKind = "policy"
	// EvidenceVerdict — the admission-enforceable approve/quarantine decision.
	EvidenceVerdict EvidenceKind = "verdict"
	// EvidenceRiskScore — the consolidated 0-100 risk score.
	EvidenceRiskScore EvidenceKind = "risk-score"
	// EvidenceResidualRisk — ArtifactExceptions: risks explicitly accepted.
	EvidenceResidualRisk EvidenceKind = "residual-risk"
	// EvidenceScanHistory — repeated scans over time.
	EvidenceScanHistory EvidenceKind = "scan-history"
	// EvidenceRevocation — the ability to deny a previously-approved model.
	EvidenceRevocation EvidenceKind = "revocation"
	// EvidenceCoverageGap — the explicit record of what was NOT measured.
	EvidenceCoverageGap EvidenceKind = "coverage-gap"
	// EvidenceBiasEval — fairness and bias evaluation. Not produced by
	// produced, so controls depending on it fail closed.
	EvidenceBiasEval EvidenceKind = "bias-eval"
)

// notObservable is the standard rationale for organizational controls.
const notObservable = "Organizational or procedural control. No property of a model artifact evidences it; requires a named attestation."

// nistAIRMF10 is the full AI RMF 1.0 Core: 4 functions, 19 categories,
// 72 subcategories. Control text is quoted from NIST AI 100-1.
//
// The Automation value on each entry is a deliberate judgement, not a
// marketing one. Where Cupel contributes only a fragment of what the
// subcategory asks for, it is Partial, and the report still demands an
// attestation to close the control.
var nistAIRMF10 = []Control{
	// ---------------- GOVERN ----------------
	{
		ID: "GOVERN 1.1", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "Legal and regulatory requirements involving AI are understood, managed, and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 1.2", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidencePolicy},
		Rationale: "An ArtifactScanPolicy encodes part of this as executable rules, but only the security and resilience characteristic. The remaining characteristics are policy statements Cupel does not hold.",
	},
	{
		ID: "GOVERN 1.3", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the organization's risk tolerance.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidencePolicy},
		Rationale: "Policy thresholds (maxCriticalCVEs, blockMalware, enforcement mode) are a machine-readable expression of risk tolerance for model artifacts.",
	},
	{
		ID: "GOVERN 1.4", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidencePolicy, EvidenceVerdict},
		Rationale: "Policy and verdict are both stored as inspectable cluster resources, so the process and its outcome are transparent and auditable for the artifact scanning slice of risk management.",
	},
	{
		ID: "GOVERN 1.5", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined, including determining the frequency of periodic review.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceScanHistory},
		Rationale: "Cupel evidences the monitoring cadence through repeated scans. Roles, responsibilities, and review planning are organizational.",
	},
	{
		ID: "GOVERN 1.6", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceInventory, EvidenceRiskScore},
		Rationale: "Cupel maintains a ModelSecurityReport per registered model version, which is a live inventory keyed to the registry and ranked by risk score.",
	},
	{
		ID: "GOVERN 1.7", Function: FunctionGovern, Category: "GOVERN 1",
		Text:       "Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks or decrease the organization's trustworthiness.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceRevocation},
		Rationale: "Revocation plus admission denial is the enforcement half of decommissioning. The surrounding process is organizational.",
	},
	{
		ID: "GOVERN 2.1", Function: FunctionGovern, Category: "GOVERN 2",
		Text:       "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 2.2", Function: FunctionGovern, Category: "GOVERN 2",
		Text:       "The organization's personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 2.3", Function: FunctionGovern, Category: "GOVERN 2",
		Text:       "Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 3.1", Function: FunctionGovern, Category: "GOVERN 3",
		Text:       "Decision-making related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team (e.g., diversity of demographics, disciplines, experience, expertise, and backgrounds).",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 3.2", Function: FunctionGovern, Category: "GOVERN 3",
		Text:       "Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 4.1", Function: FunctionGovern, Category: "GOVERN 4",
		Text:       "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimize potential negative impacts.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 4.2", Function: FunctionGovern, Category: "GOVERN 4",
		Text:       "Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, evaluate, and use, and they communicate about the impacts more broadly.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceSecurityScan, EvidenceRiskScore},
		Rationale: "Scan reports document security risk per model version. Broader impact documentation is organizational.",
	},
	{
		ID: "GOVERN 4.3", Function: FunctionGovern, Category: "GOVERN 4",
		Text:       "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceSecurityScan},
		Rationale: "Automated scanning on every registration is a testing practice. Incident handling and information sharing are organizational.",
	},
	{
		ID: "GOVERN 5.1", Function: FunctionGovern, Category: "GOVERN 5",
		Text:       "Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system regarding the potential individual and societal impacts related to AI risks.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 5.2", Function: FunctionGovern, Category: "GOVERN 5",
		Text:       "Mechanisms are established to enable the team that developed or deployed AI systems to regularly incorporate adjudicated feedback from relevant AI actors into system design and implementation.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "GOVERN 6.1", Function: FunctionGovern, Category: "GOVERN 6",
		Text:       "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party's intellectual property or other rights.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceSBOM, EvidencePolicy},
		Rationale: "The SBOM enumerates third-party components and their licences, which is the evidentiary basis for IP risk. The policy governing them is organizational.",
	},
	{
		ID: "GOVERN 6.2", Function: FunctionGovern, Category: "GOVERN 6",
		Text:       "Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceVerdict, EvidenceRevocation},
		Rationale: "Quarantine and revocation are the automated contingency for a third-party model found to be high-risk. The wider incident process is organizational.",
	},

	// ---------------- MAP ----------------
	{
		ID: "MAP 1.1", Function: FunctionMap, Category: "MAP 1",
		Text:       "Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 1.2", Function: FunctionMap, Category: "MAP 1",
		Text:       "Interdisciplinary AI actors, competencies, skills, and capacities for establishing context reflect demographic diversity and broad domain and user experience expertise, and their participation is documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 1.3", Function: FunctionMap, Category: "MAP 1",
		Text:       "The organization's mission and relevant goals for AI technology are understood and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 1.4", Function: FunctionMap, Category: "MAP 1",
		Text:       "The business value or context of business use has been clearly defined or – in the case of assessing existing AI systems – re-evaluated.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 1.5", Function: FunctionMap, Category: "MAP 1",
		Text:       "Organizational risk tolerances are determined and documented.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidencePolicy},
		Rationale: "Policy thresholds document risk tolerance for model artifacts in machine-readable form. Tolerances for other risk classes are organizational.",
	},
	{
		ID: "MAP 1.6", Function: FunctionMap, Category: "MAP 1",
		Text:       "System requirements are elicited from and understood by relevant AI actors. Design decisions take socio-technical implications into account to address AI risks.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 2.1", Function: FunctionMap, Category: "MAP 2",
		Text:       "The specific tasks and methods used to implement the tasks that the AI system will support are defined (e.g., classifiers, generative models, recommenders).",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceInventory, EvidenceAIBOM},
		Rationale: "The bill of materials records the architecture measured from the weights and the task the model card declares, which is the method framing this subcategory asks for. Inventory alone never was: it named a file format. Whether the declared task is the right one for the deployment remains a registry-authoring responsibility.",
	},
	{
		ID: "MAP 2.2", Function: FunctionMap, Category: "MAP 2",
		Text:       "Information about the AI system's knowledge limits and how system output may be utilized and overseen by humans is documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 2.3", Function: FunctionMap, Category: "MAP 2",
		Text:       "Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection, system trustworthiness, and construct validation.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 3.1", Function: FunctionMap, Category: "MAP 3",
		Text:       "Potential benefits of intended AI system functionality and performance are examined and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 3.2", Function: FunctionMap, Category: "MAP 3",
		Text:       "Potential costs, including non-monetary costs, which result from expected or realized AI errors or system functionality and trustworthiness – as connected to organizational risk tolerance – are examined and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 3.3", Function: FunctionMap, Category: "MAP 3",
		Text:       "Targeted application scope is specified and documented based on the system's capability, established context, and AI system categorization.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 3.4", Function: FunctionMap, Category: "MAP 3",
		Text:       "Processes for operator and practitioner proficiency with AI system performance and trustworthiness – and relevant technical standards and certifications – are defined, assessed, and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 3.5", Function: FunctionMap, Category: "MAP 3",
		Text:       "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the govern function.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceResidualRisk},
		Rationale: "Exception approval and promotion are human-in-the-loop steps Cupel records with an authenticated approver: a waiver carries an approver and an expiry, and a promotion into an environment requires a decision signed by the identity that made it and re-checks the security verdict at the moment it is acted on. The wider oversight design is organizational.",
	},
	{
		ID: "MAP 4.1", Function: FunctionMap, Category: "MAP 4",
		Text:       "Approaches for mapping AI technology and legal risks of its components – including the use of third-party data or software – are in place, followed, and documented, as are risks of infringement of a third party's intellectual property or other rights.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceSBOM},
		Rationale: "The SBOM is the component map for third-party software in the artifact. Data provenance and legal analysis are organizational.",
	},
	{
		ID: "MAP 4.2", Function: FunctionMap, Category: "MAP 4",
		Text:       "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidencePolicy, EvidenceSecurityScan},
		Rationale: "The ArtifactScanPolicy is a documented, version-controlled statement of the internal risk controls applied to every model component, and the scan report records that they ran.",
	},
	{
		ID: "MAP 5.1", Function: FunctionMap, Category: "MAP 5",
		Text:       "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MAP 5.2", Function: FunctionMap, Category: "MAP 5",
		Text:       "Practices and personnel for supporting regular engagement with relevant AI actors and integrating feedback about positive, negative, and unanticipated impacts are in place and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},

	// ---------------- MEASURE ----------------
	{
		ID: "MEASURE 1.1", Function: FunctionMeasure, Category: "MEASURE 1",
		Text:       "Approaches and metrics for measurement of AI risks enumerated during the map function are selected for implementation starting with the most significant AI risks. The risks or trustworthiness characteristics that will not – or cannot – be measured are properly documented.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidencePolicy, EvidenceCoverageGap},
		Rationale: "The policy names the scanners selected, and Cupel emits an explicit coverage gap for every trustworthiness characteristic it does not measure — which is precisely the documentation this subcategory asks for.",
	},
	{
		ID: "MEASURE 1.2", Function: FunctionMeasure, Category: "MEASURE 1",
		Text:       "Appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated, including reports of errors and potential impacts on affected communities.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 1.3", Function: FunctionMeasure, Category: "MEASURE 1",
		Text:       "Internal experts who did not serve as front-line developers for the system and/or independent assessors are involved in regular assessments and updates.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 2.1", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Test sets, metrics, and details about the tools used during TEVV are documented.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceSecurityScan, EvidencePolicy},
		Rationale: "Cupel records which scanner ran, at which pinned image version, and what it found. Test sets for model performance TEVV are outside its scope.",
	},
	{
		ID: "MEASURE 2.2", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Evaluations involving human subjects meet applicable requirements (including human subject protection) and are representative of the relevant population.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 2.3", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment setting(s). Measures are documented.",
		Automation: AutomationNone, Rationale: "Model performance measurement is outside the scope of artifact scanning; requires a TEVV pipeline attestation.",
	},
	{
		ID: "MEASURE 2.4", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "The functionality and behavior of the AI system and its components – as identified in the map function – are monitored when in production.",
		Automation: AutomationNone, Rationale: "This subcategory concerns inference behaviour in production. Cupel assesses the artifact, so this control takes evidence from runtime monitoring or an attestation.",
	},
	{
		ID: "MEASURE 2.5", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are documented.",
		Automation: AutomationNone, Rationale: "Validity and reliability are model-performance properties; requires a TEVV attestation.",
	},
	{
		ID: "MEASURE 2.6", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "The AI system is evaluated regularly for safety risks – as identified in the map function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely, particularly if made to operate beyond its knowledge limits.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceRiskScore, EvidenceResidualRisk},
		Rationale: "Cupel evidences that residual risk is bounded by policy and explicitly accepted where it is not. Fail-safe behaviour and knowledge limits require a TEVV attestation.",
	},
	{
		ID: "MEASURE 2.7", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "AI system security and resilience – as identified in the map function – are evaluated and documented.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceSecurityScan, EvidenceSecrets, EvidenceSBOM},
		Rationale: "This is the subcategory Cupel exists to satisfy: malware, known vulnerabilities, embedded secrets, and unsafe serialization are evaluated on every model version and the results are retained as cluster resources.",
	},
	{
		ID: "MEASURE 2.8", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Risks associated with transparency and accountability – as identified in the map function – are examined and documented.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceProvenance, EvidenceInventory},
		Rationale: "Signature verification and a per-version audit trail establish artifact accountability. Model transparency and disclosure practices are organizational.",
	},
	{
		ID: "MEASURE 2.9", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "The AI model is explained, validated, and documented, and AI system output is interpreted within its context – as identified in the map function – to inform responsible use and governance.",
		Automation: AutomationNone, Rationale: "Explainability is a model-behaviour property; requires an attestation from the team that built the model.",
	},
	{
		ID: "MEASURE 2.10", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Privacy risk of the AI system – as identified in the map function – is examined and documented.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceSecrets},
		Rationale: "Cupel detects credentials and secrets embedded in the artifact. Training-data privacy, memorization, and re-identification risk require a separate privacy assessment.",
	},
	{
		ID: "MEASURE 2.11", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Fairness and bias – as identified in the map function – are evaluated and results are documented.",
		Automation: AutomationNone, Evidence: []EvidenceKind{EvidenceBiasEval},
		Rationale: "Fairness evaluation is a separate discipline from artifact security and produces its own evidence. This control is satisfied by that evidence or by an attestation naming a reviewer, and is never inferred from a clean security scan.",
	},
	{
		ID: "MEASURE 2.12", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Environmental impact and sustainability of AI model training and management activities – as identified in the map function – are assessed and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 2.13", Function: FunctionMeasure, Category: "MEASURE 2",
		Text:       "Effectiveness of the employed TEVV metrics and processes in the measure function are evaluated and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 3.1", Function: FunctionMeasure, Category: "MEASURE 3",
		Text:       "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceScanHistory},
		Rationale: "Repeated scanning tracks emergent supply-chain risk as new vulnerabilities are published against an unchanged artifact. Performance-driven risk tracking is organizational.",
	},
	{
		ID: "MEASURE 3.2", Function: FunctionMeasure, Category: "MEASURE 3",
		Text:       "Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement techniques or where metrics are not yet available.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceCoverageGap},
		Rationale: "Cupel records what it could not measure, which is the input to this consideration. The consideration itself is organizational.",
	},
	{
		ID: "MEASURE 3.3", Function: FunctionMeasure, Category: "MEASURE 3",
		Text:       "Feedback processes for end users and impacted communities to report problems and appeal system outcomes are established and integrated into AI system evaluation metrics.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 4.1", Function: FunctionMeasure, Category: "MEASURE 4",
		Text:       "Measurement approaches for identifying AI risks are connected to deployment context(s) and informed through consultation with domain experts and other end users. Approaches are documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 4.2", Function: FunctionMeasure, Category: "MEASURE 4",
		Text:       "Measurement results regarding AI system trustworthiness in deployment context(s) and across the AI lifecycle are informed by input from domain experts and relevant AI actors to validate whether the system is performing consistently as intended.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MEASURE 4.3", Function: FunctionMeasure, Category: "MEASURE 4",
		Text:       "Measurable performance improvements or declines based on consultations with relevant AI actors, including affected communities, and field data about context-relevant risks and trustworthiness characteristics are identified and documented.",
		Automation: AutomationNone, Rationale: notObservable,
	},

	// ---------------- MANAGE ----------------
	{
		ID: "MANAGE 1.1", Function: FunctionManage, Category: "MANAGE 1",
		Text:       "A determination is made as to whether the AI system achieves its intended purposes and stated objectives and whether its development or deployment should proceed.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceVerdict},
		Rationale: "The verdict is a recorded, enforced determination on whether deployment proceeds. Whether the model achieves its intended purpose is a TEVV question Cupel does not answer.",
	},
	{
		ID: "MANAGE 1.2", Function: FunctionManage, Category: "MANAGE 1",
		Text:       "Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceRiskScore, EvidenceSecurityScan},
		Rationale: "Findings are severity-ranked and consolidated into a risk score that orders treatment, with model-level execution risk weighted above equivalent-severity CVEs.",
	},
	{
		ID: "MANAGE 1.3", Function: FunctionManage, Category: "MANAGE 1",
		Text:       "Responses to the AI risks deemed high priority, as identified by the map function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceVerdict, EvidenceResidualRisk},
		Rationale: "Quarantine is avoidance, an ArtifactException is documented acceptance with a named approver and an expiry, and admission enforcement is the mitigation. All three are recorded.",
	},
	{
		ID: "MANAGE 1.4", Function: FunctionManage, Category: "MANAGE 1",
		Text:       "Negative residual risks (defined as the sum of all unmitigated risks) to both downstream acquirers of AI systems and end users are documented.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceResidualRisk, EvidenceCoverageGap},
		Rationale: "Waived policy violations are exactly the unmitigated risk set, and Cupel records each with the reason it was accepted, by whom, and until when — alongside what was never measured.",
	},
	{
		ID: "MANAGE 2.1", Function: FunctionManage, Category: "MANAGE 2",
		Text:       "Resources required to manage AI risks are taken into account – along with viable non-AI alternative systems, approaches, or methods – to reduce the magnitude or likelihood of potential impacts.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MANAGE 2.2", Function: FunctionManage, Category: "MANAGE 2",
		Text:       "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MANAGE 2.3", Function: FunctionManage, Category: "MANAGE 2",
		Text:       "Procedures are followed to respond to and recover from a previously unknown risk when it is identified.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceScanHistory, EvidenceRevocation},
		Rationale: "Rescanning surfaces newly-published vulnerabilities in an unchanged artifact, and revocation withdraws approval. The recovery procedure around it is organizational.",
	},
	{
		ID: "MANAGE 2.4", Function: FunctionManage, Category: "MANAGE 2",
		Text:       "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceRevocation, EvidenceVerdict},
		Rationale: "Revoking a model version causes admission to refuse it, which is an applied deactivation mechanism. Assignment of responsibility is organizational.",
	},
	{
		ID: "MANAGE 3.1", Function: FunctionManage, Category: "MANAGE 3",
		Text:       "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceScanHistory, EvidencePolicy, EvidenceSBOM},
		Rationale: "Every third-party model version is scanned on registration and rescanned on a cadence, with the controls applied recorded in policy and the results retained.",
	},
	{
		ID: "MANAGE 3.2", Function: FunctionManage, Category: "MANAGE 3",
		Text:       "Pre-trained models which are used for development are monitored as part of AI system regular monitoring and maintenance.",
		Automation: AutomationFull, Evidence: []EvidenceKind{EvidenceScanHistory, EvidenceInventory, EvidenceSecurityScan},
		Rationale: "Monitoring pre-trained models is the product's precise purpose: every registered version is inventoried, scanned, and rescanned.",
	},
	{
		ID: "MANAGE 4.1", Function: FunctionManage, Category: "MANAGE 4",
		Text:       "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceScanHistory, EvidenceResidualRisk, EvidenceRevocation},
		Rationale: "Cupel provides the override path (exceptions), the decommissioning path (revocation), and continuous rescanning. User feedback capture and incident response are organizational.",
	},
	{
		ID: "MANAGE 4.2", Function: FunctionManage, Category: "MANAGE 4",
		Text:       "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties, including relevant AI actors.",
		Automation: AutomationNone, Rationale: notObservable,
	},
	{
		ID: "MANAGE 4.3", Function: FunctionManage, Category: "MANAGE 4",
		Text:       "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
		Automation: AutomationPartial, Evidence: []EvidenceKind{EvidenceVerdict},
		Rationale: "A quarantine verdict is recorded and surfaced in the registry, which is the tracking half. Communication to affected parties is organizational.",
	},
}
