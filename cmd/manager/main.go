// Command manager runs the Cupel operator: the Model Registry
// connector, the scan orchestrator, and the admission gate.
package main

import (
	"flag"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	cupelmetrics "github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		panic(err)
	}
}

func main() {
	var (
		trustRootPath          string
		auditNamespace         string
		requireTransparencyLog bool
		metricsAddr            string
		probeAddr              string
		enableLeaderElection   bool
		enableWebhook          bool
		operatorImage          string
		scannerRegistry        string
		scanServiceAccount     string
		pullSecret             string
		storageSecret          string
		workspaceSize          string
		jobTTLSeconds          int
		defaultPolicy          string
		requireReport          bool
		reportNamespace        string
		scanDeadlineMinutes    int
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address the metric endpoint binds to")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "address the probe endpoint binds to")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "enable leader election for controller manager")
	flag.BoolVar(&enableWebhook, "enable-webhook", true, "serve the model deployment admission webhook")
	flag.StringVar(&operatorImage, "operator-image", os.Getenv("CUPEL_OPERATOR_IMAGE"),
		"Cupel image used for the fetch, publish, and built-in scanner steps")
	flag.StringVar(&scannerRegistry, "scanner-registry", os.Getenv("CUPEL_SCANNER_REGISTRY"),
		"registry host and namespace holding the scanner images; set this to a mirror for air-gapped clusters")
	flag.StringVar(&scanServiceAccount, "scan-service-account", "cupel-scanner",
		"service account scan jobs run as")
	flag.StringVar(&pullSecret, "pull-secret", os.Getenv("CUPEL_PULL_SECRET"),
		"name of a dockerconfigjson Secret mounted into scan jobs for OCI pulls")
	flag.StringVar(&storageSecret, "storage-secret", os.Getenv("CUPEL_STORAGE_SECRET"),
		"name of a Secret holding S3/ODF credentials for artifact fetches")
	flag.StringVar(&workspaceSize, "workspace-size", "50Gi",
		"size limit for the scan workspace volume")
	flag.IntVar(&jobTTLSeconds, "job-ttl-seconds", 3600,
		"seconds to retain completed scan jobs")
	flag.StringVar(&defaultPolicy, "default-policy", os.Getenv("CUPEL_DEFAULT_POLICY"),
		"policy consulted by the admission gate when a workload names none")
	flag.BoolVar(&requireReport, "require-report", false,
		"deny workloads that reference a model with no Cupel security report")
	flag.IntVar(&scanDeadlineMinutes, "scan-deadline-minutes", 120,
		"fail a scan that has not reached a verdict within this many minutes; "+
			"without it a scan whose report never lands retries forever")
	flag.StringVar(&auditNamespace, "audit-namespace", os.Getenv("POD_NAMESPACE"),
		"namespace for the tamper-evident decision log; empty disables recording, "+
			"which also leaves the AU-9 control mapping with nothing behind it")
	flag.StringVar(&trustRootPath, "trust-root", os.Getenv("CUPEL_TRUST_ROOT"),
		"path to a Sigstore trusted-root JSON file for signature verification; "+
			"left empty, provenance reports that it cannot verify rather than fetching one over the network")
	flag.BoolVar(&requireTransparencyLog, "require-transparency-log", false,
		"demand an auditable transparency-log entry, not just a valid signature")
	flag.StringVar(&reportNamespace, "report-namespace", os.Getenv("POD_NAMESPACE"),
		"namespace the scan pipeline writes reports into; the admission gate searches "+
			"the workload's namespace first and then this one. Defaults to POD_NAMESPACE")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Registered before the manager starts so the endpoint never serves a
	// partial metric set.
	cupelmetrics.Register()

	if operatorImage == "" {
		setupLog.Error(nil, "operator image is required; set --operator-image or CUPEL_OPERATOR_IMAGE")
		os.Exit(1)
	}

	parsedWorkspaceSize, err := resource.ParseQuantity(workspaceSize)
	if err != nil {
		setupLog.Error(err, "invalid --workspace-size")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "cupel-model-scanner.security.davano.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	jobConfig := controller.JobConfig{
		OperatorImage:           operatorImage,
		ScannerRegistry:         scannerRegistry,
		ServiceAccount:          scanServiceAccount,
		PullSecret:              pullSecret,
		StorageSecret:           storageSecret,
		WorkspaceSize:           parsedWorkspaceSize,
		TTLSecondsAfterFinished: int32(jobTTLSeconds),
	}

	if err := (&controller.ModelRegistryConnectorReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// Uncached: a cached Secret read would start an informer over every
		// Secret in the cluster.
		SecretReader: mgr.GetAPIReader(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ModelRegistryConnector")
		os.Exit(1)
	}

	if err := (&controller.ArtifactScanReconciler{
		Client:                 mgr.GetClient(),
		Scheme:                 mgr.GetScheme(),
		JobConfig:              jobConfig,
		ScanDeadline:           time.Duration(scanDeadlineMinutes) * time.Minute,
		TrustRootPath:          trustRootPath,
		AuditNamespace:         auditNamespace,
		RequireTransparencyLog: requireTransparencyLog,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ArtifactScan")
		os.Exit(1)
	}

	if err := (&controller.PromotionReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		AuditNamespace: auditNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Promotion")
		os.Exit(1)
	}

	if err := (&controller.ComplianceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// Revocation only counts as a control when something enforces it, so
		// the assessment is told whether the gate is actually running.
		AdmissionEnforcing: enableWebhook,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Compliance")
		os.Exit(1)
	}

	if enableWebhook {
		if reportNamespace == "" {
			// Without this the gate only looks in the workload's own namespace,
			// where reports do not live, and every deployment is admitted as
			// "unscanned". Better to say so at startup than to gate nothing.
			setupLog.Info("WARNING: --report-namespace is unset and POD_NAMESPACE is empty; " +
				"the admission gate will only find reports that share a namespace with the workload")
		}
		gate := &cupelwebhook.ModelGate{
			Client:          mgr.GetClient(),
			DefaultPolicy:   defaultPolicy,
			RequireReport:   requireReport,
			ReportNamespace: reportNamespace,
		}
		// The chain records the admissions that cannot be reconstructed from
		// the rest of the trail: every denial, and every admission that
		// happened despite something. Without a namespace to write to there
		// is nowhere to put them, and the gate still gates.
		if auditNamespace != "" {
			gate.Recorder = &audit.Recorder{Client: mgr.GetClient(), Namespace: auditNamespace}
		}
		if err := gate.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to set up admission webhook")
			os.Exit(1)
		}
		// Signs risk acceptances with the authenticated identity of whoever
		// created them, so a waiver records who actually accepted it rather
		// than whichever name they typed.
		// The signer records accepted risks itself: this webhook is the only
		// place the authenticated identity of the approver exists, so a
		// controller reading the stored object later can only see a claim.
		signer := &cupelwebhook.ExceptionSigner{}
		if auditNamespace != "" {
			signer.Recorder = &audit.Recorder{Client: mgr.GetClient(), Namespace: auditNamespace}
		}
		if err := signer.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to set up exception signer")
			os.Exit(1)
		}
		// Promotion requests are signed on the same principle: the identity
		// that asked and the identity that decided both come from the
		// authenticated request rather than from the payload.
		if err := (&cupelwebhook.PromotionSigner{}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to set up promotion signer")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	// Readiness has to mean "the webhook is actually serving TLS", not just
	// "the process is alive". Ping alone passes immediately, so the pod joins
	// the Service's endpoints before the listener is up; with the webhook's
	// failurePolicy of Ignore, every admission during that window is admitted
	// unchecked — a gate that silently opens on each rollout and restart.
	readyCheck := healthz.Ping
	if enableWebhook {
		readyCheck = mgr.GetWebhookServer().StartedChecker()
	}
	if err := mgr.AddReadyzCheck("readyz", readyCheck); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting Cupel", "webhook", enableWebhook, "image", operatorImage)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
