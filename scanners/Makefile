# Builds the Cupel scanner images.
#
# Each image exposes the same contract: the entrypoint takes the staged
# artifact directory and the output file as its two positional arguments.
# internal/scanners/catalog_test.go enforces that the operator agrees.

REGISTRY ?= ghcr.io/davano-innovation-lab
# Must match scanners.ImageTag in internal/scanners/catalog.go.
TAG ?= 0.2.4
PLATFORM ?= linux/amd64
CONTAINER_TOOL ?= docker

# Bake vulnerability and signature databases into the images so scans need no
# egress. Set to false for smaller images that require network at scan time.
BAKE_DB ?= true

# Scanners that ship as their own image. model-inspector and provenance are
# implemented by the Cupel runner and ship in the operator image instead.
SCANNERS ?= clamav trivy syft trufflehog grype

TARGETARCH := $(word 2,$(subst /, ,$(PLATFORM)))

.PHONY: all
all: build ## Build every scanner image.

.PHONY: build
build: $(addprefix build-,$(SCANNERS)) ## Build every scanner image.

.PHONY: build-%
build-%:
	@echo "==> building $* ($(PLATFORM))"
	# --load is what puts the result in the local image store so the smoke
	# test can `docker run` it. Without it this silently succeeds and leaves
	# nothing runnable behind: buildx's container driver keeps the image in
	# its own cache, and any CI that has run setup-buildx-action gets that
	# driver by default even though the command still reads like `docker build`.
	$(CONTAINER_TOOL) buildx build \
		--platform $(PLATFORM) \
		--load \
		--build-arg TARGETARCH=$(TARGETARCH) \
		--build-arg BAKE_DB=$(BAKE_DB) \
		-t $(REGISTRY)/scanner-$*:$(TAG) \
		$*

# Multi-arch. Building and pushing are one step because a manifest list cannot
# be held in the local image store — buildx has to write it straight to the
# registry. Each scanner's Dockerfile already selects the right upstream asset
# from TARGETARCH, so this needs no per-scanner special casing.
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: buildx
buildx: $(addprefix buildx-,$(SCANNERS)) ## Build and push every scanner for every platform.

.PHONY: buildx-%
buildx-%:
	@echo "==> building $* ($(PLATFORMS))"
	$(CONTAINER_TOOL) buildx build \
		--platform $(PLATFORMS) \
		--build-arg BAKE_DB=$(BAKE_DB) \
		-t $(REGISTRY)/scanner-$*:$(TAG) \
		--push \
		$*

.PHONY: push
push: $(addprefix push-,$(SCANNERS)) ## Push every scanner image.

.PHONY: push-%
push-%:
	$(CONTAINER_TOOL) push $(REGISTRY)/scanner-$*:$(TAG)

.PHONY: smoke
smoke: ## Run every built scanner against the bundled test fixture.
	./smoke-test.sh $(REGISTRY) $(TAG)

.PHONY: mirror
mirror: ## Print the image list for mirroring into an air-gapped registry.
	@for s in $(SCANNERS); do echo "$(REGISTRY)/scanner-$$s:$(TAG)"; done

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\n"} \
		/^[a-zA-Z_%-]+:.*?##/ { printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
