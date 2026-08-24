# Cupel ships one image containing four binaries: the operator manager, the
# in-pod scan runner, the console API server, and the standalone CLI. Scan Jobs mount the same image
# for their fetch and publish steps, so there is a single artifact to mirror
# into an air-gapped registry, and `docker run --entrypoint /cupel` gives the
# same scanner to anyone without a cluster.
# Must be at least the go directive in go.mod, which oras-go pins to 1.25.
# Pinned to the BUILD platform, not the target. The binaries are pure Go with
# CGO disabled, so GOARCH cross-compiles them natively — emulating this stage
# under QEMU to produce an arm64 binary compiles perhaps twenty times slower
# for an identical result. Only the tiny runtime stage below is arch-specific.
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:1.25 AS builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w" -o cupel-manager ./cmd/manager && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w" -o cupel-runner ./cmd/runner && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -a -ldflags="-s -w -X main.version=${VERSION}" -o cupel ./cmd/cupel && \
      go build -a -ldflags="-s -w" -o cupel-api ./cmd/api

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

WORKDIR /

# The CA bundle. ubi-micro ships no trust store at all, so without this every
# HTTPS call the operator makes fails with "certificate signed by unknown
# authority" — the Model Registry, Hugging Face, S3, all of it. It is copied
# from the builder rather than installed, because ubi-micro has no package
# manager to install it with.
COPY --from=builder /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /workspace/cupel-manager /cupel-manager
COPY --from=builder /workspace/cupel-runner /cupel-runner
COPY --from=builder /workspace/cupel-api /cupel-api
COPY --from=builder /workspace/cupel /cupel

# 65532 is the conventional nonroot UID. OpenShift assigns its own UID from
# the namespace range, which works because the binaries need no writable paths.
USER 65532:65532


# OCI labels. The source label is what links a published package back to this
# repository on GitHub — without it the package is an orphan in the org's
# package list and cannot inherit the repository's visibility.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/cupel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Davano Innovation Lab" \
      org.opencontainers.image.title="cupel" \
      org.opencontainers.image.description="Model supply-chain security operator for OpenShift and Kubernetes"

ENTRYPOINT ["/cupel-manager"]
