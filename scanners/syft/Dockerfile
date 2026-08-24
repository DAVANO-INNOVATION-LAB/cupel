# Syft — SBOM generation for model artifacts.
ARG SYFT_VERSION=1.51.0

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS fetcher
ARG SYFT_VERSION
ARG TARGETARCH=amd64

RUN microdnf install -y tar gzip ca-certificates && microdnf clean all
RUN curl -fsSL -o /tmp/syft.tar.gz \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    chmod 0755 /usr/local/bin/syft

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY --from=fetcher /usr/local/bin/syft /usr/local/bin/syft
COPY entrypoint.sh /usr/local/bin/cupel-scan

RUN chmod 0755 /usr/local/bin/cupel-scan

# Syft caches unpacked layers under $HOME; point it at the writable tmp volume
# so the container can keep a read-only root filesystem.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/cache \
    SYFT_CHECK_FOR_APP_UPDATE=false

USER 65532:65532

# OCI labels. The source label is what links a published package back to this
# repository on GitHub — without it the package is an orphan in the org's
# package list and cannot inherit the repository's visibility.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/cupel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Davano Innovation Lab" \
      org.opencontainers.image.title="cupel-scanner-syft" \
      org.opencontainers.image.description="Syft SBOM generator"

ENTRYPOINT ["/usr/local/bin/cupel-scan"]
