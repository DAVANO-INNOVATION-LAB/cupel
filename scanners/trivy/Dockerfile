# Trivy — the primary vulnerability and misconfiguration scanner.
ARG TRIVY_VERSION=0.74.0

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS fetcher
ARG TRIVY_VERSION
ARG TARGETARCH=amd64
# Bake the vulnerability database into the image so scans work with no egress.
# This is what makes the scanner usable in an air-gapped or defense cluster;
# the tradeoff is a much larger image that must be rebuilt to refresh the DB.
ARG BAKE_DB=true

RUN microdnf install -y tar gzip ca-certificates && microdnf clean all

# Trivy's release assets use its own architecture names, not Go's.
RUN case "${TARGETARCH}" in \
      amd64) ASSET="Linux-64bit" ;; \
      arm64) ASSET="Linux-ARM64" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${ASSET}.tar.gz" && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    chmod 0755 /usr/local/bin/trivy

RUN mkdir -p /opt/trivy-db && \
    if [ "$BAKE_DB" = "true" ]; then \
      /usr/local/bin/trivy --cache-dir /opt/trivy-db image --download-db-only; \
    fi

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=fetcher /opt/trivy-db /opt/trivy-db
COPY entrypoint.sh /usr/local/bin/cupel-scan
RUN chmod 0755 /usr/local/bin/cupel-scan && chmod -R a+rX /opt/trivy-db

# The baked DB lives on the read-only root filesystem. Trivy also wants to
# write a scan cache, which is kept in memory so no writable cache dir is
# needed for the database itself.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/cache \
    TRIVY_CACHE_DIR=/opt/trivy-db \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_SKIP_JAVA_DB_UPDATE=true \
    TRIVY_NO_PROGRESS=true \
    TRIVY_DISABLE_TELEMETRY=true

USER 65532:65532

# OCI labels. The source label is what links a published package back to this
# repository on GitHub — without it the package is an orphan in the org's
# package list and cannot inherit the repository's visibility.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/cupel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Davano Innovation Lab" \
      org.opencontainers.image.title="cupel-scanner-trivy" \
      org.opencontainers.image.description="Trivy with vulnerability database baked in"

ENTRYPOINT ["/usr/local/bin/cupel-scan"]
