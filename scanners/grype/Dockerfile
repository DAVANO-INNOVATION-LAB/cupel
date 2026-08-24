# Grype — vulnerability scanning, run alongside Trivy for corroboration.
ARG GRYPE_VERSION=0.117.0

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS fetcher
ARG GRYPE_VERSION
ARG TARGETARCH=amd64
# Bake the vulnerability database so the scanner works in an air-gapped
# cluster. Set to false to build a smaller image that needs egress at scan time.
ARG BAKE_DB=true

RUN microdnf install -y tar gzip ca-certificates && microdnf clean all
RUN curl -fsSL -o /tmp/grype.tar.gz \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    chmod 0755 /usr/local/bin/grype

RUN if [ "$BAKE_DB" = "true" ]; then \
      GRYPE_DB_CACHE_DIR=/opt/grype-db /usr/local/bin/grype db update; \
    else \
      mkdir -p /opt/grype-db; \
    fi

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY --from=fetcher /usr/local/bin/grype /usr/local/bin/grype
COPY --from=fetcher /opt/grype-db /opt/grype-db
COPY entrypoint.sh /usr/local/bin/cupel-scan
RUN chmod 0755 /usr/local/bin/cupel-scan && chmod -R a+rX /opt/grype-db

ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/cache \
    GRYPE_DB_CACHE_DIR=/opt/grype-db \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false

USER 65532:65532

# OCI labels. The source label is what links a published package back to this
# repository on GitHub — without it the package is an orphan in the org's
# package list and cannot inherit the repository's visibility.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/cupel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Davano Innovation Lab" \
      org.opencontainers.image.title="cupel-scanner-grype" \
      org.opencontainers.image.description="Grype with vulnerability database baked in"

ENTRYPOINT ["/usr/local/bin/cupel-scan"]
