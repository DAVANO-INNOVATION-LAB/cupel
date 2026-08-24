# TruffleHog — detects credentials embedded in model artifacts.
ARG TRUFFLEHOG_VERSION=3.97.0

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS fetcher
ARG TRUFFLEHOG_VERSION
ARG TARGETARCH=amd64

RUN microdnf install -y tar gzip ca-certificates && microdnf clean all
RUN curl -fsSL -o /tmp/th.tar.gz \
      "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    tar -xzf /tmp/th.tar.gz -C /usr/local/bin trufflehog && \
    chmod 0755 /usr/local/bin/trufflehog

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY --from=fetcher /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY entrypoint.sh /usr/local/bin/cupel-scan
RUN chmod 0755 /usr/local/bin/cupel-scan

ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/cache

USER 65532:65532

# OCI labels. The source label is what links a published package back to this
# repository on GitHub — without it the package is an orphan in the org's
# package list and cannot inherit the repository's visibility.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/cupel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Davano Innovation Lab" \
      org.opencontainers.image.title="cupel-scanner-trufflehog" \
      org.opencontainers.image.description="TruffleHog secret scanner"

ENTRYPOINT ["/usr/local/bin/cupel-scan"]
