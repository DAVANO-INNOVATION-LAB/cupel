# ClamAV — malware scanning for model artifacts.
#
# The signature database is baked in at build time so scans work with no
# egress. Refreshing signatures means rebuilding this image, which is the
# correct tradeoff for an air-gapped or defense cluster: the alternative is a
# scanner that silently runs with no signatures when freshclam cannot reach
# the mirrors.
FROM registry.access.redhat.com/ubi9/ubi:latest AS dbfetcher

ARG BAKE_DB=true

RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
    dnf install -y clamav clamav-update && \
    dnf clean all

# freshclam drops privileges to the clamupdate user, so the destination has to
# be writable by it. Failing the build when the download fails is deliberate:
# an image with no signatures would report every artifact as clean.
RUN mkdir -p /opt/clamav-db && \
    chown clamupdate:clamupdate /opt/clamav-db && \
    if [ "$BAKE_DB" = "true" ]; then \
      sed -i 's/^Example/#Example/' /etc/freshclam.conf && \
      freshclam --datadir=/opt/clamav-db || \
        { echo "freshclam failed; the image would ship with no signatures" >&2; exit 1; }; \
      test -s /opt/clamav-db/daily.cvd || test -s /opt/clamav-db/daily.cld || \
        { echo "freshclam reported success but no daily signatures landed" >&2; exit 1; }; \
    fi

# The runtime stage stays on the full UBI rather than ubi-minimal: clamscan
# pulls in a long chain of shared libraries, and microdnf cannot install the
# EPEL release package from a URL.
FROM registry.access.redhat.com/ubi9/ubi:latest

RUN dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
    dnf install -y clamav && \
    dnf clean all && \
    rm -rf /var/cache/dnf

COPY --from=dbfetcher /opt/clamav-db /opt/clamav-db
COPY entrypoint.sh /usr/local/bin/cupel-scan
RUN chmod 0755 /usr/local/bin/cupel-scan && chmod -R a+rX /opt/clamav-db

ENV HOME=/tmp \
    TMPDIR=/tmp

USER 65532:65532

# OCI labels. The source label is what links a published package back to this
# repository on GitHub — without it the package is an orphan in the org's
# package list and cannot inherit the repository's visibility.
LABEL org.opencontainers.image.source="https://github.com/DAVANO-INNOVATION-LAB/cupel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Davano Innovation Lab" \
      org.opencontainers.image.title="cupel-scanner-clamav" \
      org.opencontainers.image.description="ClamAV with signature database baked in, for air-gapped model scanning"

ENTRYPOINT ["/usr/local/bin/cupel-scan"]
