FROM alpine:3.19

ARG TRIVY_VERSION=0.57.1

RUN set -euo pipefail \
    && apk add --no-cache bash curl docker-cli ca-certificates msmtp python3 \
    && ver="v${TRIVY_VERSION#v}" \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "${ver}" \
    && mkdir -p /trivy-cache /var/log/security-scans

ENV TRIVY_CACHE_DIR=/trivy-cache \
    PYTHONUNBUFFERED=1

COPY scan.py /usr/local/bin/scan.py

ENTRYPOINT ["python3", "/usr/local/bin/scan.py"]
