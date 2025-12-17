FROM alpine:3.19

ARG TRIVY_VERSION=0.57.1

RUN apk add --no-cache bash curl docker-cli ca-certificates msmtp \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin -v "${TRIVY_VERSION}" \
    && mkdir -p /trivy-cache /var/log/security-scans

ENV TRIVY_CACHE_DIR=/trivy-cache

COPY scan.sh /usr/local/bin/scan.sh
RUN chmod +x /usr/local/bin/scan.sh

ENTRYPOINT ["/usr/local/bin/scan.sh"]
