#!/usr/bin/env bash
set -uo pipefail

LOG_DIR="${LOG_DIR:-/var/log/security-scans}"
SUMMARY_LOG="${LOG_DIR}/scan-summary.log"
SEVERITY="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
INTERVAL="${SCAN_INTERVAL_SECONDS:-86400}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/trivy-cache}"
EXTRA_ARGS="${TRIVY_EXTRA_ARGS:-}"
SMTP_HOST="${SMTP_HOST:-}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_USER="${SMTP_USER:-}"
SMTP_PASS="${SMTP_PASS:-}"
SMTP_FROM="${SMTP_FROM:-scanner@localhost}"
SMTP_TO="${SMTP_TO:-}"
SMTP_TLS="${SMTP_TLS:-true}"
SMTP_STARTTLS="${SMTP_STARTTLS:-true}"
SMTP_SUBJECT_PREFIX="${SMTP_SUBJECT_PREFIX:-[Image Scanner]}"

mkdir -p "${LOG_DIR}" "${TRIVY_CACHE_DIR}"
export TRIVY_CACHE_DIR

from_secret_or_current() {
    local name="$1"
    local current="$2"
    local file="/run/secrets/${name}"
    if [[ -n "$current" ]]; then
        printf '%s' "$current"
        return
    fi
    if [[ -r "$file" ]]; then
        tr -d '\r\n' < "$file"
        return
    fi
    printf '%s' "$current"
}

SMTP_HOST="$(from_secret_or_current SMTP_HOST "$SMTP_HOST")"
SMTP_PORT="$(from_secret_or_current SMTP_PORT "$SMTP_PORT")"
SMTP_USER="$(from_secret_or_current SMTP_USER "$SMTP_USER")"
SMTP_PASS="$(from_secret_or_current SMTP_PASS "$SMTP_PASS")"
SMTP_FROM="$(from_secret_or_current SMTP_FROM "$SMTP_FROM")"
SMTP_TO="$(from_secret_or_current SMTP_TO "$SMTP_TO")"
SMTP_TLS="$(from_secret_or_current SMTP_TLS "$SMTP_TLS")"
SMTP_STARTTLS="$(from_secret_or_current SMTP_STARTTLS "$SMTP_STARTTLS")"
SMTP_SUBJECT_PREFIX="$(from_secret_or_current SMTP_SUBJECT_PREFIX "$SMTP_SUBJECT_PREFIX")"

timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

mode_once=0
for arg in "$@"; do
    case "$arg" in
        --once|-1) mode_once=1 ;;
    esac
done
if [[ "${SCAN_ONCE:-0}" == "1" || "${SCAN_ONCE:-false}" == "true" ]]; then
    mode_once=1
fi

smtp_config_file=""

to_bool() {
    local val
    val="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
    [[ "$val" == "1" || "$val" == "true" || "$val" == "yes" || "$val" == "on" ]]
}

smtp_configured() {
    [[ -n "${SMTP_TO}" && -n "${SMTP_HOST}" ]]
}

ensure_smtp_config() {
    if [[ -n "${smtp_config_file}" ]]; then
        return 0
    fi
    if ! smtp_configured; then
        return 1
    fi
    if ! command -v msmtp >/dev/null 2>&1; then
        echo "[$(timestamp)] msmtp not installed; skipping email notifications" >&2
        return 1
    fi

    smtp_config_file="$(mktemp)"
    {
        echo "defaults"
        echo "logfile /var/log/security-scans/msmtp.log"
        echo "tls_trust_file /etc/ssl/certs/ca-certificates.crt"
        echo "account default"
        echo "host ${SMTP_HOST}"
        echo "port ${SMTP_PORT}"
        echo "from ${SMTP_FROM}"
        if [[ -n "${SMTP_USER}" ]]; then
            echo "user ${SMTP_USER}"
            echo "password ${SMTP_PASS}"
            echo "auth on"
        else
            echo "auth off"
        fi
        if to_bool "${SMTP_TLS}"; then
            echo "tls on"
        else
            echo "tls off"
        fi
        if to_bool "${SMTP_STARTTLS}"; then
            echo "tls_starttls on"
        else
            echo "tls_starttls off"
        fi
    } > "${smtp_config_file}"
    chmod 600 "${smtp_config_file}"
}

send_email() {
    local subject="$1"
    local body="$2"
    ensure_smtp_config || return

    printf "Subject: %s\nFrom: %s\nTo: %s\n\n%s\n" \
        "${SMTP_SUBJECT_PREFIX} ${subject}" "${SMTP_FROM}" "${SMTP_TO}" "${body}" \
        | msmtp --file="${smtp_config_file}" --account=default "${SMTP_TO}" \
        || echo "[$(timestamp)] Failed to send email notification" >&2
}

if ! command -v docker >/dev/null 2>&1; then
    echo "[$(timestamp)] docker CLI not found in container; install docker-cli." >&2
    exit 1
fi
if ! command -v trivy >/dev/null 2>&1; then
    echo "[$(timestamp)] trivy not found in container; ensure build completed." >&2
    exit 1
fi

list_images() {
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep -v '<none>' \
        | sort -u
}

scan_image() {
    local image="$1"
    local safe_name
    safe_name="$(echo "${image}" | tr '/:' '__')"
    local stamp
    stamp="$(timestamp | tr ':' '-')"
    local log_file="${LOG_DIR}/scan-${stamp}--${safe_name}.log"

    echo "[$(timestamp)] Scanning ${image} (severity ${SEVERITY})"
    trivy image --quiet --severity "${SEVERITY}" --exit-code 1 \
        ${EXTRA_ARGS:+${EXTRA_ARGS}} "${image}" 2>&1 | tee "${log_file}"
    local status=${PIPESTATUS[0]}

    if [[ ${status} -eq 0 ]]; then
        echo "[$(timestamp)] No vulnerabilities found in ${image}" | tee -a "${SUMMARY_LOG}"
    elif [[ ${status} -eq 1 ]]; then
        echo "[$(timestamp)] Vulnerabilities found in ${image}; details: ${log_file}" | tee -a "${SUMMARY_LOG}"
        send_email "Vulnerabilities found in ${image}" \
"A scan detected vulnerabilities in ${image} at $(timestamp).
Severity filter: ${SEVERITY}
Log file (host-mounted): ${log_file}"
    else
        echo "[$(timestamp)] Scan error for ${image} (exit ${status}); see ${log_file}" | tee -a "${SUMMARY_LOG}" >&2
        send_email "Scan error for ${image}" \
"The scanner encountered an error (exit ${status}) while scanning ${image} at $(timestamp).
See log file: ${log_file}"
    fi
}

scan_all() {
    mapfile -t images < <(list_images)
    if [[ ${#images[@]} -eq 0 ]]; then
        echo "[$(timestamp)] No local images to scan" | tee -a "${SUMMARY_LOG}"
        return
    fi

    for image in "${images[@]}"; do
        scan_image "${image}"
    done
}

while true; do
    scan_all
    if [[ ${mode_once} -eq 1 ]]; then
        break
    fi
    sleep "${INTERVAL}"
done
