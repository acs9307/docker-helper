#!/usr/bin/env bash
set -uo pipefail

LOG_DIR="${LOG_DIR:-/var/log/security-scans}"
SUMMARY_LOG="${LOG_DIR}/scan-summary.log"
SEVERITY="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
INTERVAL="${SCAN_INTERVAL_SECONDS:-86400}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/trivy-cache}"
EXTRA_ARGS="${TRIVY_EXTRA_ARGS:-}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/snapshots}"
SNAPSHOT_WRITE="${SNAPSHOT_WRITE:-0}"
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
mkdir -p "${SNAPSHOT_DIR}"
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
        --save-snapshot) SNAPSHOT_WRITE=1 ;;
        --snapshot-dir=*) SNAPSHOT_DIR="${arg#*=}" ;;
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

should_write_snapshot() {
    to_bool "${SNAPSHOT_WRITE:-0}"
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

write_snapshot() {
    local image="$1"
    local safe_name="$2"
    local ids_file="$3"
    local baseline_file="${SNAPSHOT_DIR}/${safe_name}.json"

    local ids_json="[]"
    if [[ -s "$ids_file" ]]; then
        ids_json=$(jq -R . < "$ids_file" | jq -s .)
    fi

    jq -n \
        --arg image "$image" \
        --arg timestamp "$(timestamp)" \
        --argjson vulnerabilities "${ids_json}" \
        '{image:$image, timestamp:$timestamp, vulnerabilities:$vulnerabilities}' > "${baseline_file}"
}

load_baseline_ids() {
    local safe_name="$1"
    local baseline_file="${SNAPSHOT_DIR}/${safe_name}.json"
    local target_file="$2"
    if [[ -r "${baseline_file}" ]]; then
        jq -r '.vulnerabilities[]?' "${baseline_file}" | sort -u > "${target_file}"
    else
        : > "${target_file}"
    fi
}

summarize_counts() {
    local json_file="$1"
    jq -r '
      (.Results // []) | map(.Vulnerabilities // []) | flatten as $v
      | if ($v|length)==0 then "None"
        else ($v | map(.Severity) | group_by(.) | map("\(.[0]): \(length)") | join(", "))
        end
    ' "${json_file}" || echo "Unknown (parse error)"
}

severity_counts() {
    local json_file="$1"
    jq -r '
      (.Results // []) | map(.Vulnerabilities // []) | flatten as $v
      | reduce ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"][] as $sev
          ({}; .[$sev] = ($v | map(select(.Severity==$sev)) | length))
    ' "${json_file}" 2>/dev/null
}

scan_image() {
    local image="$1"
    local safe_name
    safe_name="$(echo "${image}" | tr '/:' '__')"
    local stamp
    stamp="$(timestamp | tr ':' '-')"
    local log_file="${LOG_DIR}/scan-${stamp}--${safe_name}.log"
    local json_file="${LOG_DIR}/scan-${stamp}--${safe_name}.json"

    echo "[$(timestamp)] Scanning ${image} (severity ${SEVERITY})"
    trivy image --quiet --severity "${SEVERITY}" --exit-code 1 --format json --output "${json_file}" \
        ${EXTRA_ARGS:+${EXTRA_ARGS}} "${image}"
    local status=$?

    if [[ ${status} -gt 1 || ! -s "${json_file}" ]]; then
        echo "[$(timestamp)] Scan error for ${image} (exit ${status}); no JSON produced" | tee -a "${SUMMARY_LOG}" >&2
        send_email "Scan error for ${image}" \
"The scanner encountered an error (exit ${status}) while scanning ${image} at $(timestamp).
JSON/log may be incomplete: ${json_file}"
        return
    fi

    # Extract vulnerability IDs
    local new_ids_file
    new_ids_file=$(mktemp)
    local jq_ids='(.Results // []) | map(.Vulnerabilities // []) | flatten | .[]? | .VulnerabilityID'
    if ! jq -r "${jq_ids}" "${json_file}" | sort -u > "${new_ids_file}"; then
        echo "[$(timestamp)] Failed to parse vulnerabilities for ${image}" | tee -a "${SUMMARY_LOG}" >&2
        send_email "Scan parse error for ${image}" \
"The scanner could not parse vulnerabilities from ${json_file} at $(timestamp)."
        rm -f "${new_ids_file}"
        return
    fi

    local baseline_ids_file
    baseline_ids_file=$(mktemp)
    load_baseline_ids "${safe_name}" "${baseline_ids_file}"

    mapfile -t new_ids < "${new_ids_file}"
    mapfile -t baseline_ids < "${baseline_ids_file}"

    mapfile -t new_only < <(comm -13 "${baseline_ids_file}" "${new_ids_file}")
    mapfile -t resolved < <(comm -23 "${baseline_ids_file}" "${new_ids_file}")
    local new_count=${#new_only[@]}
    local resolved_count=${#resolved[@]}

    local has_baseline=0
    if [[ -s "${baseline_ids_file}" || -f "${SNAPSHOT_DIR}/${safe_name}.json" ]]; then
        has_baseline=1
    fi

    local vuln_count=${#new_ids[@]}
    local changed=0
    if [[ ${has_baseline} -eq 0 ]]; then
        changed=$((vuln_count > 0 ? 1 : 0))
    elif [[ ${#new_only[@]} -gt 0 || ${#resolved[@]} -gt 0 ]]; then
        changed=1
    fi

    local counts
    counts=$(summarize_counts "${json_file}")

    local sev_counts_json
    sev_counts_json=$(severity_counts "${json_file}")
    local sev_counts_pretty=""
    if [[ -n "${sev_counts_json}" ]]; then
        sev_counts_pretty=$(echo "${sev_counts_json}" | jq -r 'to_entries | map("\(.key): \(.value)") | join(", ")')
    fi

    {
        echo "Scan time: $(timestamp)"
        echo "Image: ${image}"
        echo "Severity filter: ${SEVERITY}"
        echo "Counts: ${counts}"
        if [[ -n "${sev_counts_pretty}" ]]; then
            echo "Counts by severity: ${sev_counts_pretty}"
        fi
        if [[ ${has_baseline} -eq 1 ]]; then
            echo "Baseline: ${SNAPSHOT_DIR}/${safe_name}.json"
        else
            echo "Baseline: none"
        fi
        if [[ ${#new_only[@]} -gt 0 ]]; then
            echo "New since baseline: ${#new_only[@]}"
            printf '  %s\n' "${new_only[@]}"
        fi
        if [[ ${#resolved[@]} -gt 0 ]]; then
            echo "Resolved since baseline: ${#resolved[@]}"
            printf '  %s\n' "${resolved[@]}"
        fi
        echo "JSON report: ${json_file}"
        echo "Vulnerabilities:"
        jq -r '(.Results // []) | map(.Vulnerabilities // []) | flatten | .[]? | "\(.VulnerabilityID) \(.PkgName) \(.InstalledVersion) \(.Severity)"' "${json_file}" \
            | sed 's/^/  /' || echo "  (none)"
    } > "${log_file}"

    if [[ ${status} -eq 0 ]]; then
        if [[ ${changed} -eq 1 && ${has_baseline} -eq 1 ]]; then
            echo "[$(timestamp)] No new vulnerabilities; resolved ${resolved_count} for ${image}; counts: ${counts}${sev_counts_pretty:+ | ${sev_counts_pretty}}; details: ${log_file}" | tee -a "${SUMMARY_LOG}"
            send_email "Vulnerabilities resolved for ${image}" \
"Scan time: $(timestamp)
Image: ${image}
Counts: ${counts}
Counts by severity: ${sev_counts_pretty:-n/a}
New since baseline: ${new_count}
Resolved since baseline: ${#resolved[@]}
Report (host-mounted): ${log_file}
JSON: ${json_file}"
        else
            echo "[$(timestamp)] No new vulnerabilities found for ${image}; counts: ${counts}${sev_counts_pretty:+ | ${sev_counts_pretty}}" | tee -a "${SUMMARY_LOG}"
        fi
    elif [[ ${status} -eq 1 ]]; then
        if [[ ${changed} -eq 1 ]]; then
            if [[ ${new_count} -gt 0 ]]; then
                echo "[$(timestamp)] New vulnerabilities: ${new_count} for ${image}; counts: ${counts}${sev_counts_pretty:+ | ${sev_counts_pretty}}; details: ${log_file}" | tee -a "${SUMMARY_LOG}"
            else
                echo "[$(timestamp)] No new vulnerabilities; resolved ${resolved_count} for ${image}; counts: ${counts}${sev_counts_pretty:+ | ${sev_counts_pretty}}; details: ${log_file}" | tee -a "${SUMMARY_LOG}"
            fi
            send_email "Vulnerabilities changed for ${image}" \
"Scan time: $(timestamp)
Image: ${image}
Counts: ${counts}
Counts by severity: ${sev_counts_pretty:-n/a}
New since baseline: ${new_count}
Resolved since baseline: ${resolved_count}
Report (host-mounted): ${log_file}
JSON: ${json_file}"
        else
            echo "[$(timestamp)] No new vulnerabilities (baseline match) for ${image}; counts: ${counts}${sev_counts_pretty:+ | ${sev_counts_pretty}}; no alert" | tee -a "${SUMMARY_LOG}"
        fi
    else
        echo "[$(timestamp)] Scan error for ${image} (exit ${status}); see ${log_file}" | tee -a "${SUMMARY_LOG}" >&2
        send_email "Scan error for ${image}" \
"The scanner encountered an error (exit ${status}) while scanning ${image} at $(timestamp).
See log file: ${log_file}"
    fi

    if should_write_snapshot; then
        write_snapshot "${image}" "${safe_name}" "${new_ids_file}"
    fi

    rm -f "${new_ids_file}" "${baseline_ids_file}"
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
