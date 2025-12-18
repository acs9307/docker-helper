#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${DIR}/secrets"

mkdir -p "${SECRETS_DIR}"

touch "${SECRETS_DIR}/SMTP_PASS"

echo "Created empty SMTP_PASS secret in ${SECRETS_DIR}"
