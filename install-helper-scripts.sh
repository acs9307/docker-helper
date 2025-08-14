#!/usr/bin/env bash
set -euo pipefail

# Install helper scripts by creating symlinks in the specified bin directory.
# Usage: ./install-helper-scripts.sh [BIN_DIR]
# If BIN_DIR is not provided, defaults to "$HOME/bin".

BIN_DIR="${1:-${HOME}/bin}"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/host-scripts"

mkdir -p "${BIN_DIR}"

for script in "${SCRIPTS_DIR}"/*; do
  [ -f "$script" ] || continue
  target="${BIN_DIR}/$(basename "$script")"
  ln -sf "$script" "$target"
  echo "Installed $(basename "$script") to $target"
done

echo "Helper scripts installed in ${BIN_DIR}"

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
  echo "Warning: ${BIN_DIR} is not in your PATH."
  shell_name="${SHELL:-sh}"
  shell_name="${shell_name##*/}"
  case "$shell_name" in
    bash) rc_file="${HOME}/.bashrc" ;;
    zsh)  rc_file="${HOME}/.zshrc" ;;
    *)    rc_file="${HOME}/.${shell_name}rc" ;;
  esac
  read -r -p "Would you like to add it to your PATH in ${rc_file}? [y/N] " response
  if [[ "$response" =~ ^[Yy]$ ]]; then
    touch "$rc_file"
    echo "export PATH=\"${BIN_DIR}:\$PATH\"" >> "$rc_file"
    echo "Added ${BIN_DIR} to PATH in ${rc_file}. Please reload your shell."
  else
    echo "Please add ${BIN_DIR} to your PATH manually."
  fi
fi
