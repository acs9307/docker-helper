# Repository Guidelines

## Project Structure & Module Organization
- `host-scripts/`: Host-facing helpers. `dc-run` is a Python monitor around `docker compose up` (port/health polling, restart logic); `dc-run-interactive` starts an interactive shell in a compose service while exporting the host UID/GID.
- `docker-scripts/`: Container entry helpers; `setup-user.sh` creates the host-matched user/group inside the container before running your command.
- `example/`: Minimal compose stack showing how to mount `docker-scripts/setup-user.sh` and pass UID/GID/USER.
- `requirements.txt`: Python deps for `dc-run`; `install-helper-scripts.sh` symlinks host scripts into a bin dir for easy use.

## Setup, Build, and Development Commands
- Create a virtualenv and install deps for `dc-run`: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`.
- Install host helpers into `~/bin` (or another dir on PATH): `./install-helper-scripts.sh ~/bin`.
- Run a stack with monitoring: `python3 host-scripts/dc-run -C example --health / --restart-mode down-up` (extra args after options are forwarded to `docker compose up`).
- Drop into a service container: `host-scripts/dc-run-interactive example <service> [cmd]` (defaults to `bash`).
- Manual smoke run: `docker compose -f example/docker-compose.yaml up` to verify mounts and UID/GID wiring.

## Coding Style & Naming Conventions
- Python: prefer PEP 8, 4-space indent, f-strings, and typed signatures; keep logging through `_LOGGER` and avoid silent failures (log exceptions the monitor catches).
- Shell: target bash, favor `set -euo pipefail`, quote variables, and keep env var names uppercase (`UID`, `GID`, `USER`). Script names stay kebab-case.

## Testing Guidelines
- No automated suite yet; before sending a PR, run `python3 host-scripts/dc-run --help` to ensure CLI parses, `python3 -m compileall host-scripts` for syntax checks, and `shellcheck host-scripts/dc-run-interactive docker-scripts/setup-user.sh` if available.
- Smoke-test the sample compose: `python3 host-scripts/dc-run -C example --startup-wait 5` and confirm port detection/health logs behave as expected.

## Commit & Pull Request Guidelines
- Use concise, descriptive commit subjects similar to current history (e.g., “Update dc-run restart handling”); imperative voice is preferred.
- PRs should state intent, list key commands tested (e.g., sample `dc-run` invocations), and call out changes to defaults (restart thresholds, health paths). Link related issues when present.
