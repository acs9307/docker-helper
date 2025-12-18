# Image Vulnerability Scanner

Containerized scanner (Python entrypoint) that audits all host Docker images for vulnerabilities using Trivy. It mounts the Docker socket to enumerate images, writes per-image reports to `security/logs/`, and appends run summaries to `security/logs/scan-summary.log`.

## Prerequisites
- Host Docker daemon available and accessible via `/var/run/docker.sock`.
- Network access on first run so Trivy can download/update its vulnerability database.

## Build
```sh
docker compose -f security/docker-compose.yaml build
# To pin/override Trivy version (defaults to 0.57.1 in Dockerfile; accepts 0.57.1 or v0.57.1):
# docker compose -f security/docker-compose.yaml build --build-arg TRIVY_VERSION=0.57.1
```

## Run (periodic)
Starts a background scanner that runs every 24 hours by default.
```sh
docker compose -f security/docker-compose.yaml up -d
```

## Run (one-shot)
Execute a single pass and exit.
```sh
docker compose -f security/docker-compose.yaml run --rm image-scanner --once
```

## Run via helper script
Use the Python wrapper to build and start with custom options.
```sh
python3 security/run.py            # build + start recurring service (default 24h)
python3 security/run.py --once     # one-shot and exit
python3 security/run.py --interval 3600 --severity HIGH,CRITICAL --extra-trivy-args "--ignore-unfixed"
python3 security/run.py --smtp-host smtp.example.com --smtp-user scanner --smtp-pass 'secret' --smtp-from scanner@example.com --smtp-to admin@example.com
python3 security/run.py --save-snapshot  # write/update snapshot baseline after scan
python3 security/run.py --once --image alpine:3.20  # scan only a specific image (repeat flag to add more)
```

### Whitelisting workflow
1. Run a scan and review logs in `security/logs/`.
2. If the current vulnerabilities are acceptable, capture them as the baseline: `python3 security/run.py --once --save-snapshot`.
3. Subsequent runs will only email when the vulnerability set changes relative to the snapshot (new findings or resolved items). Update the baseline again with `--save-snapshot` when you intentionally accept a new state.

## Configuration
- `SCAN_INTERVAL_SECONDS` (default `86400`): interval between scans in daemon mode (set via env or `run.py --interval`).
- `TRIVY_SEVERITY` (default `HIGH,CRITICAL`): comma list passed to `trivy image --severity`.
- `SCAN_ONCE=1` can force one-shot even when started via `up`; `run.py --once` also works.
- `TRIVY_EXTRA_ARGS` allows extra flags (e.g., `--ignore-unfixed`, `--timeout 5m`); set via env or `run.py --extra-trivy-args`.
- Snapshots/whitelisting: set `SNAPSHOT_WRITE=1` (or `run.py --save-snapshot`) to write/update baselines in `security/snapshots/`. Alerts are only emailed when vulnerability sets change vs. the snapshot; unchanged findings are suppressed. `SNAPSHOT_DIR` controls location (default `/snapshots`).
- Email alerts (optional): set `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USER`/`SMTP_PASS` (omit for unauthenticated), `SMTP_FROM` (default `scanner@localhost`), `SMTP_TO` (recipient), `SMTP_TLS`/`SMTP_STARTTLS` (`true`/`false`), and `SMTP_SUBJECT_PREFIX`. All can be passed via `run.py` flags.
- Limiting scope: set `SCAN_IMAGES` in `.env` (comma-separated) or use `run.py --image <name>` (repeatable) to scan only specific images.
- `.env` support: copy `security/.env.example` to `security/.env` and populate values. Run from the `security/` directory or pass `--env-file security/.env` when invoking `docker compose`; `run.py` automatically uses `security/.env` if it exists. Values set via CLI flags override `.env`.
- Secrets directory: place files named `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_TO`, `SMTP_TLS`, or `SMTP_STARTTLS` into `security/secrets/` (contents are the raw value). The container reads these from `/run/secrets/<NAME>`; password is typically kept here. The directory is volume-mounted read-only.
- Ignore list: put images to skip (one per line, comments allowed) in `security/ignore-images.txt` (or copy `ignore-images.example`). Mounted at `/ignore-images.txt` by compose. Alternatively set `IGNORE_FILE` to another path or fallback to `IGNORE_IMAGES` (comma-separated) if no file is provided.

## Outputs
- Per-image report logs: `security/logs/scan-<timestamp>--<image>.log`
- Summary of findings/errors: `security/logs/scan-summary.log`
- Trivy cache persisted in `security/cache/` to speed subsequent runs.
- Snapshots/baselines: `security/snapshots/<image>.json` contains the whitelisted vulnerability IDs for change detection.
