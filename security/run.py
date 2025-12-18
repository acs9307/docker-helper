#!/usr/bin/env python3
"""Helper launcher for the image scanner container."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the image vulnerability scanner container (one-shot or recurring)."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit (default: run as recurring service).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        help="Seconds between scans when running recurring service (default: 86400; can also be set in .env).",
    )
    parser.add_argument(
        "--severity",
        help="Comma-separated severities to scan for (passed to Trivy; default HIGH,CRITICAL).",
    )
    parser.add_argument(
        "--extra-trivy-args",
        help="Additional flags forwarded to Trivy (e.g., \"--ignore-unfixed --timeout 5m\").",
    )
    parser.add_argument("--smtp-host", help="SMTP host for email alerts.")
    parser.add_argument("--smtp-port", type=int, help="SMTP port (default 587).")
    parser.add_argument("--smtp-user", help="SMTP username (omit for unauthenticated).")
    parser.add_argument("--smtp-pass", help="SMTP password (omit to use SMTP_PASS env or unauthenticated).")
    parser.add_argument("--smtp-from", help="From address for alerts (default scanner@localhost).")
    parser.add_argument("--smtp-to", help="Recipient address for alerts.")
    parser.add_argument(
        "--smtp-tls",
        choices=["true", "false"],
        help="Enable TLS (default true).",
    )
    parser.add_argument(
        "--smtp-starttls",
        choices=["true", "false"],
        help="Enable STARTTLS (default true).",
    )
    parser.add_argument(
        "--smtp-subject-prefix",
        help="Prefix for alert email subjects (default \"[Image Scanner]\").",
    )
    parser.add_argument(
        "--snapshot-dir",
        help="Directory to store vulnerability snapshots (default /snapshots inside container; host-mounted via ./snapshots).",
    )
    parser.add_argument(
        "--save-snapshot",
        action="store_true",
        help="After each scan, write/update the snapshot baseline (whitelist current state).",
    )
    parser.add_argument(
        "--image",
        action="append",
        dest="images",
        help="Scan only this image (can be repeated). If omitted, all images are scanned.",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip docker compose build (default is to build before running).",
    )
    parser.add_argument(
        "--env-file",
        help="Path to .env file to pass to docker compose (default: security/.env if present).",
    )
    parser.add_argument(
        "--docker-bin",
        default="docker",
        help="Docker CLI to use (default: docker).",
    )
    return parser.parse_args()


def ensure_dirs() -> None:
    for dirname in ("logs", "cache", "snapshots"):
        (HERE / dirname).mkdir(parents=True, exist_ok=True)


def require_docker_compose(docker_bin: str) -> None:
    try:
        subprocess.run(
            [docker_bin, "compose", "version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise SystemExit("docker CLI not found; install Docker Desktop/Engine.") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit("`docker compose` is unavailable; ensure Docker Compose plugin is installed.") from exc


def run_command(cmd: list[str], env: dict[str, str]) -> None:
    print(f"[scanner-runner] {' '.join(cmd)}")
    subprocess.run(cmd, check=True, cwd=HERE, env=env)


def main() -> int:
    args = parse_args()
    ensure_dirs()
    require_docker_compose(args.docker_bin)

    compose_file = str(HERE / "docker-compose.yaml")
    base_cmd = [args.docker_bin, "compose", "-f", compose_file]
    env_file = args.env_file
    if env_file is None:
        default_env = HERE / ".env"
        if default_env.exists():
            env_file = str(default_env)
    if env_file:
        base_cmd.extend(["--env-file", env_file])

    env = os.environ.copy()
    if args.interval is not None:
        env["SCAN_INTERVAL_SECONDS"] = str(args.interval)
    if args.severity:
        env["TRIVY_SEVERITY"] = args.severity
    if args.extra_trivy_args is not None:
        env["TRIVY_EXTRA_ARGS"] = args.extra_trivy_args
    if args.snapshot_dir:
        env["SNAPSHOT_DIR"] = args.snapshot_dir
    if args.save_snapshot:
        env["SNAPSHOT_WRITE"] = "1"
    if args.smtp_host:
        env["SMTP_HOST"] = args.smtp_host
    if args.smtp_port is not None:
        env["SMTP_PORT"] = str(args.smtp_port)
    if args.smtp_user:
        env["SMTP_USER"] = args.smtp_user
    if args.smtp_pass:
        env["SMTP_PASS"] = args.smtp_pass
    if args.smtp_from:
        env["SMTP_FROM"] = args.smtp_from
    if args.smtp_to:
        env["SMTP_TO"] = args.smtp_to
    if args.smtp_tls:
        env["SMTP_TLS"] = args.smtp_tls
    if args.smtp_starttls:
        env["SMTP_STARTTLS"] = args.smtp_starttls
    if args.smtp_subject_prefix:
        env["SMTP_SUBJECT_PREFIX"] = args.smtp_subject_prefix
    if args.images:
        env["SCAN_IMAGES"] = ",".join(args.images)

    if not args.no_build:
        run_command(base_cmd + ["build"], env)

    if args.once:
        cmd = base_cmd + ["run", "--rm", "image-scanner", "--once"]
    else:
        cmd = base_cmd + ["up", "-d"]

    run_command(cmd, env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
