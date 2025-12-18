#!/usr/bin/env python3
"""Image vulnerability scanner with snapshot/whitelist and email notifications."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def read_setting(name: str, default: str = "") -> str:
    val = os.environ.get(name, default)
    if val:
        return val
    secret_path = Path("/run/secrets") / name
    if secret_path.exists():
        return secret_path.read_text().strip()
    return default


def to_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    def __init__(self) -> None:
        self.log_dir = Path(read_setting("LOG_DIR", "/var/log/security-scans"))
        self.summary_log = self.log_dir / "scan-summary.log"
        self.severity = read_setting("TRIVY_SEVERITY", "HIGH,CRITICAL")
        self.interval = float(read_setting("SCAN_INTERVAL_SECONDS", "86400"))
        self.trivy_cache = Path(read_setting("TRIVY_CACHE_DIR", "/trivy-cache"))
        self.extra_args = read_setting("TRIVY_EXTRA_ARGS", "")
        self.snapshot_dir = Path(read_setting("SNAPSHOT_DIR", "/snapshots"))
        self.snapshot_write = to_bool(read_setting("SNAPSHOT_WRITE", "0"))
        self.ignore_file = Path(read_setting("IGNORE_FILE", "/ignore-images.txt"))
        self.ignore_images_env = [i.strip() for i in read_setting("IGNORE_IMAGES", "").split(",") if i.strip()]
        # SMTP
        self.smtp_host = read_setting("SMTP_HOST", "")
        self.smtp_port = read_setting("SMTP_PORT", "587")
        self.smtp_user = read_setting("SMTP_USER", "")
        self.smtp_pass = read_setting("SMTP_PASS", "")
        self.smtp_from = read_setting("SMTP_FROM", "scanner@localhost")
        self.smtp_to = read_setting("SMTP_TO", "")
        self.smtp_tls = to_bool(read_setting("SMTP_TLS", "true"), True)
        self.smtp_starttls = to_bool(read_setting("SMTP_STARTTLS", "true"), True)
        self.smtp_subject_prefix = read_setting("SMTP_SUBJECT_PREFIX", "[Image Scanner]")

    def ensure_dirs(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.trivy_cache.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)


def require_cmd(cmd: str) -> None:
    if shutil.which(cmd) is None:
        print(f"[{utc_timestamp()}] Required command '{cmd}' not found in container.", file=sys.stderr)
        sys.exit(1)


def list_images() -> List[str]:
    try:
        out = subprocess.check_output(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[{utc_timestamp()}] Failed to list images: {exc}", file=sys.stderr)
        return []
    images = []
    for line in out.splitlines():
        if "<none>" in line:
            continue
        line = line.strip()
        if line:
            images.append(line)
    return sorted(set(images))


def load_ignore_list(cfg: Config) -> List[str]:
    items: List[str] = []
    if cfg.ignore_file and cfg.ignore_file.exists():
        for line in cfg.ignore_file.read_text().splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry:
                items.append(entry)
    elif cfg.ignore_images_env:
        items.extend(cfg.ignore_images_env)
    return items


def safe_name(image: str) -> str:
    return image.replace("/", "__").replace(":", "__")


def run_trivy(image: str, cfg: Config, json_path: Path) -> int:
    cmd = [
        "trivy",
        "image",
        "--quiet",
        "--severity",
        cfg.severity,
        "--exit-code",
        "1",
        "--format",
        "json",
        "--output",
        str(json_path),
    ]
    if cfg.extra_args:
        cmd.extend(shlex.split(cfg.extra_args))
    cmd.append(image)
    return subprocess.call(cmd)


def extract_vulnerabilities(json_path: Path) -> Tuple[List[Dict], Dict[str, int]]:
    try:
        data = json.loads(json_path.read_text())
    except Exception:
        return [], {}

    vulns: List[Dict] = []
    sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            vulns.append(vuln)
            sev = vuln.get("Severity", "UNKNOWN").upper()
            if sev not in sev_counts:
                sev_counts[sev] = 0
            sev_counts[sev] += 1
    return vulns, sev_counts


def load_baseline(path: Path) -> List[str]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return sorted(set(data.get("vulnerabilities") or []))
    except Exception:
        return []


def write_snapshot(image: str, path: Path, vuln_ids: List[str]) -> None:
    payload = {
        "image": image,
        "timestamp": utc_timestamp(),
        "vulnerabilities": sorted(set(vuln_ids)),
    }
    path.write_text(json.dumps(payload, indent=2))


def format_counts(sev_counts: Dict[str, int]) -> str:
    entries = [f"{k}: {v}" for k, v in sev_counts.items()]
    return ", ".join(entries) if entries else "None"


def ensure_msmtp_config(cfg: Config) -> Optional[Path]:
    if not cfg.smtp_host or not cfg.smtp_to:
        return None
    if shutil.which("msmtp") is None:
        print(f"[{utc_timestamp()}] msmtp not installed; skipping email notifications", file=sys.stderr)
        return None
    content = [
        "defaults",
        "logfile /var/log/security-scans/msmtp.log",
        "tls_trust_file /etc/ssl/certs/ca-certificates.crt",
        "account default",
        f"host {cfg.smtp_host}",
        f"port {cfg.smtp_port}",
        f"from {cfg.smtp_from}",
    ]
    if cfg.smtp_user:
        content.append(f"user {cfg.smtp_user}")
        content.append(f"password {cfg.smtp_pass}")
        content.append("auth on")
    else:
        content.append("auth off")
    content.append(f"tls {'on' if cfg.smtp_tls else 'off'}")
    content.append(f"tls_starttls {'on' if cfg.smtp_starttls else 'off'}")

    tmp = Path(tempfile.mkstemp(prefix="msmtp.", text=True)[1])
    tmp.write_text("\n".join(content) + "\n")
    tmp.chmod(0o600)
    return tmp


def send_email(cfg: Config, msmtp_cfg: Optional[Path], subject: str, body: str) -> None:
    if not msmtp_cfg:
        return
    message = f"Subject: {cfg.smtp_subject_prefix} {subject}\nFrom: {cfg.smtp_from}\nTo: {cfg.smtp_to}\n\n{body}\n"
    try:
        proc = subprocess.Popen(
            ["msmtp", "--file", str(msmtp_cfg), "--account=default", cfg.smtp_to],
            stdin=subprocess.PIPE,
        )
        proc.communicate(input=message.encode())
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args)
    except subprocess.CalledProcessError:
        print(f"[{utc_timestamp()}] Failed to send email notification", file=sys.stderr)


def log_summary(cfg: Config, line: str) -> None:
    with cfg.summary_log.open("a") as fh:
        fh.write(line + "\n")
    print(line)


def process_image(image: str, cfg: Config, save_snapshot: bool) -> Dict:
    stamp = utc_timestamp()
    sname = safe_name(image)
    log_file = cfg.log_dir / f"scan-{stamp}--{sname}.log"
    json_file = cfg.log_dir / f"scan-{stamp}--{sname}.json"

    status = run_trivy(image, cfg, json_file)
    if status > 1 or not json_file.exists() or json_file.stat().st_size == 0:
        line = f"[{utc_timestamp()}] Scan error for {image} (exit {status}); see {json_file}"
        log_summary(cfg, line)
        return {
            "image": image,
            "status": status,
            "error": line,
            "log_file": log_file,
            "json_file": json_file,
            "new": 0,
            "resolved": 0,
            "changed": False,
            "counts_total": 0,
            "counts_pretty": "",
        }

    vulns, sev_counts = extract_vulnerabilities(json_file)
    vuln_ids = sorted({v.get("VulnerabilityID", "") for v in vulns if v.get("VulnerabilityID")})
    baseline_path = cfg.snapshot_dir / f"{sname}.json"
    baseline_ids = load_baseline(baseline_path)

    new_ids = sorted(set(vuln_ids) - set(baseline_ids))
    resolved_ids = sorted(set(baseline_ids) - set(vuln_ids))
    has_baseline = baseline_path.exists()
    changed = bool(new_ids or resolved_ids or (not has_baseline and vuln_ids))

    counts_total = len(vuln_ids)
    counts_pretty = format_counts(sev_counts)

    lines = [
        f"Scan time: {stamp}",
        f"Image: {image}",
        f"Severity filter: {cfg.severity}",
        f"Counts: {counts_total}",
        f"Counts by severity: {counts_pretty}",
        f"Baseline: {baseline_path if has_baseline else 'none'}",
    ]
    if new_ids:
        lines.append(f"New since baseline: {len(new_ids)}")
        lines.extend(f"  {vid}" for vid in new_ids)
    if resolved_ids:
        lines.append(f"Resolved since baseline: {len(resolved_ids)}")
        lines.extend(f"  {vid}" for vid in resolved_ids)
    lines.append(f"JSON report: {json_file}")
    lines.append("Vulnerabilities:")
    if vulns:
        for v in vulns:
            lines.append(
                f"  {v.get('VulnerabilityID','?')} {v.get('PkgName','?')} "
                f"{v.get('InstalledVersion','?')} {v.get('Severity','?')}"
            )
    else:
        lines.append("  (none)")

    log_file.write_text("\n".join(lines) + "\n")

    # Summary + email
    if status == 0:
        if changed and has_baseline and resolved_ids:
            log_summary(
                cfg,
                f"[{utc_timestamp()}] No new vulnerabilities; resolved {len(resolved_ids)} for {image}; counts: {counts_total} | {counts_pretty}; details: {log_file}",
            )
        else:
            log_summary(
                cfg,
                f"[{utc_timestamp()}] No new vulnerabilities found for {image}; counts: {counts_total} | {counts_pretty}",
            )
    elif status == 1:
        if changed:
            if new_ids:
                summary = f"New vulnerabilities: {len(new_ids)} for {image}"
            else:
                summary = f"No new vulnerabilities; resolved {len(resolved_ids)} for {image}"
            log_summary(cfg, f"[{utc_timestamp()}] {summary}; counts: {counts_total} | {counts_pretty}; details: {log_file}")
        else:
            log_summary(
                cfg,
                f"[{utc_timestamp()}] No new vulnerabilities (baseline match) for {image}; counts: {counts_total} | {counts_pretty}; no alert",
            )
    else:
        line = f"[{utc_timestamp()}] Scan error for {image} (exit {status}); see {log_file}"
        log_summary(cfg, line)

    if save_snapshot:
        write_snapshot(image, baseline_path, vuln_ids)

    return {
        "image": image,
        "status": status,
        "error": None,
        "log_file": log_file,
        "json_file": json_file,
        "new": len(new_ids),
        "resolved": len(resolved_ids),
        "changed": changed,
        "counts_total": counts_total,
        "counts_pretty": counts_pretty,
        "baseline": baseline_path if has_baseline else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan host Docker images for vulnerabilities.")
    parser.add_argument("--once", "-1", action="store_true", help="Run a single pass and exit.")
    parser.add_argument("--save-snapshot", action="store_true", help="Write/update baseline snapshots after scan.")
    parser.add_argument("--snapshot-dir", help="Override snapshot directory (defaults to $SNAPSHOT_DIR or /snapshots).")
    return parser.parse_args()


def main() -> int:
    cfg = Config()
    args = parse_args()
    cfg.ensure_dirs()

    if args.snapshot_dir:
        cfg.snapshot_dir = Path(args.snapshot_dir)
        cfg.snapshot_dir.mkdir(parents=True, exist_ok=True)
    save_snapshot = cfg.snapshot_write or args.save_snapshot

    msmtp_cfg = ensure_msmtp_config(cfg)

    while True:
        run_results: List[Dict] = []
        images = list_images()
        if not images:
            log_summary(cfg, f"[{utc_timestamp()}] No local images to scan")
        ignore_list = load_ignore_list(cfg)
        for image in images:
            if ignore_list and image in ignore_list:
                log_summary(cfg, f"[{utc_timestamp()}] Skipping ignored image {image}")
                continue
            run_results.append(process_image(image, cfg, save_snapshot))

        # Single email per scan cycle
        if msmtp_cfg and cfg.smtp_to:
            total_images = len(run_results)
            total_new = sum(r.get("new", 0) for r in run_results if r)
            total_resolved = sum(r.get("resolved", 0) for r in run_results if r)
            errors = [r for r in run_results if r and r.get("status", 0) > 1 or r.get("error")]
            changed = [r for r in run_results if r and r.get("changed")]

            subject = f"Scan report: {total_images} images; new={total_new}, resolved={total_resolved}, errors={len(errors)}"
            body_lines = [
                f"Scan completed at {utc_timestamp()}",
                f"Images scanned: {total_images}",
                f"New vulnerabilities: {total_new}",
                f"Resolved vulnerabilities: {total_resolved}",
                f"Images with changes: {len(changed)}",
                f"Errors: {len(errors)}",
                "",
            ]
            for r in run_results:
                if not r:
                    continue
                status = r.get("status", 0)
                line = f"- {r['image']}: "
                if status > 1:
                    line += f"ERROR (see {r['log_file']})"
                elif r.get("changed"):
                    if r.get("new", 0) > 0:
                        line += f"new {r['new']}"
                    if r.get("resolved", 0) > 0:
                        line += f"{'; ' if r.get('new') else ''}resolved {r['resolved']}"
                else:
                    line += "no new vulnerabilities"
                line += f" | counts: {r.get('counts_total', 0)} | {r.get('counts_pretty', '')}"
                body_lines.append(line)
            send_email(cfg, msmtp_cfg, subject, "\n".join(body_lines))
        if args.once:
            break
        time.sleep(cfg.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
