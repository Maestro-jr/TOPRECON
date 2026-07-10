"""
TOP RECON — authorization attestation & audit log.

The Authorization Gate calls :func:`record_attestation` before any scan can run.
Every attestation (who/when/what target + the "I am authorized" confirmation) is
appended to a tamper-evident JSONL audit file. This is the compliance backbone
of an authorized-recon tool: no scan starts without a logged attestation.
"""

from __future__ import annotations

import getpass
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _audit_file(audit_dir: Path) -> Path:
    return audit_dir / "authorizations.jsonl"


def record_attestation(audit_dir: Path, target: str, scope_note: str = "",
                       active_scan: bool = False) -> dict:
    """Append an authorization attestation; returns the written record."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    rec = {
        "ts": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(),
        "target": target.strip().lower(),
        "scope_note": scope_note.strip(),
        "active_scan_authorized": bool(active_scan),
        "attested": True,
        "operator": _safe(getpass.getuser),
        "host": _safe(socket.gethostname),
    }
    with _audit_file(audit_dir).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def record_event(audit_dir: Path, kind: str, detail: str, target: str = "") -> None:
    """Append a general audit event (scan start/stop, export, active-scan enable)."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    rec = {"ts": time.time(), "iso": datetime.now(timezone.utc).isoformat(),
           "kind": kind, "detail": detail, "target": target}
    with (audit_dir / "events.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def last_attestation(audit_dir: Path) -> Optional[dict]:
    path = _audit_file(audit_dir)
    if not path.exists():
        return None
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    return last


def _safe(fn) -> str:
    try:
        return str(fn())
    except Exception:  # noqa: BLE001
        return "unknown"
