"""
TOP RECON — configuration & secrets.

Reads API keys from a local ``config/.env`` (never committed) or the OS
environment, plus scan tunables. No secret is ever hardcoded. Missing keys are
fine — the owning module simply shows "Needs Key" and the engine skips it.

Keys can be entered two ways, both landing in the same place:
  * edit ``config/.env`` directly (copy ``config/.env.example``), or
  * use the in-app **API Keys** dialog, which persists to ``config/.env`` via
    :meth:`Settings.persist_keys` and applies them to the running session.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    _HAVE_DOTENV = True
except Exception:  # noqa: BLE001
    _HAVE_DOTENV = False


# App data lives beside the package by default; override with TOPRECON_DATA_DIR.
_PKG_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    d = Path(os.environ.get("TOPRECON_DATA_DIR", _PKG_ROOT / "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sub(name: str) -> Path:
    d = data_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


# Canonical env var names for each key-gated source.
KEY_ENV = {
    "shodan":     "SHODAN_API_KEY",
    "censys_id":  "CENSYS_API_ID",
    "censys_secret": "CENSYS_API_SECRET",
    "zoomeye":    "ZOOMEYE_API_KEY",
    "hunter":     "HUNTER_API_KEY",
    "hibp":       "HIBP_API_KEY",
    "dehashed":   "DEHASHED_API_KEY",
    "leakix":     "LEAKIX_API_KEY",
    "builtwith":  "BUILTWITH_API_KEY",
    "urlscan":    "URLSCAN_API_KEY",
    "checkphish": "CHECKPHISH_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "abuseipdb":  "ABUSEIPDB_API_KEY",
    "otx":        "OTX_API_KEY",
    "github":     "GITHUB_TOKEN",
    "google_cse": "GOOGLE_CSE_KEY",
    "google_cx":  "GOOGLE_CSE_CX",
}


def _write_env(env_path: Path, updates: dict[str, str]) -> None:
    """Merge ``{ENV_VAR: value}`` into *env_path*, preserving other lines."""
    env_path.parent.mkdir(parents=True, exist_ok=True)
    existing = (env_path.read_text(encoding="utf-8").splitlines()
                if env_path.exists() else [])
    seen: set[str] = set()
    out: list[str] = []
    for line in existing:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name = stripped.split("=", 1)[0].strip()
            if name in updates:
                out.append(f"{name}={updates[name]}")
                seen.add(name)
                continue
        out.append(line)
    new = [n for n in updates if n not in seen]
    if new:
        if not existing:
            out.append("# TOP RECON — API keys (written by the API Keys dialog).")
        if out and out[-1].strip():
            out.append("")
        out.extend(f"{name}={updates[name]}" for name in new)
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")


class Settings:
    def __init__(self) -> None:
        self.env_path = _PKG_ROOT / "config" / ".env"
        if _HAVE_DOTENV and self.env_path.exists():
            load_dotenv(self.env_path)
        # Scan tunables (overridable via env).
        self.max_depth   = int(os.environ.get("TOPRECON_MAX_DEPTH", 4))
        self.workers     = int(os.environ.get("TOPRECON_WORKERS", 24))
        self.rate_per_min = int(os.environ.get("TOPRECON_RATE_PER_MIN", 1250))
        # Keys entered in the current session via the API Keys dialog; take
        # precedence over the environment and are also written back to .env.
        self._overrides: dict[str, str] = {}

    # -- API keys ------------------------------------------------------------
    def get_key(self, key: str) -> str:
        """Return the API key/secret for a source id, or "" if unset."""
        if key in self._overrides:
            return self._overrides[key]
        env_name = KEY_ENV.get(key, key.upper())
        return os.environ.get(env_name, "") or ""

    def set_key(self, key: str, value: str) -> None:
        self._overrides[key] = value.strip()

    def has_key(self, key: str) -> bool:
        return bool(self.get_key(key))

    def persist_keys(self, values: dict[str, str]) -> None:
        """Apply keys to this session AND write them to ``config/.env``.

        ``values`` maps source ids (the keys of :data:`KEY_ENV`) to secrets.
        Empty values clear the override but are still written so the operator
        can see the slot. The file is created from scratch if absent.
        """
        env_updates: dict[str, str] = {}
        for kid, val in values.items():
            self.set_key(kid, val)
            env_updates[KEY_ENV.get(kid, kid.upper())] = (val or "").strip()
        _write_env(self.env_path, env_updates)

    def get(self, name: str, default: Any = None) -> Any:
        return getattr(self, name, default)

    # -- paths ---------------------------------------------------------------
    @property
    def profiles_dir(self) -> Path:
        return _sub("profiles")

    @property
    def audit_dir(self) -> Path:
        return _sub("audit")

    @property
    def reports_dir(self) -> Path:
        return _sub("reports")

    @property
    def wordlist_path(self) -> Path:
        return _PKG_ROOT / "config" / "wordlists" / "subdomains-common.txt"
