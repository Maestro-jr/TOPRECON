"""
TOP RECON — configuration & secrets.

Reads API keys from a local ``.env`` (never committed) or the OS environment,
plus scan tunables. No secret is ever hardcoded. Missing keys are fine — the
owning module simply shows "Needs Key" and the engine skips it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

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


class Settings:
    def __init__(self) -> None:
        self.env_path = _PKG_ROOT / "config" / ".env"
        if _HAVE_DOTENV and self.env_path.exists():
            load_dotenv(self.env_path)
        # Scan tunables (overridable via env).
        self.max_depth   = int(os.environ.get("TOPRECON_MAX_DEPTH", 4))
        self.workers     = int(os.environ.get("TOPRECON_WORKERS", 24))
        self.rate_per_min = int(os.environ.get("TOPRECON_RATE_PER_MIN", 1250))
        self._overrides: dict[str, str] = {}   # keys set live via the config panel

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
