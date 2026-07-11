"""
Attack-surface risk analysis + MITRE ATT&CK reconnaissance mapping.

Pure logic over the entity graph — categorizes findings into risk buckets with
severity, and annotates each category with the ATT&CK reconnaissance technique
it maps to (for the educational/demo audience). No Qt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .entities import Entity, EntityType


# Category → (MITRE technique id, technique name).
MITRE_RECON = {
    "Exposed sensitive port":     ("T1595.001", "Active Scanning: Scanning IP Blocks"),
    "Known CVE on service":       ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "Subdomain-takeover candidate": ("T1584.001", "Compromise Infrastructure: Domains"),
    "Expired / weak certificate": ("T1596.003", "Search Open Technical DBs: Digital Certs"),
    "Leaked secret in code":      ("T1552.001", "Unsecured Credentials: Credentials in Files"),
    "Public cloud bucket":        ("T1580", "Cloud Infrastructure Discovery"),
    "Breach exposure":            ("T1589.001", "Gather Victim Identity: Credentials"),
    "Brand impersonation domain": ("T1583.001", "Acquire Infrastructure: Domains"),
    "Exposed admin / login":      ("T1594", "Search Victim-Owned Websites"),
    "Large subdomain surface":    ("T1590.001", "Gather Victim Network: Domain Properties"),
}

_ADMIN_HINTS = ("admin", "login", "portal", "vpn", "citrix", "jenkins", "gitlab",
                "phpmyadmin", "webmail", "owa", "rdp", "cpanel", "dashboard",
                "grafana", "kibana", "jira", "confluence", "staging", "dev", "test")


@dataclass
class Finding:
    category: str
    severity: str            # critical|high|medium|low|info
    entity_key: str
    entity_value: str
    detail: str
    mitre_id: str = ""
    mitre_name: str = ""


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def analyze(entities: Iterable[Entity]) -> list[Finding]:
    findings: list[Finding] = []
    ents = list(entities)

    def add(category: str, sev: str, e: Entity, detail: str) -> None:
        m = MITRE_RECON.get(category, ("", ""))
        findings.append(Finding(category, sev, e.key, e.value, detail, m[0], m[1]))

    subdomain_count = 0
    for e in ents:
        # Explicit per-entity risk set by transforms.
        if e.risk and e.etype == EntityType.PORT:
            add("Exposed sensitive port", e.risk, e, e.risk_reason)
        elif e.risk and e.etype == EntityType.SERVICE and e.data.get("cves"):
            add("Known CVE on service", "critical", e, e.risk_reason)
        elif e.etype == EntityType.DNS_RECORD and e.data.get("takeover_candidate"):
            add("Subdomain-takeover candidate", "high", e, e.risk_reason)
        elif e.risk and e.etype == EntityType.CERTIFICATE:
            add("Expired / weak certificate", e.risk or "medium", e, e.risk_reason)
        elif e.etype == EntityType.LEAKED_SECRET:
            add("Leaked secret in code", "critical", e,
                e.risk_reason or e.data.get("detail", "Secret detected in public code."))
        elif e.etype == EntityType.CLOUD_BUCKET and e.data.get("public"):
            add("Public cloud bucket", "high", e, "Publicly listable cloud bucket.")
        elif e.etype == EntityType.BREACH_RECORD:
            add("Breach exposure", "high", e,
                e.data.get("detail", "Org domain present in a known breach."))
        elif e.etype == EntityType.TYPOSQUAT and e.data.get("registered"):
            add("Brand impersonation domain", "medium", e,
                e.risk_reason or "Registered lookalike domain.")

        if e.etype in (EntityType.SUBDOMAIN, EntityType.URL):
            subdomain_count += 1 if e.etype == EntityType.SUBDOMAIN else 0
            low = e.value.lower()
            if any(h in low.split(".")[0] for h in _ADMIN_HINTS):
                add("Exposed admin / login", "medium", e,
                    f"Sensitive hostname pattern in {e.value}.")

    if subdomain_count >= 25:
        # A large external footprint is itself a surface-management risk.
        seed = next((e for e in ents if e.depth == 0), None)
        if seed:
            findings.append(Finding(
                "Large subdomain surface", "low", seed.key, seed.value,
                f"{subdomain_count} subdomains — broad external attack surface.",
                *MITRE_RECON["Large subdomain surface"]))

    findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 5), f.category))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out
