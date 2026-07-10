"""
TOP RECON — Entity model.

Every finding in TOP RECON is a typed ENTITY. Tools (transforms) consume one
entity type and emit others; when a new entity appears it is auto-queued into
every transform that accepts its type — the "hive-mind" auto-pivot.

This module is pure data + normalization: no Qt, no I/O. It is imported by the
graph, the engine, the transforms, and the reports layer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EntityType(str, Enum):
    """The typed universe of org-infrastructure findings.

    The string value is the stable machine key (used in dedup keys, exports and
    the transform registry). Display label + colour live in ``ENTITY_META``.
    """

    DOMAIN          = "domain"
    SUBDOMAIN       = "subdomain"
    IP_ADDRESS      = "ip"
    ASN             = "asn"
    NETBLOCK        = "netblock"
    DNS_RECORD      = "dns_record"
    CERTIFICATE     = "certificate"
    PORT            = "port"
    SERVICE         = "service"
    WEB_TECH        = "web_tech"
    URL             = "url"
    EMAIL           = "email"          # org-domain addresses only
    CLOUD_BUCKET    = "cloud_bucket"
    CODE_REPO       = "code_repo"
    LEAKED_SECRET   = "leaked_secret"
    BREACH_RECORD   = "breach_record"  # org-domain breaches only
    TYPOSQUAT       = "typosquat"      # lookalike / impersonation domains
    WHOIS_RECORD    = "whois_record"
    COMPANY         = "company"

    def __str__(self) -> str:  # so f"{etype}" is the value, not "EntityType.X"
        return self.value


@dataclass(frozen=True)
class EntityMeta:
    label: str      # human label for the ENTITY TYPES list + legend
    color: str      # hex colour for the graph node / legend
    short: str      # compact tag used in tables / the pivot queue


# Green/teal for the org's own assets; warm colours for exposure/risk types.
ENTITY_META: dict[EntityType, EntityMeta] = {
    EntityType.DOMAIN:        EntityMeta("Domains",         "#00e676", "DOM"),
    EntityType.SUBDOMAIN:     EntityMeta("Subdomains",      "#2fe0b0", "SUB"),
    EntityType.IP_ADDRESS:    EntityMeta("IP Addresses",    "#ff6b6b", "IP"),
    EntityType.ASN:           EntityMeta("ASNs",            "#b06aff", "ASN"),
    EntityType.NETBLOCK:      EntityMeta("Netblocks",       "#9a7aff", "NET"),
    EntityType.DNS_RECORD:    EntityMeta("DNS Records",     "#3aa0ff", "DNS"),
    EntityType.CERTIFICATE:   EntityMeta("SSL/TLS Certs",   "#e3b341", "CRT"),
    EntityType.PORT:          EntityMeta("Open Ports",      "#ff9a00", "PRT"),
    EntityType.SERVICE:       EntityMeta("Services",        "#ffb84d", "SVC"),
    EntityType.WEB_TECH:      EntityMeta("Web Technologies","#7c9aff", "TEC"),
    EntityType.URL:           EntityMeta("URLs",            "#4dd0e1", "URL"),
    EntityType.EMAIL:         EntityMeta("Emails (org)",    "#5b8dff", "EML"),
    EntityType.CLOUD_BUCKET:  EntityMeta("Cloud Buckets",   "#ff8c66", "BKT"),
    EntityType.CODE_REPO:     EntityMeta("Code Repos",      "#c2ccd6", "REPO"),
    EntityType.LEAKED_SECRET: EntityMeta("Leaked Secrets",  "#ff5555", "SEC"),
    EntityType.BREACH_RECORD: EntityMeta("Breach Exposure", "#ff4081", "BRC"),
    EntityType.TYPOSQUAT:     EntityMeta("Typosquats",      "#ff6ec7", "TYP"),
    EntityType.WHOIS_RECORD:  EntityMeta("WHOIS Records",   "#8aa897", "WHO"),
    EntityType.COMPANY:       EntityMeta("Company / Org",   "#d4af37", "ORG"),
}


def meta(etype: EntityType) -> EntityMeta:
    return ENTITY_META[etype]


# --- discovery depth ladder --------------------------------------------------

class Depth(int, Enum):
    SEED     = 0
    DIRECT   = 1
    INDIRECT = 2
    PIVOTED  = 3
    DEEP     = 4


DEPTH_LABELS = {
    Depth.SEED:     "Seed",
    Depth.DIRECT:   "Direct",
    Depth.INDIRECT: "Indirect",
    Depth.PIVOTED:  "Pivoted",
    Depth.DEEP:     "Deep",
}


def _normalize(etype: EntityType, value: str) -> str:
    """Canonicalise a value so the same asset from two tools dedups to one node."""
    v = (value or "").strip()
    if etype in (EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.TYPOSQUAT):
        v = v.rstrip(".").lower()
        if v.startswith("*."):        # wildcard cert entries → base label
            v = v[2:]
    elif etype == EntityType.EMAIL:
        v = v.lower()
    elif etype == EntityType.URL:
        v = v.rstrip("/")
    elif etype in (EntityType.IP_ADDRESS, EntityType.ASN, EntityType.NETBLOCK):
        v = v.strip().upper() if etype == EntityType.ASN else v.strip()
    return v


@dataclass
class Entity:
    """A single typed node in the recon graph.

    ``key`` is the dedup identity (``type:normalized_value``). ``sources`` is the
    provenance set — every transform that produced this entity. ``data`` holds
    type-specific attributes (banner, ports, registrar, risk detail, …).
    """

    etype: EntityType
    value: str
    depth: int = 0
    sources: set[str] = field(default_factory=set)
    data: dict[str, Any] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    # Optional risk classification set by the risk analyzer.
    risk: Optional[str] = None          # "critical"|"high"|"medium"|"low"|"info"
    risk_reason: str = ""

    def __post_init__(self) -> None:
        self.value = _normalize(self.etype, self.value)

    @property
    def key(self) -> str:
        return f"{self.etype.value}:{self.value}"

    @property
    def label(self) -> str:
        """A compact display label for graph nodes / tables."""
        return self.value

    def merge(self, other: "Entity") -> None:
        """Fold a re-discovery of the same asset into this node (dedup)."""
        self.sources |= other.sources
        # Keep the shallowest depth (closest to the seed).
        self.depth = min(self.depth, other.depth)
        self.discovered_at = min(self.discovered_at, other.discovered_at)
        for k, v in other.data.items():
            if k not in self.data:
                self.data[k] = v
        if other.risk and not self.risk:
            self.risk, self.risk_reason = other.risk, other.risk_reason

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "type": self.etype.value,
            "value": self.value,
            "depth": self.depth,
            "sources": sorted(self.sources),
            "data": self.data,
            "discovered_at": self.discovered_at,
            "risk": self.risk,
            "risk_reason": self.risk_reason,
        }
