"""WHOIS transform: Domain → WHOIS Record (registrar, dates, nameservers)."""

from __future__ import annotations

import asyncio
from typing import Any

from core.entities import Entity, EntityType
from core.transforms import (Category, Emit, Transform, TransformContext)
from .common import apex_domain, clean_host

try:
    import whois as _whois          # python-whois
    _HAVE = True
except Exception:  # noqa: BLE001
    _HAVE = False


def _fmt_date(val: Any) -> str:
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val) if val else ""


class WhoisTransform(Transform):
    name = "whois"
    display = "WHOIS Lookup"
    category = Category.DNS
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.WHOIS_RECORD, EntityType.DNS_RECORD)
    active = False
    request_weight = 1
    timeout = 30.0

    def availability(self, settings):
        from core.transforms import ModuleStatus
        return ModuleStatus.IDLE if _HAVE else ModuleStatus.MISSING

    async def run(self, entity: Entity, ctx: TransformContext) -> list[Emit]:
        if not _HAVE:
            return []
        domain = clean_host(entity.value)
        rec = await asyncio.to_thread(self._lookup, domain)
        if not rec:
            return []
        out: list[Emit] = []
        registrar = rec.get("registrar") or "unknown registrar"
        who = ctx.child(EntityType.WHOIS_RECORD, f"whois:{domain}",
                        source=self.name, depth=entity.depth + 1,
                        registrar=registrar,
                        created=rec.get("created"), expires=rec.get("expires"),
                        nameservers=rec.get("nameservers", []),
                        emails=rec.get("emails", []), org=rec.get("org", ""))
        who.data["display"] = registrar
        out.append(Emit.discovered(who, "whois"))
        # Nameservers are DNS infrastructure — surface as DNS records.
        for ns in rec.get("nameservers", [])[:12]:
            nsv = clean_host(ns)
            if not nsv:
                continue
            dr = ctx.child(EntityType.DNS_RECORD, f"NS {domain} → {nsv}",
                           source=self.name, depth=entity.depth + 1,
                           record_type="NS", target=nsv)
            out.append(Emit.pivot(dr, "NS"))
        return out

    @staticmethod
    def _lookup(domain: str) -> dict:
        try:
            w = _whois.whois(domain)
        except Exception:  # noqa: BLE001 — WHOIS servers are flaky
            return {}
        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]
        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]
        return {
            "registrar": w.registrar,
            "created": _fmt_date(w.creation_date),
            "expires": _fmt_date(w.expiration_date),
            "nameservers": [str(x).lower() for x in ns],
            "emails": [str(x) for x in emails],
            "org": str(w.org) if getattr(w, "org", None) else "",
        }
