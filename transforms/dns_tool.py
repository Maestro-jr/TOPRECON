"""
DNS transform (dnspython): Domain/Subdomain → DNS Records + IP Addresses.

Resolves A/AAAA/MX/NS/TXT/CNAME/SOA. A/AAAA become IP entities (which pivot to
Shodan/Censys/threat-intel); a dangling CNAME is flagged as a subdomain-takeover
candidate for the risk panel.
"""

from __future__ import annotations

import asyncio

from core.entities import Entity, EntityType
from core.transforms import Category, Emit, ModuleStatus, Transform, TransformContext
from .common import clean_host, is_ip

try:
    import dns.resolver
    import dns.exception
    _HAVE = True
except Exception:  # noqa: BLE001
    _HAVE = False

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

# CNAME targets pointing at these unclaimed-service patterns = takeover risk.
_TAKEOVER_HINTS = (
    "s3.amazonaws.com", "github.io", "herokuapp.com", "herokudns.com",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "cloudfront.net",
    "wordpress.com", "pantheonsite.io", "fastly.net", "ghost.io", "surge.sh",
    "bitbucket.io", "readthedocs.io", "netlify.app", "shopify.com", "zendesk.com",
)


class DnsTransform(Transform):
    name = "dns_enum"
    display = "DNS Enumeration"
    category = Category.DNS
    input_types = (EntityType.DOMAIN, EntityType.SUBDOMAIN)
    output_types = (EntityType.DNS_RECORD, EntityType.IP_ADDRESS)
    active = False
    request_weight = 1
    timeout = 25.0

    def availability(self, settings):
        return ModuleStatus.IDLE if _HAVE else ModuleStatus.MISSING

    async def run(self, entity: Entity, ctx: TransformContext) -> list[Emit]:
        if not _HAVE:
            return []
        host = clean_host(entity.value)
        records = await asyncio.to_thread(self._resolve_all, host)
        out: list[Emit] = []
        d = entity.depth + 1
        for rtype, values in records.items():
            for val in values:
                if rtype in ("A", "AAAA") and is_ip(val):
                    ip = ctx.child(EntityType.IP_ADDRESS, val, source=self.name,
                                   depth=d, ptr_host=host)
                    out.append(Emit.discovered(ip, rtype))
                dr = ctx.child(EntityType.DNS_RECORD, f"{rtype} {host} → {val}",
                               source=self.name, depth=d,
                               record_type=rtype, target=val, host=host)
                if rtype == "CNAME":
                    tgt = clean_host(val)
                    for hint in _TAKEOVER_HINTS:
                        if tgt.endswith(hint):
                            dr.risk = "high"
                            dr.risk_reason = (
                                f"CNAME → {tgt}: possible subdomain-takeover "
                                "candidate (verify the target is claimed).")
                            dr.data["takeover_candidate"] = True
                            break
                out.append(Emit.discovered(dr, rtype) if rtype in ("A", "AAAA")
                           else Emit.pivot(dr, rtype))
        return out

    @staticmethod
    def _resolve_all(host: str) -> dict[str, list[str]]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6.0
        resolver.timeout = 4.0
        results: dict[str, list[str]] = {}
        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(host, rtype)
            except Exception:  # noqa: BLE001 — NXDOMAIN/NoAnswer/timeout are normal
                continue
            vals = []
            for a in answers:
                txt = a.to_text().strip().strip('"')
                vals.append(txt)
            if vals:
                results[rtype] = vals
        return results
