"""
Shodan transform: IP / Domain → open Ports, Services, banners, known CVEs.

Passive (Shodan's own scans, not ours). Key-gated: shows "Needs Key" until a
SHODAN_API_KEY is present. Open sensitive ports and known CVEs are risk-tagged
for the Attack-Surface panel.
"""

from __future__ import annotations

import asyncio

from core.entities import Entity, EntityType
from core.transforms import Category, Emit, ModuleStatus, Transform, TransformContext
from .common import apex_domain, clean_host, in_scope, is_ip, is_valid_domain

try:
    import shodan as _shodan
    _HAVE = True
except Exception:  # noqa: BLE001
    _HAVE = False

# Ports that are notable exposure when reachable from the internet.
_SENSITIVE_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP",
                    3306: "MySQL", 5432: "Postgres", 6379: "Redis",
                    9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
                    5900: "VNC", 1433: "MSSQL", 2375: "Docker API"}


class ShodanTransform(Transform):
    name = "shodan"
    display = "Shodan"
    category = Category.HOST
    input_types = (EntityType.IP_ADDRESS, EntityType.DOMAIN)
    output_types = (EntityType.PORT, EntityType.SERVICE, EntityType.SUBDOMAIN,
                    EntityType.IP_ADDRESS)
    active = False
    needs_key = "shodan"
    request_weight = 1
    timeout = 40.0

    def availability(self, settings):
        if not _HAVE:
            return ModuleStatus.MISSING
        return ModuleStatus.IDLE if settings.get_key("shodan") else ModuleStatus.NEEDS_KEY

    async def run(self, entity: Entity, ctx: TransformContext) -> list[Emit]:
        key = ctx.settings.get_key("shodan")
        if not _HAVE or not key:
            return []
        api = _shodan.Shodan(key)
        if entity.etype == EntityType.IP_ADDRESS:
            return await asyncio.to_thread(self._host, api, entity, ctx)
        return await asyncio.to_thread(self._domain, api, entity, ctx)

    def _host(self, api, entity: Entity, ctx: TransformContext) -> list[Emit]:
        ip = clean_host(entity.value)
        try:
            info = api.host(ip)
        except Exception:  # noqa: BLE001 — 404 = no data on this host
            return []
        out: list[Emit] = []
        d = entity.depth + 1
        entity.data.setdefault("org", info.get("org", ""))
        entity.data.setdefault("isp", info.get("isp", ""))
        entity.data.setdefault("country", info.get("country_name", ""))
        for item in info.get("data", []):
            port = item.get("port")
            if port is None:
                continue
            product = item.get("product") or item.get("_shodan", {}).get("module", "")
            banner = (item.get("data") or "")[:400]
            pe = ctx.child(EntityType.PORT, f"{ip}:{port}", source=self.name,
                           depth=d, port=port, transport=item.get("transport", "tcp"),
                           product=product)
            if port in _SENSITIVE_PORTS:
                pe.risk = "high"
                pe.risk_reason = (f"Sensitive service {_SENSITIVE_PORTS[port]} "
                                  f"exposed on port {port}.")
            out.append(Emit.discovered(pe, str(port)))
            if product:
                se = ctx.child(EntityType.SERVICE, f"{product} @ {ip}:{port}",
                               source=self.name, depth=d, banner=banner,
                               port=port, version=item.get("version", ""))
                cves = list((item.get("vulns") or {}).keys())
                if cves:
                    se.risk = "critical"
                    se.risk_reason = f"Known CVEs: {', '.join(cves[:6])}"
                    se.data["cves"] = cves
                out.append(Emit.pivot(se, "service"))
        for host in info.get("hostnames", []):
            h = clean_host(host)
            if is_valid_domain(h) and in_scope(h, apex_domain(ctx.seed_target)):
                sub = ctx.child(EntityType.SUBDOMAIN, h, source=self.name,
                                depth=d, via="shodan reverse")
                out.append(Emit.pivot(sub, "ptr"))
        return out

    def _domain(self, api, entity: Entity, ctx: TransformContext) -> list[Emit]:
        domain = clean_host(entity.value)
        try:
            info = api.dns.domain_info(domain, history=False, type=None)
        except Exception:  # noqa: BLE001
            return []
        out: list[Emit] = []
        seed_apex = apex_domain(ctx.seed_target)
        d = entity.depth + 1
        for rec in info.get("data", [])[:200]:
            sub = rec.get("subdomain")
            host = f"{sub}.{domain}" if sub else domain
            host = clean_host(host)
            value = rec.get("value", "")
            if rec.get("type") in ("A", "AAAA") and is_ip(value):
                out.append(Emit.discovered(
                    ctx.child(EntityType.IP_ADDRESS, value, source=self.name,
                              depth=d), value))
            if host and is_valid_domain(host) and in_scope(host, seed_apex):
                etype = EntityType.DOMAIN if host == seed_apex else EntityType.SUBDOMAIN
                out.append(Emit.discovered(
                    ctx.child(etype, host, source=self.name, depth=d,
                              via="shodan dns"), "shodan"))
        return out
