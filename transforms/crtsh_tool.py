"""
crt.sh Certificate Transparency transform: Domain → Subdomains + SSL Certs.

Passive, no key. Queries the public CT log mirror at crt.sh and turns every
logged certificate into a Certificate entity and every SAN/CN into an in-scope
Subdomain entity — a classic high-yield recon pivot.
"""

from __future__ import annotations

import json

from core.entities import Entity, EntityType
from core.transforms import Category, Emit, Transform, TransformContext
from .common import apex_domain, clean_host, http_client, in_scope, is_valid_domain


class CrtShTransform(Transform):
    name = "crtsh"
    display = "Cert Transparency (crt.sh)"
    category = Category.CERT
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN, EntityType.CERTIFICATE)
    active = False
    request_weight = 1
    timeout = 40.0

    async def run(self, entity: Entity, ctx: TransformContext) -> list[Emit]:
        domain = clean_host(entity.value)
        rows = await self._query(domain)
        if not rows:
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out: list[Emit] = []
        seen_hosts: set[str] = set()
        seen_certs: set[str] = set()
        d = entity.depth + 1
        for row in rows:
            issuer = (row.get("issuer_name") or "")[:120]
            cert_id = str(row.get("id") or row.get("serial_number") or "")
            names = str(row.get("name_value") or "").splitlines()
            primary = clean_host(names[0]) if names else domain
            if cert_id and cert_id not in seen_certs:
                seen_certs.add(cert_id)
                cert = ctx.child(
                    EntityType.CERTIFICATE, f"cert:{cert_id}", source=self.name,
                    depth=d, issuer=issuer, common_name=primary,
                    not_before=row.get("not_before"),
                    not_after=row.get("not_after"),
                    sans=[clean_host(n) for n in names][:40])
                cert.data["display"] = primary or issuer
                self._flag_weak_cert(cert, row)
                out.append(Emit.discovered(cert, "cert"))
            for name in names:
                host = clean_host(name)
                if not host or host in seen_hosts or not is_valid_domain(host):
                    continue
                if not in_scope(host, seed_apex):
                    continue
                seen_hosts.add(host)
                etype = (EntityType.DOMAIN if host == seed_apex
                         else EntityType.SUBDOMAIN)
                sub = ctx.child(etype, host, source=self.name, depth=d,
                                via="certificate transparency")
                out.append(Emit.discovered(sub, "CT"))
        return out

    async def _query(self, domain: str) -> list[dict]:
        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        try:
            resp = await http_client().get(url, params=params, timeout=35.0)
            if resp.status_code != 200 or not resp.text.strip():
                return []
            # crt.sh occasionally returns concatenated JSON objects.
            try:
                return resp.json()
            except json.JSONDecodeError:
                fixed = "[" + resp.text.replace("}\n{", "},\n{") + "]"
                return json.loads(fixed)
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _flag_weak_cert(cert: Entity, row: dict) -> None:
        na = str(row.get("not_after") or "")
        # Expired certificate → medium risk (cheap heuristic on the CT date).
        try:
            from datetime import datetime, timezone
            if na:
                dt = datetime.fromisoformat(na.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < datetime.now(timezone.utc):
                    cert.risk = "medium"
                    cert.risk_reason = f"Certificate expired ({na})."
        except Exception:  # noqa: BLE001
            pass
