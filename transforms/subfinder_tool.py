"""
subfinder transform: Domain → Subdomains (passive, fast).

Wraps the ProjectDiscovery `subfinder` binary via subprocess. If the binary is
not on PATH the module reports "Not Installed" and the engine skips it — the app
never crashes over a missing tool.
"""

from __future__ import annotations

import asyncio
import shutil

from core.entities import Entity, EntityType
from core.transforms import Category, Emit, ModuleStatus, Transform, TransformContext
from .common import apex_domain, clean_host, in_scope, is_valid_domain


class SubfinderTransform(Transform):
    name = "subfinder"
    display = "Subfinder"
    category = Category.SUBDOMAIN
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN,)
    active = False
    requires_bin = "subfinder"
    request_weight = 2
    timeout = 120.0

    async def run(self, entity: Entity, ctx: TransformContext) -> list[Emit]:
        binp = shutil.which("subfinder")
        if not binp:
            return []
        domain = clean_host(entity.value)
        lines = await self._run_subfinder(binp, domain)
        seed_apex = apex_domain(ctx.seed_target)
        out: list[Emit] = []
        seen: set[str] = set()
        for line in lines:
            host = clean_host(line)
            if not host or host in seen or not is_valid_domain(host):
                continue
            if not in_scope(host, seed_apex):
                continue
            seen.add(host)
            etype = (EntityType.DOMAIN if host == seed_apex
                     else EntityType.SUBDOMAIN)
            sub = ctx.child(etype, host, source=self.name,
                            depth=entity.depth + 1, via="subfinder")
            out.append(Emit.discovered(sub, "subfinder"))
        return out

    async def _run_subfinder(self, binp: str, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                binp, "-d", domain, "-silent", "-all",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            return stdout.decode("utf-8", "replace").splitlines()
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return []
