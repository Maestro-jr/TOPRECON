"""
Transform registry assembly.

``build_registry()`` instantiates and registers every transform. Adding a tool
is a one-line append here — the engine auto-discovers which entity types it
consumes and wires the pivot graph accordingly.
"""

from __future__ import annotations

from core.transforms import TransformRegistry


def build_registry() -> TransformRegistry:
    reg = TransformRegistry()

    # --- Domain & DNS intelligence ---
    from .whois_tool import WhoisTransform
    from .dns_tool import DnsTransform
    reg.register(WhoisTransform())
    reg.register(DnsTransform())

    # --- Subdomain enumeration ---
    from .subfinder_tool import SubfinderTransform
    reg.register(SubfinderTransform())

    # --- Certificate intelligence ---
    from .crtsh_tool import CrtShTransform
    reg.register(CrtShTransform())

    # --- Host / service / port discovery ---
    from .shodan_tool import ShodanTransform
    reg.register(ShodanTransform())

    # --- Remaining modules (registered as they are wired in) ---
    try:
        from . import extra_modules
        extra_modules.register_all(reg)
    except Exception:  # noqa: BLE001 — extras are additive, never fatal
        pass

    return reg
