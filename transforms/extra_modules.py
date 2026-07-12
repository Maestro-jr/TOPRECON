"""
The remaining TOP RECON transform modules.

Grouped by class:
  * Keyless HTTP APIs with real parsers (certspotter, anubis, wayback,
    hackertarget, urlscan-search, xposedornot, robtex) — run out of the box.
  * Key-gated HTTP sources (VirusTotal, AbuseIPDB, HIBP, Censys, Hunter,
    BuiltWith, GitHub code search, OTX, LeakIX, URLScan submit) — real when a
    key is present, "Needs Key" otherwise.
  * Subprocess binaries (amass, sublist3r, dnstwist, httpx, nmap, whatweb,
    theHarvester, gitleaks, s3scanner) — real when the tool is on PATH,
    "Not Installed" otherwise. Active tools honour the active-scan gate.

Every module fails closed: no crash on a missing key/binary/timeout.
"""

from __future__ import annotations

import asyncio
import json
import shutil

from core.entities import EntityType
from core.transforms import Category, Emit, ModuleStatus, Transform
from .common import (apex_domain, clean_host, http_client, in_scope, is_ip,
                     is_valid_domain)


# ============================================================ keyless HTTP APIs
class _KeylessHTTP(Transform):
    active = False
    def availability(self, settings):
        return ModuleStatus.IDLE


class CertSpotterTransform(_KeylessHTTP):
    name = "certspotter"; display = "CertSpotter CT"
    category = Category.CERT
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN, EntityType.CERTIFICATE)
    timeout = 35.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        try:
            r = await http_client().get(
                f"https://api.certspotter.com/v1/issuances",
                params={"domain": domain, "include_subdomains": "true",
                        "expand": "dns_names"}, timeout=30.0)
            if r.status_code != 200:
                return []
            rows = r.json()
        except Exception:  # noqa: BLE001
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen = [], set()
        for row in rows:
            for name in row.get("dns_names", []):
                h = clean_host(name)
                if h and h not in seen and is_valid_domain(h) and in_scope(h, seed_apex):
                    seen.add(h)
                    et = EntityType.DOMAIN if h == seed_apex else EntityType.SUBDOMAIN
                    out.append(Emit.discovered(
                        ctx.child(et, h, source=self.name, depth=entity.depth + 1), "CT"))
        return out


class AnubisTransform(_KeylessHTTP):
    name = "anubis"; display = "AnubisDB"
    category = Category.SUBDOMAIN
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN,)
    timeout = 25.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        try:
            r = await http_client().get(f"https://jldc.me/anubis/subdomains/{domain}",
                                        timeout=20.0)
            names = r.json() if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen = [], set()
        for name in names or []:
            h = clean_host(name)
            if h and h not in seen and is_valid_domain(h) and in_scope(h, seed_apex):
                seen.add(h)
                et = EntityType.DOMAIN if h == seed_apex else EntityType.SUBDOMAIN
                out.append(Emit.discovered(
                    ctx.child(et, h, source=self.name, depth=entity.depth + 1), "anubis"))
        return out


class HackerTargetTransform(_KeylessHTTP):
    name = "hackertarget"; display = "HackerTarget hostsearch"
    category = Category.SUBDOMAIN
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN, EntityType.IP_ADDRESS)
    timeout = 25.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        try:
            r = await http_client().get("https://api.hackertarget.com/hostsearch/",
                                        params={"q": domain}, timeout=20.0)
            text = r.text if r.status_code == 200 else ""
        except Exception:  # noqa: BLE001
            return []
        if "API count exceeded" in text or "error" in text.lower():
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen = [], set()
        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) != 2:
                continue
            host, ip = clean_host(parts[0]), parts[1].strip()
            if host and host not in seen and is_valid_domain(host) and in_scope(host, seed_apex):
                seen.add(host)
                et = EntityType.DOMAIN if host == seed_apex else EntityType.SUBDOMAIN
                sub = ctx.child(et, host, source=self.name, depth=entity.depth + 1)
                out.append(Emit.discovered(sub, "hostsearch"))
            if is_ip(ip):
                out.append(Emit.discovered(
                    ctx.child(EntityType.IP_ADDRESS, ip, source=self.name,
                              depth=entity.depth + 1), "A"))
        return out


class WaybackTransform(_KeylessHTTP):
    name = "wayback"; display = "Wayback Machine"
    category = Category.BRAND
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.URL, EntityType.SUBDOMAIN)
    timeout = 35.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        try:
            r = await http_client().get(
                "http://web.archive.org/cdx/search/cdx",
                params={"url": f"*.{domain}/*", "output": "json",
                        "fl": "original", "collapse": "urlkey", "limit": "500"},
                timeout=30.0)
            rows = r.json() if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen_u, seen_h = [], set(), set()
        for row in (rows[1:] if rows and isinstance(rows[0], list) else []):
            url = row[0] if row else ""
            if not url or url in seen_u:
                continue
            seen_u.add(url)
            if len(out) < 120:
                out.append(Emit.discovered(
                    ctx.child(EntityType.URL, url, source=self.name,
                              depth=entity.depth + 1), "archived"))
            # extract host → subdomain
            host = url.split("//")[-1].split("/")[0].split(":")[0]
            host = clean_host(host)
            if host and host not in seen_h and is_valid_domain(host) and in_scope(host, seed_apex):
                seen_h.add(host)
                et = EntityType.DOMAIN if host == seed_apex else EntityType.SUBDOMAIN
                out.append(Emit.pivot(
                    ctx.child(et, host, source=self.name, depth=entity.depth + 1), "archive"))
        return out


class UrlscanSearchTransform(_KeylessHTTP):
    name = "urlscan_search"; display = "URLScan.io search"
    category = Category.BRAND
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.URL, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS)
    timeout = 30.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        try:
            r = await http_client().get("https://urlscan.io/api/v1/search/",
                                        params={"q": f"domain:{domain}", "size": 100},
                                        timeout=25.0)
            results = r.json().get("results", []) if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen = [], set()
        for res in results:
            page = res.get("page", {})
            url = res.get("task", {}).get("url") or page.get("url", "")
            host = clean_host(page.get("domain", ""))
            ip = page.get("ip", "")
            if url and url not in seen and len(out) < 120:
                seen.add(url)
                out.append(Emit.discovered(
                    ctx.child(EntityType.URL, url, source=self.name,
                              depth=entity.depth + 1), "urlscan"))
            if host and is_valid_domain(host) and in_scope(host, seed_apex):
                et = EntityType.DOMAIN if host == seed_apex else EntityType.SUBDOMAIN
                out.append(Emit.pivot(
                    ctx.child(et, host, source=self.name, depth=entity.depth + 1), "urlscan"))
            if is_ip(ip):
                out.append(Emit.pivot(
                    ctx.child(EntityType.IP_ADDRESS, ip, source=self.name,
                              depth=entity.depth + 1), "resolved"))
        return out


class XposedOrNotTransform(_KeylessHTTP):
    name = "xposedornot"; display = "XposedOrNot breaches"
    category = Category.BREACH
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.BREACH_RECORD,)
    timeout = 25.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        if domain != apex_domain(ctx.seed_target):
            return []   # org-domain only
        try:
            r = await http_client().get(
                f"https://api.xposedornot.com/v1/domain-breaches/{domain}", timeout=20.0)
            data = r.json() if r.status_code == 200 else {}
        except Exception:  # noqa: BLE001
            return []
        out = []
        breaches = (data.get("breaches") or data.get("Exposed_Breaches") or [])
        for b in breaches[:40]:
            name = b if isinstance(b, str) else b.get("breach", "breach")
            be = ctx.child(EntityType.BREACH_RECORD, f"{domain}:{name}",
                           source=self.name, depth=entity.depth + 1,
                           detail=f"Org domain in breach '{name}'.")
            be.data["display"] = name
            out.append(Emit.discovered(be, "breach"))
        return out


class RobtexTransform(_KeylessHTTP):
    name = "robtex"; display = "Robtex passive DNS"
    category = Category.DNS
    input_types = (EntityType.IP_ADDRESS,)
    output_types = (EntityType.SUBDOMAIN, EntityType.DOMAIN)
    timeout = 25.0

    async def run(self, entity, ctx):
        ip = clean_host(entity.value)
        try:
            r = await http_client().get(f"https://freeapi.robtex.com/ipquery/{ip}",
                                        timeout=20.0)
            data = r.json() if r.status_code == 200 else {}
        except Exception:  # noqa: BLE001
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen = [], set()
        for rec in (data.get("pas", []) or []):
            host = clean_host(rec.get("o", ""))
            if host and host not in seen and is_valid_domain(host) and in_scope(host, seed_apex):
                seen.add(host)
                et = EntityType.DOMAIN if host == seed_apex else EntityType.SUBDOMAIN
                out.append(Emit.pivot(
                    ctx.child(et, host, source=self.name, depth=entity.depth + 1), "pdns"))
        return out


# ============================================================ key-gated HTTP
class VirusTotalTransform(Transform):
    name = "virustotal"; display = "VirusTotal"
    category = Category.THREATINTEL
    input_types = (EntityType.DOMAIN, EntityType.IP_ADDRESS)
    output_types = (EntityType.SUBDOMAIN, EntityType.IP_ADDRESS)
    needs_key = "virustotal"; timeout = 30.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("virustotal")
        if not key:
            return []
        headers = {"x-apikey": key}
        base = "https://www.virustotal.com/api/v3"
        seed_apex = apex_domain(ctx.seed_target)
        out = []
        try:
            if entity.etype == EntityType.DOMAIN:
                r = await http_client().get(
                    f"{base}/domains/{clean_host(entity.value)}/subdomains",
                    headers=headers, params={"limit": 40}, timeout=25.0)
                for item in (r.json().get("data", []) if r.status_code == 200 else []):
                    h = clean_host(item.get("id", ""))
                    if is_valid_domain(h) and in_scope(h, seed_apex):
                        out.append(Emit.discovered(
                            ctx.child(EntityType.SUBDOMAIN, h, source=self.name,
                                      depth=entity.depth + 1), "vt"))
            else:
                r = await http_client().get(
                    f"{base}/ip_addresses/{clean_host(entity.value)}",
                    headers=headers, timeout=25.0)
                if r.status_code == 200:
                    attr = r.json().get("data", {}).get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    mal = stats.get("malicious", 0)
                    entity.data["vt_malicious"] = mal
                    if mal:
                        entity.risk = "high" if mal > 2 else "medium"
                        entity.risk_reason = f"VirusTotal: {mal} engines flag this IP."
        except Exception:  # noqa: BLE001
            return out
        return out


class AbuseIPDBTransform(Transform):
    name = "abuseipdb"; display = "AbuseIPDB"
    category = Category.THREATINTEL
    input_types = (EntityType.IP_ADDRESS,)
    output_types = ()
    needs_key = "abuseipdb"; timeout = 25.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("abuseipdb")
        if not key:
            return []
        try:
            r = await http_client().get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": clean_host(entity.value), "maxAgeInDays": 90},
                timeout=20.0)
            data = r.json().get("data", {}) if r.status_code == 200 else {}
        except Exception:  # noqa: BLE001
            return []
        score = data.get("abuseConfidenceScore", 0)
        entity.data["abuse_score"] = score
        entity.data["isp"] = data.get("isp", "")
        if score >= 50:
            entity.risk = "high"
            entity.risk_reason = f"AbuseIPDB confidence {score}% ({data.get('totalReports',0)} reports)."
        return []


class HIBPTransform(Transform):
    name = "hibp"; display = "Have I Been Pwned"
    category = Category.BREACH
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.BREACH_RECORD,)
    needs_key = "hibp"; timeout = 25.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("hibp")
        domain = clean_host(entity.value)
        if not key or domain != apex_domain(ctx.seed_target):
            return []
        try:
            r = await http_client().get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                params={"domain": domain},
                headers={"hibp-api-key": key, "user-agent": "TOP-RECON"}, timeout=20.0)
            rows = r.json() if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        out = []
        for b in rows or []:
            name = b.get("Name", "breach")
            be = ctx.child(EntityType.BREACH_RECORD, f"{domain}:{name}",
                           source=self.name, depth=entity.depth + 1,
                           detail=f"{b.get('PwnCount',0):,} accounts — {b.get('BreachDate','')}")
            be.data["display"] = name
            out.append(Emit.discovered(be, "hibp"))
        return out


class HunterTransform(Transform):
    name = "hunter"; display = "Hunter.io"
    category = Category.EMAIL
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.EMAIL,)
    needs_key = "hunter"; timeout = 25.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("hunter")
        domain = clean_host(entity.value)
        if not key or not in_scope(domain, apex_domain(ctx.seed_target)):
            return []
        try:
            r = await http_client().get("https://api.hunter.io/v2/domain-search",
                                        params={"domain": domain, "api_key": key,
                                                "limit": 50}, timeout=20.0)
            data = r.json().get("data", {}) if r.status_code == 200 else {}
        except Exception:  # noqa: BLE001
            return []
        out = []
        for e in data.get("emails", []):
            addr = (e.get("value") or "").lower()
            if addr.endswith("@" + apex_domain(ctx.seed_target)) or apex_domain(ctx.seed_target) in addr:
                out.append(Emit.discovered(
                    ctx.child(EntityType.EMAIL, addr, source=self.name,
                              depth=entity.depth + 1,
                              pattern=data.get("pattern", "")), "hunter"))
        return out


class CensysTransform(Transform):
    name = "censys"; display = "Censys hosts"
    category = Category.HOST
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.IP_ADDRESS, EntityType.SUBDOMAIN)
    needs_key = "censys_id"; timeout = 30.0

    async def run(self, entity, ctx):
        cid = ctx.settings.get_key("censys_id")
        secret = ctx.settings.get_key("censys_secret")
        if not (cid and secret):
            return []
        domain = clean_host(entity.value)
        try:
            r = await http_client().post(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": f"services.tls.certificates.leaf_data.names: {domain}",
                        "per_page": 50}, auth=(cid, secret), timeout=25.0)
            hits = r.json().get("result", {}).get("hits", []) if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        out = []
        for h in hits:
            ip = h.get("ip", "")
            if is_ip(ip):
                out.append(Emit.discovered(
                    ctx.child(EntityType.IP_ADDRESS, ip, source=self.name,
                              depth=entity.depth + 1), "censys"))
        return out


class BuiltWithTransform(Transform):
    name = "builtwith"; display = "BuiltWith"
    category = Category.WEBTECH
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.WEB_TECH,)
    needs_key = "builtwith"; timeout = 25.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("builtwith")
        if not key:
            return []
        try:
            r = await http_client().get("https://api.builtwith.com/v21/api.json",
                                        params={"KEY": key, "LOOKUP": clean_host(entity.value)},
                                        timeout=20.0)
            data = r.json() if r.status_code == 200 else {}
        except Exception:  # noqa: BLE001
            return []
        out, seen = [], set()
        for res in data.get("Results", []):
            for path in res.get("Result", {}).get("Paths", []):
                for tech in path.get("Technologies", []):
                    name = tech.get("Name", "")
                    if name and name not in seen:
                        seen.add(name)
                        out.append(Emit.discovered(
                            ctx.child(EntityType.WEB_TECH, name, source=self.name,
                                      depth=entity.depth + 1,
                                      category=tech.get("Tag", "")), "builtwith"))
        return out


class OTXTransform(Transform):
    name = "otx"; display = "AlienVault OTX"
    category = Category.THREATINTEL
    input_types = (EntityType.DOMAIN, EntityType.IP_ADDRESS)
    output_types = (EntityType.SUBDOMAIN,)
    needs_key = "otx"; timeout = 25.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("otx")
        if not key:
            return []
        kind = "domain" if entity.etype == EntityType.DOMAIN else "IPv4"
        try:
            r = await http_client().get(
                f"https://otx.alienvault.com/api/v1/indicators/{kind}/"
                f"{clean_host(entity.value)}/passive_dns",
                headers={"X-OTX-API-KEY": key}, timeout=20.0)
            rows = r.json().get("passive_dns", []) if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        seed_apex = apex_domain(ctx.seed_target)
        out, seen = [], set()
        for rec in rows:
            h = clean_host(rec.get("hostname", ""))
            if h and h not in seen and is_valid_domain(h) and in_scope(h, seed_apex):
                seen.add(h)
                et = EntityType.DOMAIN if h == seed_apex else EntityType.SUBDOMAIN
                out.append(Emit.pivot(
                    ctx.child(et, h, source=self.name, depth=entity.depth + 1), "otx"))
        return out


class GitHubCodeTransform(Transform):
    name = "github_code"; display = "GitHub code search"
    category = Category.CLOUD
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.CODE_REPO, EntityType.LEAKED_SECRET)
    needs_key = "github"; timeout = 30.0

    async def run(self, entity, ctx):
        token = ctx.settings.get_key("github")
        domain = clean_host(entity.value)
        if not token or domain != apex_domain(ctx.seed_target):
            return []
        try:
            r = await http_client().get(
                "https://api.github.com/search/code",
                params={"q": f'"{domain}"', "per_page": 30},
                headers={"Authorization": f"Bearer {token}",
                         "Accept": "application/vnd.github+json"}, timeout=25.0)
            items = r.json().get("items", []) if r.status_code == 200 else []
        except Exception:  # noqa: BLE001
            return []
        out, seen = [], set()
        for it in items:
            repo = it.get("repository", {}).get("full_name", "")
            if repo and repo not in seen:
                seen.add(repo)
                out.append(Emit.discovered(
                    ctx.child(EntityType.CODE_REPO, repo, source=self.name,
                              depth=entity.depth + 1,
                              url=it.get("html_url", "")), "github"))
        return out


class LeakIXTransform(Transform):
    name = "leakix"; display = "LeakIX"
    category = Category.CLOUD
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SERVICE, EntityType.LEAKED_SECRET)
    needs_key = "leakix"; timeout = 30.0

    async def run(self, entity, ctx):
        key = ctx.settings.get_key("leakix")
        if not key:
            return []
        try:
            r = await http_client().get(
                f"https://leakix.net/domain/{clean_host(entity.value)}",
                headers={"api-key": key, "Accept": "application/json"}, timeout=25.0)
            data = r.json() if r.status_code == 200 else {}
        except Exception:  # noqa: BLE001
            return []
        out = []
        for svc in (data.get("Services", []) or [])[:40]:
            ip = svc.get("ip", ""); port = svc.get("port", "")
            se = ctx.child(EntityType.SERVICE, f"{svc.get('software',{}).get('name','svc')} @ {ip}:{port}",
                           source=self.name, depth=entity.depth + 1,
                           port=port, ip=ip)
            out.append(Emit.discovered(se, "leakix"))
        for leak in (data.get("Leaks", []) or [])[:20]:
            le = ctx.child(EntityType.LEAKED_SECRET,
                           f"leak:{leak.get('event_source','')}:{leak.get('ip','')}",
                           source=self.name, depth=entity.depth + 1,
                           detail=leak.get("event_source", "exposed data"))
            le.risk = "high"; le.risk_reason = "LeakIX flagged exposed data."
            out.append(Emit.discovered(le, "leak"))
        return out


# ============================================================ subprocess tools
class _Subprocess(Transform):
    """Base for binary tools; availability keys off the binary being on PATH."""
    def availability(self, settings):
        if self.needs_key and not settings.get_key(self.needs_key):
            return ModuleStatus.NEEDS_KEY
        return ModuleStatus.IDLE if shutil.which(self.requires_bin) else ModuleStatus.MISSING

    async def _exec(self, *args: str, timeout: float = None) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(),
                                            timeout=timeout or self.timeout)
            return out.decode("utf-8", "replace")
        except (asyncio.TimeoutError, FileNotFoundError, OSError):
            return ""


class AmassTransform(_Subprocess):
    name = "amass"; display = "OWASP Amass"
    category = Category.SUBDOMAIN
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN,)
    requires_bin = "amass"; timeout = 240.0; request_weight = 3

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        text = await self._exec("amass", "enum", "-passive", "-d", domain, "-nocolor")
        return _hosts_to_emits(text.splitlines(), entity, ctx, self.name, "amass")


class Sublist3rTransform(_Subprocess):
    name = "sublist3r"; display = "Sublist3r"
    category = Category.SUBDOMAIN
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.SUBDOMAIN,)
    requires_bin = "sublist3r"; timeout = 180.0; request_weight = 2

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        text = await self._exec("sublist3r", "-d", domain, "-n")
        return _hosts_to_emits(text.splitlines(), entity, ctx, self.name, "sublist3r")


class DnstwistTransform(_Subprocess):
    name = "dnstwist"; display = "dnstwist (typosquat)"
    category = Category.BRAND
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.TYPOSQUAT,)
    requires_bin = "dnstwist"; timeout = 180.0; request_weight = 2

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        if domain != apex_domain(ctx.seed_target):
            return []
        text = await self._exec("dnstwist", "--format", "json", "-r", domain)
        try:
            rows = json.loads(text) if text.strip() else []
        except json.JSONDecodeError:
            return []
        out = []
        for row in rows:
            fuzz = row.get("fuzzer", "")
            name = clean_host(row.get("domain", row.get("domain-name", "")))
            if not name or name == domain or not is_valid_domain(name):
                continue
            registered = bool(row.get("dns_a") or row.get("dns-a") or row.get("dns_ns"))
            te = ctx.child(EntityType.TYPOSQUAT, name, source=self.name,
                           depth=entity.depth + 1, fuzzer=fuzz, registered=registered)
            if registered:
                te.risk = "medium"
                te.risk_reason = f"Registered lookalike ({fuzz}) — brand-impersonation risk."
            out.append(Emit.discovered(te, "typosquat"))
        return out


class HttpxTransform(_Subprocess):
    name = "httpx"; display = "httpx (live probe)"
    category = Category.HOST
    input_types = (EntityType.SUBDOMAIN, EntityType.DOMAIN)
    output_types = (EntityType.URL, EntityType.WEB_TECH)
    requires_bin = "httpx"; active = True; timeout = 40.0

    async def run(self, entity, ctx):
        host = clean_host(entity.value)
        text = await self._exec("httpx", "-u", host, "-json", "-silent",
                                 "-title", "-tech-detect", "-status-code")
        out = []
        for line in text.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = d.get("url", "")
            if url:
                ue = ctx.child(EntityType.URL, url, source=self.name,
                               depth=entity.depth + 1,
                               status=d.get("status_code"), title=d.get("title", ""))
                out.append(Emit.discovered(ue, "live"))
            for tech in d.get("tech", []) or d.get("technologies", []) or []:
                out.append(Emit.pivot(
                    ctx.child(EntityType.WEB_TECH, tech, source=self.name,
                              depth=entity.depth + 1), "tech"))
        return out


class NmapTransform(_Subprocess):
    name = "nmap"; display = "Nmap (active)"
    category = Category.HOST
    input_types = (EntityType.IP_ADDRESS,)
    output_types = (EntityType.PORT, EntityType.SERVICE)
    requires_bin = "nmap"; active = True; timeout = 180.0

    async def run(self, entity, ctx):
        ip = clean_host(entity.value)
        text = await self._exec("nmap", "-T4", "-F", "-sV", "--open", ip)
        out = []
        for line in text.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                svc = parts[2] if len(parts) > 2 else ""
                ver = " ".join(parts[3:]) if len(parts) > 3 else ""
                pe = ctx.child(EntityType.PORT, f"{ip}:{port}", source=self.name,
                               depth=entity.depth + 1, port=int(port) if port.isdigit() else port)
                out.append(Emit.discovered(pe, port))
                if svc:
                    out.append(Emit.pivot(
                        ctx.child(EntityType.SERVICE, f"{svc} @ {ip}:{port}",
                                  source=self.name, depth=entity.depth + 1,
                                  version=ver), "service"))
        return out


class WhatWebTransform(_Subprocess):
    name = "whatweb"; display = "WhatWeb"
    category = Category.WEBTECH
    input_types = (EntityType.URL,)
    output_types = (EntityType.WEB_TECH,)
    requires_bin = "whatweb"; active = True; timeout = 60.0

    async def run(self, entity, ctx):
        text = await self._exec("whatweb", "--log-json=-", "--no-errors", entity.value)
        out, seen = [], set()
        for line in text.splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            for plugin in (d.get("plugins", {}) or {}):
                if plugin not in seen:
                    seen.add(plugin)
                    out.append(Emit.discovered(
                        ctx.child(EntityType.WEB_TECH, plugin, source=self.name,
                                  depth=entity.depth + 1), "whatweb"))
        return out


class TheHarvesterTransform(_Subprocess):
    name = "theharvester"; display = "theHarvester"
    category = Category.EMAIL
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.EMAIL, EntityType.SUBDOMAIN)
    requires_bin = "theHarvester"; timeout = 180.0; request_weight = 2

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        if domain != apex_domain(ctx.seed_target):
            return []
        import tempfile, os
        tmp = os.path.join(tempfile.gettempdir(), f"th_{domain}")
        await self._exec("theHarvester", "-d", domain, "-b", "crtsh,bing,duckduckgo",
                         "-f", tmp)
        out = []
        jf = tmp + ".json"
        try:
            if os.path.exists(jf):
                data = json.loads(open(jf, encoding="utf-8").read())
                for em in data.get("emails", []):
                    if apex_domain(ctx.seed_target) in em.lower():
                        out.append(Emit.discovered(
                            ctx.child(EntityType.EMAIL, em.lower(), source=self.name,
                                      depth=entity.depth + 1), "harvester"))
                for h in data.get("hosts", []):
                    host = clean_host(h.split(":")[0])
                    if is_valid_domain(host) and in_scope(host, apex_domain(ctx.seed_target)):
                        out.append(Emit.pivot(
                            ctx.child(EntityType.SUBDOMAIN, host, source=self.name,
                                      depth=entity.depth + 1), "harvester"))
        except Exception:  # noqa: BLE001
            pass
        return out


class GitleaksTransform(_Subprocess):
    name = "gitleaks"; display = "Gitleaks (secrets)"
    category = Category.CLOUD
    input_types = (EntityType.CODE_REPO,)
    output_types = (EntityType.LEAKED_SECRET,)
    requires_bin = "gitleaks"; timeout = 180.0

    async def run(self, entity, ctx):
        url = entity.data.get("url") or f"https://github.com/{entity.value}"
        import tempfile, os
        rep = os.path.join(tempfile.gettempdir(), "tr_" + entity.value.replace("/", "_"))
        await self._exec("git", "clone", "--depth", "1", url, rep, timeout=90.0)
        report = rep + "_gl.json"
        await self._exec("gitleaks", "detect", "-s", rep, "-r", report, "--no-git",
                         timeout=120.0)
        out = []
        try:
            if os.path.exists(report):
                findings = json.loads(open(report, encoding="utf-8").read())
                for f in findings[:30]:
                    le = ctx.child(EntityType.LEAKED_SECRET,
                                   f"secret:{entity.value}:{f.get('RuleID','')}:{f.get('StartLine','')}",
                                   source=self.name, depth=entity.depth + 1,
                                   rule=f.get("RuleID", ""), file=f.get("File", ""),
                                   detail=f.get("Description", "secret detected"))
                    le.risk = "critical"
                    le.risk_reason = f"{f.get('RuleID','secret')} in {f.get('File','')}"
                    le.data["display"] = f.get("RuleID", "secret")
                    out.append(Emit.discovered(le, "secret"))
        except Exception:  # noqa: BLE001
            pass
        return out


class S3ScannerTransform(_Subprocess):
    name = "s3scanner"; display = "S3Scanner (buckets)"
    category = Category.CLOUD
    input_types = (EntityType.DOMAIN,)
    output_types = (EntityType.CLOUD_BUCKET,)
    requires_bin = "s3scanner"; timeout = 120.0

    async def run(self, entity, ctx):
        domain = clean_host(entity.value)
        keyword = domain.split(".")[0]
        text = await self._exec("s3scanner", "-bucket", keyword)
        out = []
        for line in text.splitlines():
            if "exists" in line.lower() or "AuthUsers" in line or "AllUsers" in line:
                public = "AllUsers" in line or "open" in line.lower()
                be = ctx.child(EntityType.CLOUD_BUCKET, keyword, source=self.name,
                               depth=entity.depth + 1, public=public, detail=line.strip())
                if public:
                    be.risk = "high"; be.risk_reason = "Publicly accessible S3 bucket."
                out.append(Emit.discovered(be, "bucket"))
                break
        return out


# ------------------------------------------------------------------- helpers
def _hosts_to_emits(lines, entity, ctx, source, edge):
    seed_apex = apex_domain(ctx.seed_target)
    out, seen = [], set()
    for line in lines:
        h = clean_host(line)
        if h and h not in seen and is_valid_domain(h) and in_scope(h, seed_apex):
            seen.add(h)
            et = EntityType.DOMAIN if h == seed_apex else EntityType.SUBDOMAIN
            out.append(Emit.discovered(
                ctx.child(et, h, source=source, depth=entity.depth + 1), edge))
    return out


def register_all(reg) -> None:
    for cls in (CertSpotterTransform, AnubisTransform, HackerTargetTransform,
                WaybackTransform, UrlscanSearchTransform, XposedOrNotTransform,
                RobtexTransform,
                VirusTotalTransform, AbuseIPDBTransform, HIBPTransform,
                HunterTransform, CensysTransform, BuiltWithTransform,
                OTXTransform, GitHubCodeTransform, LeakIXTransform,
                AmassTransform, Sublist3rTransform, DnstwistTransform,
                HttpxTransform, NmapTransform, WhatWebTransform,
                TheHarvesterTransform, GitleaksTransform, S3ScannerTransform):
        try:
            reg.register(cls())
        except Exception:  # noqa: BLE001
            pass
