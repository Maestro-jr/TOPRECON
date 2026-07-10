# TOP RECON

**Authorized organizational attack-surface reconnaissance platform.**

TOP RECON maps an organization's *own* external attack surface — domains,
subdomains, DNS, certificates, exposed services, technology stacks, cloud
buckets, code/secret leaks, and brand-impersonation domains — and fuses every
source into one live **entity graph** via an auto-pivoting "hive mind" engine.

> It targets **organizational infrastructure only**. It performs **no
> person-targeting** of any kind. A mandatory Authorization Gate requires you to
> attest ownership or written authorization before any scan runs; every
> attestation is written to an audit log.

---

## Run

```bash
pip install -r requirements.txt
python run.py
```

1. The **Authorization Gate** opens. Enter the target domain, tick the
   authorization attestation, optionally enable **active scanning** (tools that
   directly touch the target), and launch.
2. The dashboard opens and the scan begins automatically, streaming discoveries
   into the entity graph, module panels, live feed, and intelligence summary.

No API keys are required to get started — several modules (crt.sh, CertSpotter,
AnubisDB, HackerTarget, URLScan search, Wayback, Robtex passive DNS, XposedOrNot,
plus WHOIS + DNS) run out of the box. Add keys in `config/.env` (copy
`config/.env.example`) to light up the key-gated sources.

---

## Architecture

```
core/         Entity model, dedup graph, transform registry, async pivot engine,
              rate limiter, attack-surface risk + MITRE recon mapping.
transforms/   30 tool wrappers (one per module); each declares the entity types
              it consumes/produces so the engine auto-pivots.
gui/          PyQt6 dashboard — top-bar metrics, entity graph, module/queue
              panels, live feed, intelligence summary, risk/detail/timeline,
              Google-comparison view, history/diff/replay.
reports/      JSON / HTML / PDF export.
config/       .env (API keys) + wordlists.
profiles/     Saved scans (history, diff-since-last-scan, replay).
audit/        Authorization attestations + run events.
```

### The pivot engine
Every finding is a typed **Entity**. Every tool is a **Transform** declaring its
`input_types` and `output_types`. When a transform emits a new entity, the
engine auto-queues it into every transform that accepts that type — deduping,
tracking provenance and discovery depth (Seed→Direct→Indirect→Pivoted→Deep),
rate-limiting globally and per-source, and running everything concurrently.

**Passive** modules run freely; **active** modules (Nmap, httpx, brute force)
only run when active scanning was explicitly authorized at the gate.

---

## Features

- Interactive force-directed **entity graph** (octagon nodes colour-coded by
  type; solid = discovered, dashed = pivot; pan/zoom/click-to-drill-down).
- Live **ENTITY TYPES filters**, **DISCOVERY DEPTH** ladder, **LIVE FEED**,
  **ACTIVE MODULES**, **PIVOT QUEUE**, **RECENT DISCOVERIES**,
  **INTELLIGENCE SUMMARY** + confidence gauge.
- **Attack-Surface Risk** panel: exposed sensitive ports, known-CVE services,
  subdomain-takeover candidates, expired/weak certs, leaked secrets, public
  buckets, breach & brand-impersonation exposure — each mapped to a MITRE
  ATT&CK reconnaissance technique.
- **Google-comparison** view: what a plain search surfaces vs. the full fused
  attack surface.
- **Export** to JSON / HTML / PDF, **scan history**, **diff since last scan**,
  and a **demo/replay** mode that plays a saved scan back step-by-step.
- **Graceful degradation**: any missing key or tool shows "Needs Key" /
  "Not Installed" and is skipped — the engine continues with what's available.

---

## Legal

Use only against assets you own or are explicitly authorized to test.
Authorization attestations are logged to `data/audit/`.
