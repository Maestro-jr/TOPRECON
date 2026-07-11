# TOP RECON

**Authorized organizational attack-surface reconnaissance platform.**

TOP RECON maps an organization's *own* external attack surface — domains,
subdomains, DNS, certificates, exposed services, technology stacks, cloud
buckets, code/secret leaks, and brand-impersonation domains — and fuses every
source into one live **entity graph** via an auto-pivoting "hive-mind" engine.

> It targets **organizational infrastructure only** and performs **no
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

Requires Python 3.10+. This is runnable Python source — it is **not** packaged
to an executable.

---

## API keys (optional)

**No keys are required to get started.** ~10 modules run out of the box (crt.sh,
CertSpotter, AnubisDB, HackerTarget, URLScan search, Wayback, Robtex passive DNS,
XposedOrNot, plus WHOIS + DNS). Additional key-gated sources light up when you
add a key; a source with no key simply shows **“Needs Key”** and is skipped.

You enter your **own** keys in either of two places — both land in the same
git-ignored `config/.env`:

- **In-app:** click **⚿ KEYS** in the title bar, paste your keys, and Save. They
  are written to `config/.env` and applied to the running session immediately
  (keyed modules flip from “Needs Key” to “Idle” without a restart).
- **File:** copy `config/.env.example` to `config/.env` and fill in what you have.

`config/.env` is in `.gitignore` and is never committed. No secret is hardcoded.

| Source | Env var | Unlocks |
|---|---|---|
| Shodan | `SHODAN_API_KEY` | Open ports, services, banners, CVEs |
| VirusTotal | `VIRUSTOTAL_API_KEY` | IP / domain reputation & associations |
| Have I Been Pwned | `HIBP_API_KEY` | Breaches affecting the org domain |
| Hunter.io | `HUNTER_API_KEY` | Org email addresses & patterns |
| GitHub | `GITHUB_TOKEN` | Code search for exposed secrets / configs |
| URLScan.io | `URLSCAN_API_KEY` | Lookalike / suspicious URL scans |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` | Hosts, services, certificates |
| ZoomEye | `ZOOMEYE_API_KEY` | Alternative host / service source |
| BuiltWith | `BUILTWITH_API_KEY` | Domain technology stack |
| DeHashed / LeakIX | `DEHASHED_API_KEY`, `LEAKIX_API_KEY` | Exposed credential data & leaks |
| CheckPhish | `CHECKPHISH_API_KEY` | Phishing verdict on lookalike domains |
| AbuseIPDB / OTX | `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | IP abuse reports & threat pulses |
| Google CSE | `GOOGLE_CSE_KEY`, `GOOGLE_CSE_CX` | The Google-comparison view |

Some modules are external command-line tools (subfinder, amass, dnstwist, nmap,
httpx, whatweb, gitleaks, …). Install them separately and put them on your
`PATH`; any that are missing show **“Not Installed”** and are skipped.

---

## Using the dashboard

- **⚿ KEYS** (title bar) — enter / update API keys (see above).
- **＋ NEW RECON** (title bar) — switch to a **new target without restarting**:
  it reopens the Authorization Gate, and once you re-attest, resets the whole
  console and scans the new scope.
- **⏸ PAUSE / ▶ RESUME** — halt and continue outgoing requests at any time.
- **⏹ STOP** — end the scan entirely; no further requests are sent.
- **Summary / Export** — a full report (counts, exposures, top risks) exportable
  to JSON / HTML / PDF.
- **History** — reload past scans, diff against the last scan, and replay a scan
  step-by-step.
- The window is frameless with its own title bar; drag it to move, double-click
  to maximize, and use the corner grip to resize.

### Reading the entity graph

The central graph is a **relationship map**, not just connected dots:

- **Node colour** = entity type; **node size** grows with risk and connectivity,
  so exposed and highly-connected assets stand out.
- **Solid edge** = a directly observed relationship; **dashed edge** = an
  inferred / pivoted one. Each edge is **typed** — `resolves`, `exposes`, `runs`,
  `presents` (cert), `CNAME→`, `MX`, `SAN`, `look-alike`, … — with a direction
  arrow. Hover an edge, or toggle **Relations**, to label them.
- **Click a node** to trace and highlight its **exposure path from the seed**
  (e.g. `acme.com → vpn.acme.com → 93.184.1.1 → :3389/RDP`), dimming everything
  else. Click empty space to clear.
- The left **ENTITY TYPES** list filters the graph; **DISCOVERY DEPTH** shows how
  far each finding is from the seed.

---

## Architecture

```
core/         Entity model, dedup graph, transform registry, async pivot engine,
              rate limiter, attack-surface risk + MITRE recon mapping.
transforms/   30 tool wrappers (one per module); each declares the entity types
              it consumes / produces so the engine auto-pivots.
gui/          PyQt6 dashboard — frameless shell + title bar, entity graph,
              module / queue panels, live feed, intelligence summary,
              risk / detail / timeline, Google-comparison view, history / replay,
              API-keys dialog.
reports/      JSON / HTML / PDF export.
config/       .env (API keys) + wordlists.
profiles/     Saved scans (history, diff-since-last-scan, replay).
audit/        Authorization attestations + run events.
```

### The pivot engine

Every finding is a typed **Entity**. Every tool is a **Transform** declaring its
`input_types` and `output_types`. When a transform emits a new entity, the engine
auto-queues it into every transform that accepts that type — deduping, tracking
provenance and discovery depth (Seed → Direct → Indirect → Pivoted → Deep),
rate-limiting globally and per-source, and running everything concurrently
(asyncio + qasync, so the GUI never blocks).

**Passive** modules run freely; **active** modules (Nmap, httpx probing,
brute-force) only run when active scanning was explicitly authorized at the gate.

---

## Features

- Interactive force-directed **entity relationship graph** — typed, directional
  edges; click-to-trace exposure paths; risk/connectivity-scaled nodes;
  pan / zoom / filter.
- Live **ENTITY TYPES filters**, **DISCOVERY DEPTH** ladder, **LIVE FEED**,
  **ACTIVE MODULES**, **PIVOT QUEUE**, **RECENT DISCOVERIES**, and an
  **INTELLIGENCE SUMMARY** with a confidence gauge.
- **Attack-Surface Risk** panel: exposed sensitive ports, known-CVE services,
  subdomain-takeover candidates, expired / weak certs, leaked secrets, public
  buckets, breach & brand-impersonation exposure — each mapped to a MITRE
  ATT&CK reconnaissance technique.
- **Google-comparison** view: what a plain search surfaces vs. the full fused
  attack surface.
- In-app **API-keys** entry, **New Recon** target switching, and
  **Pause / Resume / Stop** request controls.
- **Export** to JSON / HTML / PDF, **scan history**, **diff since last scan**, and
  a **demo / replay** mode that plays a saved scan back step-by-step.
- **Graceful degradation**: any missing key or tool shows “Needs Key” /
  “Not Installed” and is skipped — the engine continues with what's available.

---

## Legal

Use only against assets you own or are explicitly authorized to test.
Authorization attestations are logged to `data/audit/`.
