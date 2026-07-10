# TOP RECON — Build Specification

> **How to use this file:** In Claude Code, run a goal that points here, e.g.
> `/goal Build the application exactly as specified in TOP_RECON_BUILD_SPEC.md. Read the whole file first, then follow the build approach at the bottom. The attached image is the dashboard design target.`
> Attach the HIVED "Recon Automata" dashboard screenshot alongside that goal. Claude Code already has the HiveDefend project in context.

---

## GOAL

Build a complete PyQt6 desktop application called **TOP RECON** — an authorized **organizational attack-surface reconnaissance platform**. The attached image is the exact visual design target for the main dashboard: match its dark cyber aesthetic, layout, color-coded entity graph, module panels, live feed, and metrics tiles.

Take structural and stylistic inspiration from the **HiveDefend** project already studied in this session: the topology visualization, panel architecture, dark enterprise-SIEM look, and the `.ui` + `.py` PyQt6 file-pairing approach.

**Do NOT compile to `.exe`.** Leave it as runnable Python source.

---

## SCOPE (READ FIRST — THIS IS A DEFENSIVE / AUTHORIZED-RECON TOOL)

TOP RECON targets **ORGANIZATIONS and their INFRASTRUCTURE ONLY** — domains, subdomains, DNS, certificates, exposed services, technology stacks, cloud buckets, code/secret leaks, and brand-impersonation domains. It is built for a security team assessing their **own** external attack surface, or an authorized engagement.

Build in a mandatory **Authorization Gate** on startup: before any scan runs, the user must enter the target organization/domain **AND** tick a checkbox confirming they own the target or have written authorization to test it. Log this attestation (timestamp + target) to a local audit file. No scan module runs until the gate is satisfied. Add a persistent banner showing the authorized target scope.

**Do NOT implement any person-targeting capability:** no people-search, no family-tree/relatives, no phone-number-to-identity, no facial recognition, no username-to-person dossier building. This tool maps org infrastructure, not individuals. If a tool has both org and person modes, wire only its org/domain functionality.

---

## ARCHITECTURE: THE "HIVE" PIVOT ENGINE

The core is an entity-driven pivot engine (like SpiderFoot / Maltego transforms). Model every finding as a typed **ENTITY**, and every tool as a **TRANSFORM** that consumes one entity type and produces others. When a tool outputs a new entity, it is automatically queued as input to every tool that accepts that entity type — this is the "hive mind" auto-pivoting.

**Entity types:** Domain, Subdomain, IP Address, ASN, Netblock, DNS Record, SSL/TLS Certificate, Open Port, Service/Banner, Web Technology, URL, Email Address (org domain only), Cloud Bucket, Code Repository, Leaked Secret, Breach Record (org-domain only), Lookalike/Typosquat Domain, WHOIS Record, Company/Org.

Build the engine as:
1. An **ENTITY GRAPH** data model (nodes + typed edges: `discovered` vs `pivot`).
2. A **TRANSFORM REGISTRY** where each tool declares `input_types` and `output_types`.
3. An async **TASK QUEUE / worker pool** that runs transforms concurrently with rate limiting.
4. A **DEPTH tracker** (Seed=0, Direct=1, Indirect=2, Pivoted=3, Deep=4) with a configurable max-depth cap.
5. A **PIVOT QUEUE** showing pending transforms (entity → tool → status), exactly like the reference image's "PIVOT QUEUE" panel.

Deduplicate entities (same domain/IP/cert discovered by multiple tools = one node with multiple source edges). Track provenance: every entity records which transform(s) discovered it.

---

## TOOLS TO INTEGRATE (organize into these transform modules)

Integrate real tools via subprocess wrappers, official Python libraries, or public APIs. For each, write a proper parser that converts raw output into typed entities. Where a tool needs an API key, read it from a local `.env` / config panel and degrade gracefully if absent (mark module "Needs Key"). Aim for a genuinely impressive module count (target the "28 modules" density shown in the reference image). You MAY add more tools beyond these if they fit the org-recon scope and strengthen the pivot graph. Do NOT add person-targeting tools.

### Domain & DNS Intelligence
- **whois / python-whois** (Domain → WHOIS Record, registrar, dates, nameservers)
- **dig / dnspython** (Domain → DNS Records: A, AAAA, MX, NS, TXT, CNAME, SOA)
- **dnsrecon** (Domain → DNS records, zone-transfer attempts)
- **dnstwist** (Domain → Typosquat/Lookalike Domains — brand impersonation detection)
- **Robtex / passive DNS** (IP ↔ Domain relationships)

### Subdomain Enumeration
- **subfinder** (Domain → Subdomains — passive, fast)
- **OWASP Amass** (Domain → Subdomains + IPs + related domains — comprehensive)
- **Sublist3r** (Domain → Subdomains via search engines)
- **crt.sh Certificate Transparency** (Domain → Subdomains via logged certs)
- **KnockPy / gobuster dns** (Domain → brute-forced Subdomains via wordlist)

### Certificate Intelligence
- **crt.sh + Censys certs** (Domain → SSL Certificates → more Subdomains)
- **testssl.sh** (Host → TLS config, cipher/protocol weaknesses)

### Host / Service / Port Discovery
- **Shodan API** (IP/Domain → open ports, services, banners, known CVEs)
- **Censys API** (IP/Domain → hosts, services, certs)
- **ZoomEye API** (IP/Domain → services — alternative source)
- **Nmap / python-nmap** (IP → open Ports, Service/Banner, OS guess — **ACTIVE**, gated behind an explicit "active scan" confirmation since it touches the target directly)
- **httpx** (Subdomain → live hosts, status codes, titles, tech)

### Web Technology Fingerprinting
- **Wappalyzer / python-Wappalyzer** (URL → Web Technologies)
- **BuiltWith API** (Domain → tech stack)
- **WhatWeb** (URL → technologies, versions)

### Email & Public Footprint (ORG DOMAIN ONLY)
- **theHarvester** (Domain → org emails, subdomains, hosts from public sources)
- **Hunter.io API** (Domain → email pattern + org email addresses)

### Breach / Credential Exposure (ORG DOMAIN ONLY — the org's own domain)
- **Have I Been Pwned API** (org domain → breaches affecting that domain)
- **Dehashed / LeakIX API** (org domain/asset → exposed data — key-gated)
- **XposedOrNot** (org domain → breach exposure)

### Cloud & Code / Secret Leaks
- **S3Scanner** (Org/Domain keywords → open S3 buckets)
- **ScoutSuite** (authorized cloud account → misconfig audit — clearly marked "your own cloud only")
- **TruffleHog / Gitleaks** (org GitHub repos → leaked secrets/keys in code & git history)
- **GitHub code search API** (org name/domain → exposed configs/keys in public repos)

### Brand / Impersonation Monitoring
- **dnstwist** (typosquats — cross-listed)
- **URLScan.io API** (suspicious lookalike URL → screenshot, network, IOCs)
- **CheckPhish** (lookalike domain → phishing verdict)
- **Wayback Machine / archive.org** (Domain → historical snapshots, previously exposed content)

### Threat-Intel Enrichment (enrich discovered IPs/domains)
- **VirusTotal API** (IP/Domain/URL → reputation, associations)
- **AbuseIPDB API** (IP → abuse reports)
- **AlienVault OTX API** (IP/Domain → threat pulses)

---

## GUI REQUIREMENTS (match the reference image)

**Top bar:** app logo "TOP RECON", engine name/version, live status (RUNNING/IDLE), Depth (x/max), Entities Discovered, Requests, Success Rate, Elapsed timer, node label, throughput req/s.

**LEFT COLUMN:**
- **INPUT SEED** panel (the authorized target — domain/org — with the authorization state).
- **ENTITY TYPES** list with live counts per type (Domain, Subdomain, IP, Cert, Port, Email, Cloud Bucket, Leak, Typosquat, etc.) — clicking a type **FILTERS** the graph.
- **DISCOVERY DEPTH** bars (Seed → Deep) with counts.
- **LIVE FEED:** streaming timestamped log of discoveries and pivots (e.g. "Subdomain discovered: api.target.com", "Pivot: Domain → Cert Enum").

**CENTER: ENTITY GRAPH — the centerpiece.** A force-directed / auto-layout network graph with the seed domain at the center, color-coded nodes by entity type (match the image's legend: Domain, IP, Cert, Port, Subdomain, Email, etc.), solid edges = `discovered`, dashed edges = `pivot`. Interactive: pan/zoom, click a node to see its details + which transforms are queued for it, auto-layout button, fullscreen, filter button. Same topology concept as HiveDefend's node graph — reuse that approach with the domain as the root instead of a person.

**RIGHT COLUMN:**
- **ACTIVE MODULES** panel: every transform module with a live status (Running/Queued/Idle/Needs Key) and a running hit-count, exactly like the image.
- **PIVOT QUEUE** panel: table of pending pivots (Entity | From-type | Tool | Status).
- **RECENT DISCOVERIES** feed.

**BOTTOM: INTELLIGENCE SUMMARY strip** — Top Discovered Subdomains, Top Services/Ports, Top Data Sources (by hit count), and a **CONFIDENCE SCORE** gauge based on volume/quality of findings. Plus an engine status footer (workers, rate limit, memory, CPU, uptime).

---

## REQUIRED FEATURES

1. **SUMMARY BUTTON** — opens a clean summary report of everything found (counts per entity type, key exposures, top risks) exportable to HTML/PDF/JSON.
2. **DASHBOARD FILTERS** — the entity-type list acts as live filters on the graph and on a detail-table view. Filters MUST include at minimum: Subdomains, IP Addresses, DNS Records, SSL Certificates, Open Ports/Services, Web Technologies, Emails (org), Cloud Buckets, Code/Secret Leaks, Breach Exposure, Typosquat/Impersonation Domains, WHOIS — and add more relevant ones (do not stop at this list).
3. **GOOGLE-COMPARISON TOGGLE** — a switch that flips the main view between:
   - **(a) "Plain Google Search" mode:** what a normal person gets — run the org name/domain as a standard Google query (via the official Custom Search API, or open results in an embedded view) showing the handful of surface links.
   - **(b) "TOP RECON" mode:** the full fused entity graph + all module results.
   - The contrast between the two is the demo centerpiece — make it dramatic and obvious. Add a side-by-side "before/after" view option.
4. **DETAIL DRILL-DOWN** — clicking any entity opens a panel with all data collected about it and its relationships.
5. **SCAN PROFILES** — save/load target profiles; scan history with timestamps.
6. **EXPORT** — full results to JSON, plus a polished HTML report and PDF.
7. **GRACEFUL DEGRADATION** — any tool that's missing/unconfigured shows as "Needs Key" or "Not Installed" without crashing the app; the engine continues with available modules.
8. **CONCURRENCY + RATE LIMITING** — async worker pool, per-source rate limits, a global requests/min cap shown in the footer.
9. **ACTIVE vs PASSIVE separation** — passive modules (certs, passive DNS, APIs) run freely; ACTIVE modules that directly touch the target (Nmap, httpx probing, brute-force) require a separate explicit confirmation and are clearly flagged.

---

## ADD THESE (beyond the basics)

- A **"Kill Chain / Attack Surface Risk" panel** that categorizes findings by risk (exposed admin panels, expired/weak certs, open sensitive ports, leaked secrets, subdomain-takeover candidates, publicly exposed buckets) with severity coloring.
- **Subdomain-takeover detection** (dangling CNAME check on discovered subdomains).
- A **timeline view** of when each entity was discovered during the scan.
- A **"diff since last scan"** feature so re-scanning a target highlights NEW exposures.
- **MITRE-style mapping note** on each finding category (which reconnaissance technique it maps to) for the educational/demo audience.
- A **demo/replay mode** that can replay a saved scan step-by-step for presenting to a non-technical audience.

---

## BUILD APPROACH

- **PyQt6**, `QMainWindow` + `QDockWidgets` for panels, `.ui` + `.py` file pairing where sensible.
- Use **pyqtgraph** and a graph library (**networkx** for the model; render the interactive graph with a Qt-friendly approach) for the entity graph and metrics.
- **asyncio + qasync** so the GUI never blocks; all scanning is async/background with signals updating the UI.
- Clean modular structure:
  - `/core` — entity model, graph, pivot engine, task queue
  - `/transforms` — one module per tool with declared input/output entity types + parser
  - `/gui` — panels, widgets, styles
  - `/reports` — export (JSON/HTML/PDF)
  - `/config` — `.env`, API keys, wordlists
  - `/profiles` — saved targets & scan history
  - `/audit` — authorization attestations & run logs
- Match the reference image's dark theme precisely (near-black background, teal/green accents, octagon node styling, monospace metrics).
- **Production-grade:** error handling on every subprocess/API call, timeouts, input validation on the target, no hardcoded secrets.

### Order of work
1. Scaffold the full project structure and the **core entity/pivot engine**.
2. Build the **transform registry** with **3–4 tools end-to-end** (whois, subfinder, crt.sh, Shodan) so the pivot loop works.
3. Build the **GUI shell** matching the image.
4. Wire the rest of the modules in.

**Show me the structure and the core engine first before writing every transform.**
