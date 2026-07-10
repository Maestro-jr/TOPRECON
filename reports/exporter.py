"""
Export a completed scan: JSON (full graph), a polished HTML report, and PDF.

PDF uses reportlab when available; otherwise it writes the same report as
print-ready HTML and tells the caller to "Print → Save as PDF" (graceful
degradation — never a hard dependency).
"""

from __future__ import annotations

import html
import json
import time
from collections import Counter
from pathlib import Path
from typing import Optional

from core.entities import EntityType, ENTITY_META
from core.risk import analyze, summarize


def export_json(graph, path: Path, meta: dict) -> Path:
    payload = {"tool": "TOP RECON", "generated": time.time(),
               "meta": meta, "graph": graph.to_dict(),
               "findings": [f.__dict__ for f in analyze(graph)]}
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def _report_html(graph, meta: dict) -> str:
    counts = graph.counts_by_type()
    findings = analyze(graph)
    sev = summarize(findings)
    target = meta.get("target", "—")
    gen = time.strftime("%Y-%m-%d %H:%M:%S")

    rows = "".join(
        f"<tr><td><span class='dot' style='color:{ENTITY_META[t].color}'>&#9679;</span> "
        f"{ENTITY_META[t].label}</td><td class='num'>{counts.get(t,0)}</td></tr>"
        for t in EntityType if counts.get(t, 0))

    frows = "".join(
        f"<tr class='sev-{f.severity}'><td>{f.severity.upper()}</td>"
        f"<td>{html.escape(f.category)}</td><td>{html.escape(f.entity_value)}</td>"
        f"<td>{html.escape(f.detail)}</td>"
        f"<td>{html.escape(f.mitre_id)} {html.escape(f.mitre_name)}</td></tr>"
        for f in findings) or "<tr><td colspan='5'>No risks flagged.</td></tr>"

    subs = [e.value for e in graph.entities(EntityType.SUBDOMAIN)][:40]
    sub_list = "".join(f"<li>{html.escape(s)}</li>" for s in subs) or "<li>none</li>"

    return f"""<!doctype html><html><head><meta charset='utf-8'>
<title>TOP RECON Report — {html.escape(target)}</title><style>
 body{{background:#0a0e14;color:#cfe0ea;font-family:'Segoe UI',sans-serif;margin:0;padding:32px;}}
 h1{{color:#00e676;font-family:monospace;letter-spacing:3px;margin:0;}}
 h2{{color:#26c6da;font-family:monospace;border-bottom:1px solid #16212f;padding-bottom:6px;margin-top:32px;}}
 .tag{{color:#5f7688;font-family:monospace;font-size:12px;}}
 table{{border-collapse:collapse;width:100%;font-family:monospace;font-size:13px;}}
 td,th{{border-bottom:1px solid #16212f;padding:6px 10px;text-align:left;}}
 .num{{text-align:right;color:#fff;font-weight:700;}}
 .cards{{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0;}}
 .card{{background:#0b111b;border:1px solid #16212f;border-radius:6px;padding:14px 20px;}}
 .card .v{{font-size:26px;font-weight:800;font-family:monospace;}}
 .card .l{{font-size:10px;color:#5f7688;letter-spacing:2px;}}
 .sev-critical td:first-child{{color:#ff4d5e;font-weight:700;}}
 .sev-high td:first-child{{color:#ff8a3c;font-weight:700;}}
 .sev-medium td:first-child{{color:#e3c341;}}
 .sev-low td:first-child{{color:#3fd07f;}}
 ul{{columns:3;font-family:monospace;font-size:12px;color:#9fb3c2;}}
</style></head><body>
<h1>TOP RECON</h1>
<div class='tag'>Authorized attack-surface reconnaissance &middot; Target: {html.escape(target)} &middot; Generated {gen}</div>
<div class='cards'>
 <div class='card'><div class='v' style='color:#00e676'>{len(graph)}</div><div class='l'>ENTITIES</div></div>
 <div class='card'><div class='v' style='color:#2fe0b0'>{counts.get(EntityType.SUBDOMAIN,0)}</div><div class='l'>SUBDOMAINS</div></div>
 <div class='card'><div class='v' style='color:#ff6b6b'>{counts.get(EntityType.IP_ADDRESS,0)}</div><div class='l'>IP ADDRESSES</div></div>
 <div class='card'><div class='v' style='color:#ff9a00'>{counts.get(EntityType.PORT,0)}</div><div class='l'>OPEN PORTS</div></div>
 <div class='card'><div class='v' style='color:#ff4d5e'>{sev.get('critical',0)+sev.get('high',0)}</div><div class='l'>HIGH+ RISKS</div></div>
</div>
<h2>Entity Breakdown</h2><table><tr><th>Type</th><th class='num'>Count</th></tr>{rows}</table>
<h2>Attack-Surface Risks &amp; MITRE Recon Mapping</h2>
<table><tr><th>Severity</th><th>Category</th><th>Entity</th><th>Detail</th><th>MITRE ATT&amp;CK</th></tr>{frows}</table>
<h2>Discovered Subdomains ({len(subs)} shown)</h2><ul>{sub_list}</ul>
</body></html>"""


def export_html(graph, path: Path, meta: dict) -> Path:
    path.write_text(_report_html(graph, meta), encoding="utf-8")
    return path


def export_pdf(graph, path: Path, meta: dict) -> tuple[Path, bool]:
    """Return (path, is_pdf). Falls back to HTML if no PDF engine is present."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
    except Exception:  # noqa: BLE001
        alt = path.with_suffix(".html")
        export_html(graph, alt, meta)
        return alt, False

    counts = graph.counts_by_type()
    findings = analyze(graph)
    c = canvas.Canvas(str(path), pagesize=A4)
    w, h = A4
    y = h - 2 * cm
    c.setFillColorRGB(0, 0.9, 0.46)
    c.setFont("Helvetica-Bold", 20); c.drawString(2 * cm, y, "TOP RECON")
    y -= 0.8 * cm
    c.setFillColorRGB(0.4, 0.5, 0.55); c.setFont("Helvetica", 10)
    c.drawString(2 * cm, y, f"Target: {meta.get('target','—')}   "
                 f"Generated: {time.strftime('%Y-%m-%d %H:%M')}")
    y -= 1 * cm
    c.setFillColorRGB(0.85, 0.9, 0.93); c.setFont("Helvetica-Bold", 13)
    c.drawString(2 * cm, y, "Entity Breakdown"); y -= 0.6 * cm
    c.setFont("Helvetica", 10)
    for t in EntityType:
        if counts.get(t, 0):
            c.drawString(2.4 * cm, y, f"{ENTITY_META[t].label}: {counts[t]}")
            y -= 0.5 * cm
            if y < 3 * cm:
                c.showPage(); y = h - 2 * cm
    y -= 0.4 * cm
    c.setFont("Helvetica-Bold", 13); c.drawString(2 * cm, y, "Top Risks"); y -= 0.6 * cm
    c.setFont("Helvetica", 9)
    for f in findings[:30]:
        c.drawString(2.4 * cm, y, f"[{f.severity.upper()}] {f.category}: {f.entity_value}")
        y -= 0.45 * cm
        if y < 3 * cm:
            c.showPage(); y = h - 2 * cm
    c.showPage(); c.save()
    return path, True
