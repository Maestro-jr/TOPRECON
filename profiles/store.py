"""
Scan profiles & history.

Every completed scan is snapshotted to ``profiles/<apex>/<timestamp>.json``.
This powers scan history, the "diff since last scan" feature (new exposures
highlighted on a re-scan), and demo/replay mode (step through a saved scan).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional


def _apex_dir(profiles_dir: Path, apex: str) -> Path:
    d = profiles_dir / apex.replace("/", "_")
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_snapshot(profiles_dir: Path, apex: str, graph, meta: dict) -> Path:
    d = _apex_dir(profiles_dir, apex)
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = d / f"{ts}.json"
    payload = {"apex": apex, "saved": time.time(), "ts": ts,
               "meta": meta, "graph": graph.to_dict()}
    path.write_text(json.dumps(payload, default=str), encoding="utf-8")
    return path


def list_snapshots(profiles_dir: Path, apex: str) -> list[dict]:
    """Return snapshot summaries for an apex, newest first."""
    d = _apex_dir(profiles_dir, apex)
    out = []
    for p in sorted(d.glob("*.json"), reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        nodes = data.get("graph", {}).get("nodes", [])
        out.append({"path": str(p), "ts": data.get("ts", p.stem),
                    "saved": data.get("saved", 0), "entities": len(nodes),
                    "apex": data.get("apex", apex)})
    return out


def load_snapshot(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def previous_snapshot(profiles_dir: Path, apex: str) -> Optional[dict]:
    """The most recent saved snapshot (before the current run), or None."""
    snaps = list_snapshots(profiles_dir, apex)
    return load_snapshot(snaps[0]["path"]) if snaps else None


def diff_against(prev: dict, graph) -> dict:
    """Return {'new': [...], 'removed': [...]} entity keys vs a previous snapshot."""
    prev_keys = {n["key"] for n in prev.get("graph", {}).get("nodes", [])}
    cur_nodes, _ = graph.snapshot()
    cur_keys = {e.key for e in cur_nodes}
    new = sorted(cur_keys - prev_keys)
    removed = sorted(prev_keys - cur_keys)
    new_ents = [e for e in cur_nodes if e.key in set(new)]
    return {"new": new, "removed": removed,
            "new_entities": new_ents,
            "prev_ts": prev.get("ts", "?"),
            "prev_count": len(prev_keys), "cur_count": len(cur_keys)}
