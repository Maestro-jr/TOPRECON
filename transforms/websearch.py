"""Google Custom Search helper for the comparison view (org-surface links only)."""

from __future__ import annotations

from .common import http_client


async def fetch_google(settings, query: str) -> tuple[list[dict], str]:
    """Return (results, note). Empty results + a note if no key is configured."""
    key = settings.get_key("google_cse")
    cx = settings.get_key("google_cx")
    if not (key and cx):
        return [], ("No Google Custom Search key configured. Set GOOGLE_CSE_KEY "
                    "and GOOGLE_CSE_CX in config/.env to fetch live surface links. "
                    "This is the 'handful of links' a normal search returns — "
                    "contrast it with the fused graph on the right.")
    try:
        resp = await http_client().get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": key, "cx": cx, "q": query, "num": 10}, timeout=20.0)
        data = resp.json()
        items = data.get("items", []) or []
        results = [{"title": it.get("title", ""), "link": it.get("link", ""),
                    "snippet": it.get("snippet", "")} for it in items]
        total = data.get("searchInformation", {}).get("formattedTotalResults", "")
        return results, f"~{total} total results indexed by Google" if total else ""
    except Exception as exc:  # noqa: BLE001
        return [], f"Google search failed: {exc}"
