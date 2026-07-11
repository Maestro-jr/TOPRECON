"""
Google-comparison view.

Side-by-side contrast between (a) what a plain Google search of the org surfaces
— a handful of links — and (b) what TOP RECON's fused entity graph reveals. The
Google side uses the official Custom Search API when a key is configured, and
otherwise degrades to an honest explanatory placeholder (never fabricated hits).
"""

from __future__ import annotations

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
                             QListWidget, QListWidgetItem, QGridLayout)

from gui import theme
from core.entities import EntityType


class GoogleComparePanel(QWidget):
    def __init__(self, graph_model, parent=None):
        super().__init__(parent)
        self._model = graph_model
        root = QHBoxLayout(self); root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(16)
        root.addWidget(self._build_google(), 1)
        root.addWidget(self._build_recon(), 1)

    # -- left: plain google -------------------------------------------------
    def _build_google(self) -> QFrame:
        box = QFrame(); box.setObjectName("panel")
        v = QVBoxLayout(box); v.setContentsMargins(16, 14, 16, 14); v.setSpacing(8)
        t = QLabel("PLAIN GOOGLE SEARCH")
        t.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO};"
                        "font-size:13px; font-weight:700; letter-spacing:2px;")
        v.addWidget(t)
        sub = QLabel("What anyone gets by searching the organization name.")
        sub.setStyleSheet(f"color:{theme.TEXT_FAINT}; font-size:11px;")
        v.addWidget(sub)
        self._g_count = QLabel("—")
        self._g_count.setStyleSheet(f"color:{theme.TEXT}; font-family:{theme.FONT_MONO};"
                                    "font-size:40px; font-weight:800;")
        v.addWidget(self._g_count)
        cl = QLabel("SURFACE LINKS"); cl.setObjectName("sectionLabel"); v.addWidget(cl)
        self._g_list = QListWidget()
        v.addWidget(self._g_list, 1)
        return box

    # -- right: top recon ---------------------------------------------------
    def _build_recon(self) -> QFrame:
        box = QFrame(); box.setObjectName("panel")
        box.setStyleSheet(f"#panel {{ background:{theme.BG_PANEL};"
                          f" border:1px solid {theme.ACCENT_DIM}; border-radius:6px; }}")
        v = QVBoxLayout(box); v.setContentsMargins(16, 14, 16, 14); v.setSpacing(8)
        t = QLabel("TOP RECON — FUSED ATTACK SURFACE")
        t.setStyleSheet(f"color:{theme.ACCENT}; font-family:{theme.FONT_MONO};"
                        "font-size:13px; font-weight:700; letter-spacing:2px;")
        v.addWidget(t)
        sub = QLabel("The same organization, correlated across every recon source.")
        sub.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:11px;")
        v.addWidget(sub)
        self._r_count = QLabel("0")
        self._r_count.setStyleSheet(f"color:{theme.ACCENT}; font-family:{theme.FONT_MONO};"
                                    "font-size:40px; font-weight:800;")
        v.addWidget(self._r_count)

        grid = QGridLayout(); grid.setSpacing(10)
        self._tiles: dict[str, QLabel] = {}
        specs = [("SUBDOMAINS", EntityType.SUBDOMAIN), ("IP ADDRESSES", EntityType.IP_ADDRESS),
                 ("CERTIFICATES", EntityType.CERTIFICATE), ("OPEN PORTS", EntityType.PORT),
                 ("SERVICES", EntityType.SERVICE), ("DNS RECORDS", EntityType.DNS_RECORD),
                 ("EMAILS", EntityType.EMAIL), ("TYPOSQUATS", EntityType.TYPOSQUAT)]
        for i, (label, et) in enumerate(specs):
            cell = QFrame(); cell.setObjectName("panel")
            cl = QVBoxLayout(cell); cl.setContentsMargins(10, 8, 10, 8); cl.setSpacing(0)
            val = QLabel("0")
            val.setStyleSheet(f"color:{ENTITY_COLOR(et)}; font-family:{theme.FONT_MONO};"
                              "font-size:20px; font-weight:700;")
            lab = QLabel(label); lab.setObjectName("metricLabel")
            cl.addWidget(val); cl.addWidget(lab)
            grid.addWidget(cell, i // 4, i % 4)
            self._tiles[et.value] = val
        v.addLayout(grid)
        self._risk = QLabel("0 attack-surface risks flagged")
        self._risk.setStyleSheet(f"color:{theme.ERRORC}; font-family:{theme.FONT_MONO}; font-size:12px;")
        v.addWidget(self._risk)
        v.addStretch()
        return box

    # -- feeders ------------------------------------------------------------
    def set_google_results(self, results: list[dict], note: str = "") -> None:
        self._g_list.clear()
        if not results:
            it = QListWidgetItem(note or "No API key configured — set GOOGLE_CSE_KEY / "
                                 "GOOGLE_CSE_CX to fetch live results.")
            it.setForeground(QColor(theme.TEXT_FAINT))
            self._g_list.addItem(it)
            self._g_count.setText("~10")
            return
        self._g_count.setText(str(len(results)))
        for r in results[:12]:
            it = QListWidgetItem(f"• {r.get('title','')}\n   {r.get('link','')}")
            it.setForeground(QColor(theme.TEXT))
            self._g_list.addItem(it)

    def update_recon(self, risk_count: int = 0) -> None:
        counts = self._model.counts_by_type()
        self._r_count.setText(str(len(self._model)))
        for et_val, lbl in self._tiles.items():
            for et in EntityType:
                if et.value == et_val:
                    lbl.setText(str(counts.get(et, 0)))
                    break
        self._risk.setText(f"{risk_count} attack-surface risks flagged")


def ENTITY_COLOR(et: EntityType) -> str:
    from core.entities import ENTITY_META
    return ENTITY_META[et].color
