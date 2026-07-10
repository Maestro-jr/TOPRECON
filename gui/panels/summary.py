"""Bottom strip: Intelligence Summary (top subdomains / services / sources) + confidence."""

from __future__ import annotations

from collections import Counter
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
                             QGridLayout)

from gui import theme
from gui.widgets.common import Panel, MiniBar, ConfidenceGauge
from core.entities import EntityType


class _RankedList(QWidget):
    """A titled column of ranked label + bar + count rows."""

    def __init__(self, title: str, color: str = theme.ACCENT):
        super().__init__()
        self._color = color
        v = QVBoxLayout(self); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(5)
        t = QLabel(title.upper()); t.setObjectName("sectionLabel")
        v.addWidget(t)
        self._rows = QVBoxLayout(); self._rows.setSpacing(4)
        v.addLayout(self._rows); v.addStretch()

    def set_items(self, items: list[tuple[str, int]]) -> None:
        while self._rows.count():
            it = self._rows.takeAt(0)
            if it.widget():
                it.widget().setParent(None)
        if not items:
            cap = QLabel("awaiting data")
            cap.setStyleSheet(f"color:{theme.TEXT_FAINT}; font-family:{theme.FONT_MONO};"
                              "font-size:10px; font-style:italic;")
            self._rows.addWidget(cap)
            return
        peak = max(v for _, v in items) or 1
        for name, val in items[:6]:
            row = QWidget(); h = QHBoxLayout(row); h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(8)
            lbl = QLabel(name if len(name) <= 24 else name[:22] + "…")
            lbl.setStyleSheet(f"color:{theme.TEXT}; font-family:{theme.FONT_MONO}; font-size:10px;")
            lbl.setFixedWidth(150)
            bar = MiniBar(self._color); bar.set_value(val / peak)
            cnt = QLabel(str(val))
            cnt.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                              "font-size:10px; font-weight:700;")
            cnt.setFixedWidth(40); cnt.setAlignment(Qt.AlignmentFlag.AlignRight)
            h.addWidget(lbl); h.addWidget(bar, 1); h.addWidget(cnt)
            self._rows.addWidget(row)


class IntelligenceSummaryPanel(Panel):
    def __init__(self, graph_model, parent=None):
        super().__init__("Intelligence Summary", parent=parent)
        self._model = graph_model
        grid = QGridLayout(); grid.setSpacing(24)
        self._subs = _RankedList("Top Subdomains", theme.ACCENT)
        self._svcs = _RankedList("Top Services / Ports", theme.QUEUED)
        self._srcs = _RankedList("Top Data Sources", theme.ACCENT_TEAL)
        grid.addWidget(self._subs, 0, 0)
        grid.addWidget(self._svcs, 0, 1)
        grid.addWidget(self._srcs, 0, 2)

        conf = QWidget(); cv = QVBoxLayout(conf); cv.setSpacing(2)
        ct = QLabel("CONFIDENCE SCORE"); ct.setObjectName("sectionLabel")
        ct.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._gauge = ConfidenceGauge()
        self._basis = QLabel("Based on 0 data points")
        self._basis.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO};"
                                  "font-size:9px;")
        self._basis.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cv.addWidget(ct); cv.addWidget(self._gauge, 1); cv.addWidget(self._basis)
        grid.addWidget(conf, 0, 3)
        grid.setColumnStretch(0, 3); grid.setColumnStretch(1, 3)
        grid.setColumnStretch(2, 3); grid.setColumnStretch(3, 2)
        self.body.addLayout(grid)

    def update_summary(self, modules: list, requests: int) -> None:
        # Top subdomains by graph degree (breadth of related infrastructure).
        subs = self._model.entities(EntityType.SUBDOMAIN)
        deg = []
        for s in subs:
            d = len(self._model.neighbors(s.key)) + len(s.sources)
            deg.append((s.value, d))
        deg.sort(key=lambda x: -x[1])
        self._subs.set_items(deg[:6])

        # Top services/ports by port frequency.
        port_c: Counter = Counter()
        for p in self._model.entities(EntityType.PORT):
            pn = p.data.get("port")
            if pn is not None:
                prod = p.data.get("product") or ""
                key = f"{pn}" + (f" {prod}" if prod else "")
                port_c[key] += 1
        self._svcs.set_items(port_c.most_common(6))

        # Top data sources by module hit count.
        src = sorted(((m.display, m.hits) for m in modules if m.hits),
                     key=lambda x: -x[1])
        self._srcs.set_items(src[:6])

        self._basis.setText(f"Based on {requests} data points")
        self._gauge.set_score(self._confidence())

    def _confidence(self) -> int:
        """Volume + breadth + corroboration → 0-100 confidence heuristic."""
        counts = self._model.counts_by_type()
        n = len(self._model)
        if n <= 1:
            return 0
        distinct_types = sum(1 for v in counts.values() if v)
        volume = min(45, n / 6)                       # up to 45 pts for volume
        breadth = min(30, distinct_types * 3)          # up to 30 for type diversity
        # corroboration: entities discovered by >1 source
        multi = sum(1 for e in self._model if len(e.sources) > 1)
        corrob = min(25, multi * 2)                    # up to 25 for cross-confirmation
        return int(min(99, volume + breadth + corrob))
