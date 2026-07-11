"""Left column: Input Seed, Entity Types (filters), Discovery Depth, Live Feed."""

from __future__ import annotations

import time
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QVBoxLayout,
                             QListWidget, QListWidgetItem)

from gui import theme
from gui.widgets.common import Panel, MiniBar
from core.entities import (EntityType, ENTITY_META, Depth, DEPTH_LABELS)


class InputSeedPanel(Panel):
    def __init__(self, parent=None):
        super().__init__("Input Seed", parent=parent)
        card = QFrame(); card.setObjectName("panel")
        card.setStyleSheet(f"#panel {{ background:{theme.BG_PANEL_HI};"
                           f" border:1px solid {theme.ACCENT_DIM}; border-radius:5px; }}")
        cl = QVBoxLayout(card); cl.setContentsMargins(12, 10, 12, 10); cl.setSpacing(3)
        self._target = QLabel("—")
        self._target.setStyleSheet(f"color:{theme.ACCENT}; font-family:{theme.FONT_MONO};"
                                   "font-size:15px; font-weight:700;")
        self._type = QLabel("Domain  ·  SEED")
        self._type.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO};"
                                 "font-size:10px;")
        self._auth = QLabel("● AWAITING AUTHORIZATION")
        self._auth.setStyleSheet(f"color:{theme.QUEUED}; font-family:{theme.FONT_MONO};"
                                 "font-size:10px;")
        cl.addWidget(self._target); cl.addWidget(self._type); cl.addWidget(self._auth)
        self.body.addWidget(card)

    def set_seed(self, target: str, apex: str, active: bool) -> None:
        self._target.setText(target)
        self._type.setText(f"Domain  ·  apex {apex}  ·  SEED-{int(time.time()) % 10_000_000}")
        mode = "ACTIVE + PASSIVE" if active else "PASSIVE ONLY"
        self._auth.setText(f"● AUTHORIZED  ·  {mode}")
        self._auth.setStyleSheet(f"color:{theme.ACCENT}; font-family:{theme.FONT_MONO};"
                                 "font-size:10px;")


class _TypeRow(QFrame):
    clicked = pyqtSignal(object)   # EntityType

    def __init__(self, etype: EntityType):
        super().__init__()
        self.etype = etype
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("QFrame:hover { background:#0e1622; border-radius:4px; }")
        h = QHBoxLayout(self); h.setContentsMargins(6, 3, 6, 3); h.setSpacing(8)
        meta = ENTITY_META[etype]
        dot = QLabel("●"); dot.setStyleSheet(f"color:{meta.color}; font-size:11px;")
        name = QLabel(meta.label)
        name.setStyleSheet(f"color:{theme.TEXT}; font-family:{theme.FONT_MONO}; font-size:11px;")
        self._count = QLabel("0")
        self._count.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO};"
                                  "font-size:11px; font-weight:700;")
        h.addWidget(dot); h.addWidget(name); h.addStretch(); h.addWidget(self._count)

    def set_count(self, n: int) -> None:
        self._count.setText(str(n))
        col = theme.TEXT_BRIGHT if n else theme.TEXT_FAINT
        self._count.setStyleSheet(f"color:{col}; font-family:{theme.FONT_MONO};"
                                  "font-size:11px; font-weight:700;")

    def set_active(self, on: bool) -> None:
        self.setStyleSheet(
            ("QFrame { background:#0d2a1c; border-left:2px solid " + theme.ACCENT + "; }")
            if on else "QFrame:hover { background:#0e1622; border-radius:4px; }")

    def mousePressEvent(self, e):
        self.clicked.emit(self.etype)


class EntityTypesPanel(Panel):
    """Live per-type counts; clicking a type filters the graph/table."""
    filter_changed = pyqtSignal(object)   # EntityType or None

    # The types shown, in the order of the reference list (most useful first).
    ORDER = [EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS,
             EntityType.DNS_RECORD, EntityType.CERTIFICATE, EntityType.PORT,
             EntityType.SERVICE, EntityType.WEB_TECH, EntityType.EMAIL,
             EntityType.CLOUD_BUCKET, EntityType.CODE_REPO,
             EntityType.LEAKED_SECRET, EntityType.BREACH_RECORD,
             EntityType.TYPOSQUAT, EntityType.URL, EntityType.ASN,
             EntityType.NETBLOCK, EntityType.WHOIS_RECORD, EntityType.COMPANY]

    def __init__(self, parent=None):
        super().__init__("Entity Types", parent=parent)
        self._active: Optional[EntityType] = None
        self._rows: dict[EntityType, _TypeRow] = {}

        allbtn = _AllRow()
        allbtn.clicked.connect(lambda: self._select(None))
        self._all = allbtn
        self.body.addWidget(allbtn)
        for et in self.ORDER:
            row = _TypeRow(et)
            row.clicked.connect(self._select)
            self._rows[et] = row
            self.body.addWidget(row)
        self.body.addStretch()

    def _select(self, etype: Optional[EntityType]) -> None:
        self._active = None if etype == self._active else etype
        for et, row in self._rows.items():
            row.set_active(et == self._active)
        self._all.set_active(self._active is None)
        self.filter_changed.emit(self._active)

    def update_counts(self, counts: dict) -> None:
        total = 0
        for et, row in self._rows.items():
            n = counts.get(et, 0)
            row.set_count(n)
            total += n
        self.set_badge(str(total))

    def reset_filter(self) -> None:
        self._active = None
        for row in self._rows.values():
            row.set_active(False)
        self._all.set_active(True)


class _AllRow(QFrame):
    clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        h = QHBoxLayout(self); h.setContentsMargins(6, 3, 6, 3)
        lab = QLabel("▣  ALL ENTITIES")
        lab.setStyleSheet(f"color:{theme.ACCENT_TEAL}; font-family:{theme.FONT_MONO};"
                          "font-size:11px; font-weight:700;")
        h.addWidget(lab); h.addStretch()
        self.set_active(True)

    def set_active(self, on: bool) -> None:
        self.setStyleSheet("QFrame { background:#0d2a1c; border-radius:4px; }" if on
                           else "QFrame:hover { background:#0e1622; border-radius:4px; }")

    def mousePressEvent(self, e):
        self.clicked.emit()


class DiscoveryDepthPanel(Panel):
    def __init__(self, parent=None):
        super().__init__("Discovery Depth", parent=parent)
        self._bars: dict[int, MiniBar] = {}
        self._counts: dict[int, QLabel] = {}
        for depth in (Depth.SEED, Depth.DIRECT, Depth.INDIRECT, Depth.PIVOTED, Depth.DEEP):
            row = QHBoxLayout(); row.setSpacing(8)
            idx = QLabel(str(int(depth)))
            idx.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO}; font-size:10px;")
            idx.setFixedWidth(10)
            name = QLabel(DEPTH_LABELS[depth])
            name.setStyleSheet(f"color:{theme.TEXT}; font-family:{theme.FONT_MONO}; font-size:10px;")
            name.setFixedWidth(64)
            bar = MiniBar(theme.ACCENT)
            cnt = QLabel("—")
            cnt.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                              "font-size:10px; font-weight:700;")
            cnt.setFixedWidth(46); cnt.setAlignment(Qt.AlignmentFlag.AlignRight)
            row.addWidget(idx); row.addWidget(name); row.addWidget(bar, 1); row.addWidget(cnt)
            self.body.addLayout(row)
            self._bars[int(depth)] = bar
            self._counts[int(depth)] = cnt
        # Max-depth line
        mrow = QHBoxLayout()
        self._maxlbl = QLabel("Max Depth")
        self._maxlbl.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO}; font-size:10px;")
        self._maxval = QLabel("—")
        self._maxval.setStyleSheet(f"color:{theme.ACCENT_TEAL}; font-family:{theme.FONT_MONO};"
                                   "font-size:10px; font-weight:700;")
        self._maxval.setAlignment(Qt.AlignmentFlag.AlignRight)
        mrow.addSpacing(20); mrow.addWidget(self._maxlbl); mrow.addStretch(); mrow.addWidget(self._maxval)
        self.body.addLayout(mrow)
        self.body.addStretch()

    def update_depths(self, by_depth: dict, max_depth: int) -> None:
        peak = max(by_depth.values(), default=1) or 1
        for d, bar in self._bars.items():
            n = by_depth.get(d, 0)
            bar.set_value(n / peak)
            self._counts[d].setText(str(n) if n else "—")
        self._maxval.setText(f"{max_depth}")


class LiveFeedPanel(Panel):
    _COLORS = {"discovery": theme.ACCENT, "pivot": theme.ACCENT_TEAL,
               "warn": theme.QUEUED, "error": theme.ERRORC, "info": theme.TEXT_MUTED}

    def __init__(self, parent=None):
        super().__init__("Live Feed", parent=parent)
        self._list = QListWidget()
        self._list.setWordWrap(False)
        self.body.addWidget(self._list, 1)
        self._max = 400

    def clear(self) -> None:
        self._list.clear()

    def append(self, entry: dict) -> None:
        ts = time.strftime("%H:%M:%S", time.localtime(entry.get("ts", time.time())))
        level = entry.get("level", "info")
        tag = {"discovery": "[+]", "pivot": "[»]", "warn": "[!]",
               "error": "[x]", "info": "[*]"}.get(level, "[*]")
        text = f"{ts}  {tag} {entry.get('text','')}"
        it = QListWidgetItem(text)
        it.setForeground(QColor(self._COLORS.get(level, theme.TEXT_MUTED)))
        self._list.insertItem(0, it)
        while self._list.count() > self._max:
            self._list.takeItem(self._list.count() - 1)
