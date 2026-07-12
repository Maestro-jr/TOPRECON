"""Right column: Active Modules, Pivot Queue, Recent Discoveries."""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QAbstractItemView, QScrollArea, QListWidget,
                             QListWidgetItem)

from gui import theme
from gui.widgets.common import Panel
from core.entities import ENTITY_META
from core.transforms import ModuleStatus

_STATUS_COLOR = {
    ModuleStatus.RUNNING:   theme.RUNNING,
    ModuleStatus.QUEUED:    theme.QUEUED,
    ModuleStatus.IDLE:      theme.TEXT_MUTED,
    ModuleStatus.NEEDS_KEY: theme.NEEDS_KEY,
    ModuleStatus.MISSING:   theme.MISSING,
    ModuleStatus.DISABLED:  theme.TEXT_FAINT,
    ModuleStatus.ERROR:     theme.ERRORC,
}


class _ModuleRow(QFrame):
    def __init__(self, name: str, display: str):
        super().__init__()
        self.name = name
        h = QHBoxLayout(self); h.setContentsMargins(6, 3, 6, 3); h.setSpacing(8)
        self._dot = QLabel("●"); self._dot.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-size:10px;")
        self._name = QLabel(display)
        self._name.setStyleSheet(f"color:{theme.TEXT}; font-family:{theme.FONT_MONO}; font-size:11px;")
        self._status = QLabel("Idle")
        self._status.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO}; font-size:10px;")
        self._hits = QLabel("")
        self._hits.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                                 "font-size:11px; font-weight:700;")
        self._hits.setFixedWidth(42); self._hits.setAlignment(Qt.AlignmentFlag.AlignRight)
        h.addWidget(self._dot); h.addWidget(self._name); h.addStretch()
        h.addWidget(self._status); h.addWidget(self._hits)

    def update_state(self, status: str, hits: int) -> None:
        col = _STATUS_COLOR.get(status, theme.TEXT_MUTED)
        self._dot.setStyleSheet(f"color:{col}; font-size:10px;")
        self._status.setText(status)
        self._status.setStyleSheet(f"color:{col}; font-family:{theme.FONT_MONO}; font-size:10px;")
        self._hits.setText(str(hits) if hits else "")


class ActiveModulesPanel(Panel):
    def __init__(self, parent=None):
        super().__init__("Active Modules", parent=parent)
        self.add_view_all()
        area = QScrollArea(); area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        host = QWidget(); host.setStyleSheet("background:transparent;")
        self._v = QVBoxLayout(host)
        self._v.setContentsMargins(0, 0, 6, 0); self._v.setSpacing(1)
        self._v.addStretch()
        area.setWidget(host)
        self.body.addWidget(area, 1)
        self._rows: dict[str, _ModuleRow] = {}

    def build(self, modules: list) -> None:
        self.set_badge(f"({len(modules)})")
        for mod in modules:
            if mod.name in self._rows:
                continue
            row = _ModuleRow(mod.name, mod.display)
            row.update_state(mod.status, mod.hits)
            self._rows[mod.name] = row
            self._v.insertWidget(self._v.count() - 1, row)

    def update_module(self, name: str, payload: dict) -> None:
        row = self._rows.get(name)
        if row is not None:
            row.update_state(payload.get("status", ModuleStatus.IDLE),
                             payload.get("hits", 0))

    def reset(self, modules: list) -> None:
        for mod in modules:
            row = self._rows.get(mod.name)
            if row is not None:
                row.update_state(mod.status, mod.hits)


class PivotQueuePanel(Panel):
    def __init__(self, parent=None):
        super().__init__("Pivot Queue", parent=parent)
        self.add_view_all()
        self._t = QTableWidget(0, 4)
        self._t.setHorizontalHeaderLabels(["PIVOT", "FROM", "TOOL", "STATUS"])
        self._t.verticalHeader().setVisible(False)
        self._t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._t.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        hh = self._t.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.body.addWidget(self._t, 1)
        self._sig = None

    def update_queue(self, pending: list) -> None:
        self.set_badge(f"({len(pending)})")
        show = pending[:60]
        # Skip the (allocating) table rebuild when the visible queue is unchanged.
        sig = tuple((pk.entity_value, pk.tool, pk.status) for pk in show)
        if sig == self._sig:
            return
        self._sig = sig
        if self._t.rowCount() != len(show):
            self._t.setRowCount(len(show))
        for r, pk in enumerate(show):
            vals = (pk.entity_value, pk.from_type, pk.tool_display, pk.status)
            for c, v in enumerate(vals):
                it = self._t.item(r, c)
                if it is None:
                    it = QTableWidgetItem(str(v))
                    self._t.setItem(r, c, it)
                elif it.text() != str(v):
                    it.setText(str(v))
                if c == 3:
                    col = theme.RUNNING if pk.status == "Running" else theme.QUEUED
                    it.setForeground(QColor(col))


class RecentDiscoveriesPanel(Panel):
    def __init__(self, parent=None):
        super().__init__("Recent Discoveries", parent=parent)
        self.add_view_all()
        self._list = QListWidget()
        self._list.setMinimumHeight(120)
        self.body.addWidget(self._list, 1)
        self._max = 120
        self._seen = 0

    def clear(self) -> None:
        self._list.clear()
        self._seen = 0
        self.set_badge("")

    def add(self, entity) -> None:
        meta = ENTITY_META[entity.etype]
        ts = time.strftime("%H:%M:%S")
        it = QListWidgetItem(f"● {entity.value}")
        it.setForeground(QColor(meta.color))
        it.setToolTip(f"{meta.label} · discovered {ts} · depth {entity.depth}")
        self._list.insertItem(0, it)
        self._seen += 1
        self.set_badge(str(self._seen))
        while self._list.count() > self._max:
            self._list.takeItem(self._list.count() - 1)
