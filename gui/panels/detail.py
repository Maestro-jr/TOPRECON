"""Entity detail drill-down: all data collected about a clicked entity + relations."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QLabel, QVBoxLayout, QWidget, QListWidget,
                             QListWidgetItem, QFrame, QHBoxLayout)

from gui import theme
from gui.widgets.common import Panel
from core.entities import ENTITY_META


class EntityDetailPanel(Panel):
    """Shows everything known about the selected entity and lets you pivot the
    view by clicking a related entity."""
    relation_clicked = pyqtSignal(str)   # entity key

    def __init__(self, graph_model, parent=None):
        super().__init__("Entity Detail", parent=parent)
        self._model = graph_model
        self._key: Optional[str] = None

        self._title = QLabel("Select a node")
        self._title.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                                  "font-size:14px; font-weight:700;")
        self._title.setWordWrap(True)
        self._sub = QLabel("")
        self._sub.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO}; font-size:10px;")
        self.body.addWidget(self._title)
        self.body.addWidget(self._sub)

        self._risk = QLabel(""); self._risk.setWordWrap(True)
        self._risk.setStyleSheet(f"color:{theme.ERRORC}; font-family:{theme.FONT_MONO}; font-size:10px;")
        self.body.addWidget(self._risk)

        al = QLabel("ATTRIBUTES"); al.setObjectName("sectionLabel")
        self.body.addWidget(al)
        self._attrs = QListWidget(); self._attrs.setMaximumHeight(190)
        self.body.addWidget(self._attrs)

        rl = QLabel("RELATIONSHIPS"); rl.setObjectName("sectionLabel")
        self.body.addWidget(rl)
        self._rels = QListWidget()
        self._rels.itemClicked.connect(self._on_rel)
        self.body.addWidget(self._rels, 1)

    def clear(self) -> None:
        self._key = None
        self._title.setText("Select a node")
        self._title.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                                  "font-size:14px; font-weight:700;")
        self._sub.setText(""); self._risk.setText("")
        self._attrs.clear(); self._rels.clear()

    def show_entity(self, key: str) -> None:
        ent = self._model.get(key)
        if ent is None:
            return
        self._key = key
        meta = ENTITY_META[ent.etype]
        self._title.setText(ent.value)
        self._title.setStyleSheet(f"color:{meta.color}; font-family:{theme.FONT_MONO};"
                                  "font-size:14px; font-weight:700;")
        self._sub.setText(f"{meta.label}  ·  depth {ent.depth}  ·  "
                          f"sources: {', '.join(sorted(ent.sources)) or '—'}")
        if ent.risk:
            self._risk.setText(f"⚠ {ent.risk.upper()}: {ent.risk_reason}")
            self._risk.setStyleSheet(
                f"color:{theme.SEV.get(ent.risk, theme.ERRORC)}; "
                f"font-family:{theme.FONT_MONO}; font-size:10px;")
        else:
            self._risk.setText("")

        self._attrs.clear()
        for k, v in ent.data.items():
            if k == "display":
                continue
            sv = str(v)
            if len(sv) > 90:
                sv = sv[:88] + "…"
            it = QListWidgetItem(f"{k}: {sv}")
            it.setForeground(QColor(theme.TEXT))
            self._attrs.addItem(it)
        if self._attrs.count() == 0:
            self._attrs.addItem(QListWidgetItem("(no additional attributes)"))

        self._rels.clear()
        for other, direction, kind in self._model.neighbors(key):
            om = ENTITY_META[other.etype]
            arrow = "→" if direction == "out" else "←"
            it = QListWidgetItem(f"{arrow} [{om.short}] {other.value}  ({kind})")
            it.setForeground(QColor(om.color))
            it.setData(Qt.ItemDataRole.UserRole, other.key)
            self._rels.addItem(it)
        if self._rels.count() == 0:
            self._rels.addItem(QListWidgetItem("(no relationships yet)"))

    def _on_rel(self, item: QListWidgetItem) -> None:
        key = item.data(Qt.ItemDataRole.UserRole)
        if key:
            self.relation_clicked.emit(key)
