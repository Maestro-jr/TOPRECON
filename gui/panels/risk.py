"""Attack-Surface Risk panel — findings by severity with MITRE recon mapping."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
                             QListWidget, QListWidgetItem)

from gui import theme
from gui.widgets.common import Panel
from core.risk import analyze, summarize


class RiskPanel(Panel):
    finding_clicked = pyqtSignal(str)   # entity key

    def __init__(self, graph_model, parent=None):
        super().__init__("Attack Surface Risk", parent=parent)
        self._model = graph_model

        strip = QHBoxLayout(); strip.setSpacing(6)
        self._chips: dict[str, QLabel] = {}
        for sev in ("critical", "high", "medium", "low"):
            chip = QLabel(f"{sev[:4].upper()} 0")
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip.setStyleSheet(
                f"background:{theme.BG_PANEL_HI}; color:{theme.SEV[sev]};"
                f"border:1px solid {theme.SEV[sev]}; border-radius:3px;"
                f"font-family:{theme.FONT_MONO}; font-size:10px; padding:3px 4px;")
            self._chips[sev] = chip
            strip.addWidget(chip, 1)
        self.body.addLayout(strip)

        self._list = QListWidget()
        self._list.itemClicked.connect(self._on_click)
        self.body.addWidget(self._list, 1)

    def refresh(self) -> list:
        findings = analyze(self._model)
        counts = summarize(findings)
        for sev, chip in self._chips.items():
            chip.setText(f"{sev[:4].upper()} {counts.get(sev, 0)}")
        self.set_badge(str(len(findings)))
        self._list.clear()
        for f in findings[:120]:
            head = QListWidgetItem(f"[{f.severity.upper()}] {f.category}")
            head.setForeground(QColor(theme.SEV.get(f.severity, theme.TEXT)))
            head.setData(Qt.ItemDataRole.UserRole, f.entity_key)
            self._list.addItem(head)
            sub = QListWidgetItem(f"    {f.entity_value} — {f.detail}")
            sub.setForeground(QColor(theme.TEXT_MUTED))
            sub.setData(Qt.ItemDataRole.UserRole, f.entity_key)
            self._list.addItem(sub)
            if f.mitre_id:
                mit = QListWidgetItem(f"    ↳ MITRE {f.mitre_id} · {f.mitre_name}")
                mit.setForeground(QColor(theme.ACCENT_TEAL))
                self._list.addItem(mit)
        if not findings:
            self._list.addItem(QListWidgetItem("No attack-surface risks flagged yet."))
        return findings

    def _on_click(self, item: QListWidgetItem) -> None:
        key = item.data(Qt.ItemDataRole.UserRole)
        if key:
            self.finding_clicked.emit(key)
