"""
Left navigation rail — a slim vertical strip of icon buttons that jump to the
dashboard's sections (graph, the analysis tabs, config). Exclusive selection,
tooltips, glyph-only so it stays compact.
"""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QFrame, QVBoxLayout, QPushButton, QButtonGroup,
                             QSizePolicy)


class IconRail(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("iconRail")
        self.setFixedWidth(52)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self._v = QVBoxLayout(self)
        self._v.setContentsMargins(0, 10, 0, 10)
        self._v.setSpacing(4)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

    def add_button(self, glyph: str, tooltip: str, on_click: Callable[[], None],
                   *, checkable: bool = True) -> QPushButton:
        b = QPushButton(glyph)
        b.setObjectName("railBtn")
        b.setToolTip(tooltip)
        b.setCheckable(checkable)
        b.setFixedHeight(42)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        b.clicked.connect(lambda: on_click())
        if checkable:
            self._group.addButton(b)
        self._v.addWidget(b)
        return b

    def add_spacer(self) -> None:
        self._v.addStretch(1)
