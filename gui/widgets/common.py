"""Reusable building blocks: titled Panel frame, metric tile, mini bar, gauge."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtGui import QColor, QPainter, QPen, QFont
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
                             QSizePolicy)

from gui import theme


class Panel(QFrame):
    """A titled, bordered panel — the standard container for dashboard sections."""

    def __init__(self, title: str, badge: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("panel")
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 12)
        root.setSpacing(8)

        head = QFrame(); head.setObjectName("panelHeader")
        hl = QHBoxLayout(head); hl.setContentsMargins(0, 0, 0, 0); hl.setSpacing(6)
        self._title = QLabel(title.upper()); self._title.setObjectName("panelTitle")
        hl.addWidget(self._title)
        hl.addStretch()
        self._badge = QLabel(badge); self._badge.setObjectName("panelBadge")
        hl.addWidget(self._badge)
        root.addWidget(head)

        self.body = QVBoxLayout(); self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(6)
        root.addLayout(self.body, 1)
        self._head_layout = hl

    def set_badge(self, text: str) -> None:
        self._badge.setText(text)

    def add_header_widget(self, w: QWidget) -> None:
        self._head_layout.addWidget(w)


class MetricTile(QWidget):
    """A compact label-over-value tile used in the top bar."""

    def __init__(self, label: str, value: str = "—", green: bool = False,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        v = QVBoxLayout(self); v.setContentsMargins(10, 4, 10, 4); v.setSpacing(1)
        self._lbl = QLabel(label.upper()); self._lbl.setObjectName("metricLabel")
        self._val = QLabel(value)
        self._val.setObjectName("metricValueGreen" if green else "metricValue")
        v.addWidget(self._lbl); v.addWidget(self._val)

    def set_value(self, value: str) -> None:
        self._val.setText(value)

    def set_color(self, color: str) -> None:
        self._val.setStyleSheet(f"color:{color}; font-family:{theme.FONT_MONO};"
                                "font-size:15px; font-weight:700;")


class MiniBar(QFrame):
    """A slim horizontal magnitude bar (discovery-depth / summary rows)."""

    def __init__(self, color: str = theme.ACCENT, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._value = 0.0
        self._color = color
        self.setFixedHeight(6)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, frac: float) -> None:
        self._value = max(0.0, min(1.0, frac))
        self.update()

    def set_color(self, color: str) -> None:
        self._color = color; self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.rect()
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(theme.BG_PANEL_HI))
        p.drawRoundedRect(QRectF(r), 3, 3)
        if self._value > 0:
            w = r.width() * self._value
            p.setBrush(QColor(self._color))
            p.drawRoundedRect(QRectF(0, 0, w, r.height()), 3, 3)
        p.end()


class ConfidenceGauge(QWidget):
    """Circular confidence-score gauge rendered as a sweeping arc."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._score = 0
        self._label = "—"
        self.setMinimumSize(140, 140)

    def set_score(self, score: int, label: str = "") -> None:
        self._score = max(0, min(100, int(score)))
        if not label:
            label = ("HIGH" if self._score >= 75 else
                     "MEDIUM" if self._score >= 40 else "LOW")
        self._label = label
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 12
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2,
                      side, side)
        # track
        pen = QPen(QColor(theme.BORDER_HI), 9)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen); p.drawArc(rect, 0, 360 * 16)
        # value arc
        col = (theme.ACCENT if self._score >= 75 else
               theme.QUEUED if self._score >= 40 else theme.ERRORC)
        pen = QPen(QColor(col), 9); pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        span = int(360 * 16 * self._score / 100)
        p.drawArc(rect, 90 * 16, -span)
        # centre text
        p.setPen(QColor(col))
        f = QFont("Consolas", 26, QFont.Weight.Bold); p.setFont(f)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(self._score))
        p.setPen(QColor(theme.TEXT_MUTED))
        f2 = QFont("Consolas", 9); f2.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 2)
        p.setFont(f2)
        lr = QRectF(rect.left(), rect.center().y() + 24, rect.width(), 20)
        p.drawText(lr, Qt.AlignmentFlag.AlignCenter, self._label)
        p.end()
