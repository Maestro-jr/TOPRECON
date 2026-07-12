"""
TOP RECON — custom frameless title bar.

Replaces the OS title bar with a branded, draggable bar hosting the logo mark,
the NEW RECON action, the engine identity, live metric tiles, a UTC clock and
custom minimize/maximize/close controls. Dragging moves the window; double-click
toggles maximize. Cleaner and more cohesive than a default OS frame.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import Qt, QPointF, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen, QPolygonF, QLinearGradient
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
                             QWidget)

from gui import theme
from gui.widgets.common import MetricTile


class LogoMark(QWidget):
    """A painted hex 'target' mark: concentric radar rings + a crosshair core."""

    def __init__(self, size: int = 34, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(self.rect().center())   # QPointF: drawEllipse(center, rx, ry)
        r = min(self.width(), self.height()) / 2 - 2
        # outer hexagon
        pts = [QPointF(c.x() + r * math.cos(math.pi / 6 + i * math.pi / 3),
                       c.y() + r * math.sin(math.pi / 6 + i * math.pi / 3))
               for i in range(6)]
        grad = QLinearGradient(0, 0, 0, self.height())
        grad.setColorAt(0, QColor(theme.ACCENT))
        grad.setColorAt(1, QColor(theme.ACCENT_TEAL))
        pen = QPen(QColor(theme.ACCENT), 1.8); p.setPen(pen)
        p.setBrush(QColor(13, 42, 28)); p.drawPolygon(QPolygonF(pts))
        # radar rings
        p.setBrush(Qt.BrushStyle.NoBrush)
        for rr, a in ((r * 0.62, 200), (r * 0.36, 255)):
            col = QColor(theme.ACCENT); col.setAlpha(a)
            p.setPen(QPen(col, 1.2))
            p.drawEllipse(c, rr, rr)
        # crosshair
        p.setPen(QPen(QColor(theme.ACCENT_TEAL), 1.0))
        p.drawLine(int(c.x() - r * 0.7), int(c.y()), int(c.x() + r * 0.7), int(c.y()))
        p.drawLine(int(c.x()), int(c.y() - r * 0.7), int(c.x()), int(c.y() + r * 0.7))
        # sweep dot
        p.setPen(Qt.PenStyle.NoPen); p.setBrush(QColor(theme.ACCENT))
        p.drawEllipse(QPointF(c.x() + r * 0.36, c.y() - r * 0.18), 2.2, 2.2)
        p.end()


def _win_button(glyph: str, name: str) -> QPushButton:
    b = QPushButton(glyph); b.setObjectName(name)
    b.setFixedSize(38, 30)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    return b


class TitleBar(QFrame):
    new_recon_requested = pyqtSignal()
    keys_requested      = pyqtSignal()
    minimize_requested  = pyqtSignal()
    maximize_requested  = pyqtSignal()
    close_requested     = pyqtSignal()

    def __init__(self, engine_name: str, engine_tag: str, parent=None):
        super().__init__(parent)
        self.setObjectName("titleBar")
        self.setFixedHeight(58)
        self._drag_pos = None
        self.tiles: dict[str, MetricTile] = {}

        h = QHBoxLayout(self); h.setContentsMargins(14, 4, 8, 4); h.setSpacing(16)

        h.addWidget(LogoMark(34))
        brand = QVBoxLayout(); brand.setSpacing(0)
        name = QLabel("TOP RECON"); name.setObjectName("appName")
        tag = QLabel("ATTACK SURFACE RECON ENGINE  v1.0"); tag.setObjectName("appTag")
        brand.addWidget(name); brand.addWidget(tag)
        h.addLayout(brand)

        # NEW RECON — primary in-app action to start a fresh target.
        self._new_btn = QPushButton("＋  NEW RECON")
        self._new_btn.setObjectName("newRecon")
        self._new_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._new_btn.clicked.connect(self.new_recon_requested)
        h.addWidget(self._new_btn)

        self._keys_btn = QPushButton("⚿  KEYS")
        self._keys_btn.setObjectName("keysBtn")
        self._keys_btn.setToolTip("Enter API keys to unlock key-gated sources")
        self._keys_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._keys_btn.clicked.connect(self.keys_requested)
        h.addWidget(self._keys_btn)

        eng = QVBoxLayout(); eng.setSpacing(0)
        en = QLabel(engine_name)
        en.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                         "font-size:11px; font-weight:700;")
        et = QLabel(engine_tag); et.setObjectName("appTag")
        eng.addWidget(en); eng.addWidget(et)
        h.addLayout(eng)
        h.addStretch()

        for key, label, value, green in (
                ("status", "STATUS", "IDLE", True), ("depth", "DEPTH", "0 / 4", False),
                ("entities", "ENTITIES", "0", False), ("requests", "REQUESTS", "0", False),
                ("success", "SUCCESS", "—", True), ("elapsed", "ELAPSED", "00:00:00", False),
                ("thru", "THROUGHPUT", "0 req/s", True)):
            t = MetricTile(label, value, green=green)
            self.tiles[key] = t
            h.addWidget(t)

        sep = QFrame(); sep.setFixedWidth(1); sep.setStyleSheet(f"background:{theme.BORDER_HI};")
        h.addWidget(sep)
        self._clock = QLabel("--:--:-- UTC")
        self._clock.setStyleSheet(f"color:{theme.ACCENT}; font-family:{theme.FONT_MONO};"
                                  "font-size:11px; font-weight:600;")
        h.addWidget(self._clock)

        h.addSpacing(6)
        btn_min = _win_button("—", "winBtn")
        self._btn_max = _win_button("▢", "winBtn")
        btn_close = _win_button("✕", "winClose")
        btn_min.clicked.connect(self.minimize_requested)
        self._btn_max.clicked.connect(self.maximize_requested)
        btn_close.clicked.connect(self.close_requested)
        for b in (btn_min, self._btn_max, btn_close):
            h.addWidget(b)

    def set_clock(self, text: str) -> None:
        self._clock.setText(text)

    def set_maximized(self, on: bool) -> None:
        self._btn_max.setText("❐" if on else "▢")

    # -- window drag / double-click maximize --------------------------------
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if (self._drag_pos is not None and e.buttons() & Qt.MouseButton.LeftButton
                and not self.window().isMaximized()):
            self.window().move(e.globalPosition().toPoint() - self._drag_pos)
            e.accept()

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    def mouseDoubleClickEvent(self, e):
        self.maximize_requested.emit()
