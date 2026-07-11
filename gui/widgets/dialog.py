"""
Frameless dialog base + message box, matching the main window's custom chrome.

Every TOP RECON dialog (Authorization Gate, Scan Summary, History, Replay,
message popups) uses these so no sub-window shows a default OS title bar.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QPushButton,
                             QVBoxLayout, QWidget)

from gui import theme


class _DlgTitleBar(QFrame):
    def __init__(self, dialog: QDialog, title: str):
        super().__init__()
        self.setObjectName("dlgTitle")
        self.setFixedHeight(40)
        self._dlg = dialog
        self._drag = None
        h = QHBoxLayout(self); h.setContentsMargins(14, 0, 8, 0); h.setSpacing(8)
        dot = QLabel("●"); dot.setStyleSheet(f"color:{theme.ACCENT}; font-size:11px;")
        lbl = QLabel(title.upper()); lbl.setObjectName("dlgTitleText")
        h.addWidget(dot); h.addWidget(lbl); h.addStretch()
        close = QPushButton("✕"); close.setObjectName("winClose")
        close.setFixedSize(34, 28); close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        close.clicked.connect(dialog.reject)
        h.addWidget(close)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag = e.globalPosition().toPoint() - self._dlg.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag is not None and e.buttons() & Qt.MouseButton.LeftButton:
            self._dlg.move(e.globalPosition().toPoint() - self._drag)

    def mouseReleaseEvent(self, e):
        self._drag = None


class FramelessDialog(QDialog):
    """A themed, draggable, borderless dialog. Put content in ``self.body``."""

    def __init__(self, parent=None, title: str = "TOP RECON",
                 width: Optional[int] = None, height: Optional[int] = None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setStyleSheet(theme.stylesheet())
        self.setModal(True)
        outer = QVBoxLayout(self); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)
        frame = QFrame(); frame.setObjectName("dlgFrame")
        outer.addWidget(frame)
        v = QVBoxLayout(frame); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(0)
        v.addWidget(_DlgTitleBar(self, title))
        content = QWidget()
        self.body = QVBoxLayout(content)
        self.body.setContentsMargins(22, 16, 22, 18); self.body.setSpacing(10)
        v.addWidget(content, 1)
        if width:
            self.setMinimumWidth(width)
        if height:
            self.setMinimumHeight(height)


class MessageDialog(FramelessDialog):
    """A themed info/confirm popup replacing native QMessageBox chrome."""

    def __init__(self, parent, title: str, message: str, *, confirm: bool = False,
                 level: str = "info"):
        super().__init__(parent, title=title, width=420)
        msg = QLabel(message); msg.setWordWrap(True)
        msg.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_UI};"
                          "font-size:12px;")
        self.body.addWidget(msg)
        row = QHBoxLayout(); row.addStretch()
        if confirm:
            cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject)
            row.addWidget(cancel)
        ok = QPushButton("OK"); ok.setObjectName("primary"); ok.clicked.connect(self.accept)
        row.addWidget(ok)
        self.body.addLayout(row)

    @staticmethod
    def info(parent, title: str, message: str, level: str = "info") -> None:
        MessageDialog(parent, title, message, level=level).exec()

    @staticmethod
    def confirm(parent, title: str, message: str) -> bool:
        return MessageDialog(parent, title, message, confirm=True).exec() == QDialog.DialogCode.Accepted
