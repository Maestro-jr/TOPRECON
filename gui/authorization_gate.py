"""
TOP RECON — Authorization Gate.

Mandatory startup dialog. No scan module can run until the operator (1) enters
the target organization/domain and (2) attests ownership or written
authorization. The attestation is written to the audit log before the main
window opens. Active scanning (tools that directly touch the target) requires a
second, separate confirmation here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QCheckBox, QDialog, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QVBoxLayout, QWidget, QFrame)

from gui import theme
from gui.widgets.dialog import FramelessDialog
from transforms.common import apex_domain, is_valid_domain
from audit.attestation import record_attestation, record_event


@dataclass
class GateResult:
    target: str
    apex: str
    scope_note: str
    active_scan: bool


class AuthorizationGate(FramelessDialog):
    def __init__(self, settings, parent: Optional[QWidget] = None):
        super().__init__(parent, title="TOP RECON — Authorization Gate", width=600)
        self._settings = settings
        self._result: Optional[GateResult] = None
        self._build()

    def _build(self) -> None:
        root = self.body
        root.setSpacing(12)

        title = QLabel("TOP RECON")
        title.setObjectName("appName")
        root.addWidget(title)
        sub = QLabel("AUTHORIZED ATTACK-SURFACE RECONNAISSANCE  ·  ORG INFRASTRUCTURE ONLY")
        sub.setObjectName("appTag")
        root.addWidget(sub)

        warn = QFrame(); warn.setObjectName("banner")
        wl = QVBoxLayout(warn); wl.setContentsMargins(12, 10, 12, 10)
        wt = QLabel(
            "This tool maps an organization's own external attack surface —\n"
            "domains, DNS, certificates, exposed services, cloud & code leaks,\n"
            "and brand-impersonation domains. It performs NO person-targeting.\n"
            "You must own the target or hold written authorization to test it.")
        wt.setObjectName("bannerText")
        wl.addWidget(wt)
        root.addWidget(warn)

        lbl = QLabel("TARGET ORGANIZATION / DOMAIN"); lbl.setObjectName("sectionLabel")
        root.addWidget(lbl)
        self._target = QLineEdit()
        self._target.setPlaceholderText("example.com")
        self._target.textChanged.connect(self._validate)
        self._target.returnPressed.connect(self._on_authorize)
        root.addWidget(self._target)

        lbl2 = QLabel("SCOPE NOTE (engagement ref / ticket — optional)")
        lbl2.setObjectName("sectionLabel")
        root.addWidget(lbl2)
        self._scope = QLineEdit()
        self._scope.setPlaceholderText("e.g. Q3 external assessment — authorized by CISO")
        root.addWidget(self._scope)

        self._attest = QCheckBox(
            "I confirm I own this target OR have written authorization to test it.")
        self._attest.stateChanged.connect(self._validate)
        root.addWidget(self._attest)

        self._active = QCheckBox(
            "Also authorize ACTIVE scanning (Nmap, live HTTP probing, brute force "
            "— these directly touch the target).")
        root.addWidget(self._active)

        self._hint = QLabel("")
        self._hint.setStyleSheet(f"color:{theme.ERRORC}; font-family:{theme.FONT_MONO};"
                                 "font-size:10px;")
        root.addWidget(self._hint)

        btns = QHBoxLayout()
        btns.addStretch()
        cancel = QPushButton("Exit")
        cancel.clicked.connect(self.reject)
        self._go = QPushButton("AUTHORIZE & LAUNCH")
        self._go.setObjectName("primary")
        self._go.setEnabled(False)
        self._go.clicked.connect(self._on_authorize)
        btns.addWidget(cancel); btns.addWidget(self._go)
        root.addLayout(btns)

    def _validate(self) -> None:
        target = self._target.text().strip().lower()
        ok = is_valid_domain(target) and self._attest.isChecked()
        if target and not is_valid_domain(target):
            self._hint.setText("Enter a valid domain (e.g. example.com).")
        elif not self._attest.isChecked():
            self._hint.setText("You must attest authorization to proceed.")
        else:
            self._hint.setText("")
        self._go.setEnabled(ok)

    def _on_authorize(self) -> None:
        target = self._target.text().strip().lower()
        if not (is_valid_domain(target) and self._attest.isChecked()):
            self._validate()
            return
        apex = apex_domain(target)
        active = self._active.isChecked()
        record_attestation(self._settings.audit_dir, target,
                           self._scope.text().strip(), active)
        record_event(self._settings.audit_dir, "scan_authorized",
                     f"active={active}", target)
        self._result = GateResult(target=target, apex=apex,
                                  scope_note=self._scope.text().strip(),
                                  active_scan=active)
        self.accept()

    def result(self) -> Optional[GateResult]:
        return self._result
