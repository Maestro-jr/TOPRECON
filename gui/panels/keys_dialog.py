"""
API Keys dialog — enter and persist the optional keys that unlock key-gated
sources. Saves to ``config/.env`` and applies to the running session, then the
caller refreshes module availability so newly-keyed modules light up live.
"""

from __future__ import annotations

from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QScrollArea, QVBoxLayout, QWidget, QFrame)

from gui import theme
from gui.widgets.dialog import FramelessDialog

# source id → (display name, what a key unlocks). Covers every id in KEY_ENV.
KEY_SOURCES = [
    ("shodan",        "Shodan",            "Open ports, services, banners, CVEs"),
    ("virustotal",    "VirusTotal",        "IP / domain reputation & associations"),
    ("hibp",          "Have I Been Pwned", "Breaches affecting the org domain"),
    ("hunter",        "Hunter.io",         "Org email addresses & patterns"),
    ("github",        "GitHub Token",      "Code search for exposed secrets / configs"),
    ("urlscan",       "URLScan.io",        "Lookalike / suspicious URL scans"),
    ("censys_id",     "Censys API ID",     "Hosts, services, certificates"),
    ("censys_secret", "Censys API Secret", "Paired with the Censys API ID"),
    ("zoomeye",       "ZoomEye",           "Alternative host / service source"),
    ("builtwith",     "BuiltWith",         "Domain technology stack"),
    ("dehashed",      "DeHashed",          "Exposed credential data"),
    ("leakix",        "LeakIX",            "Exposed services & leaks"),
    ("checkphish",    "CheckPhish",        "Phishing verdict on lookalike domains"),
    ("abuseipdb",     "AbuseIPDB",         "IP abuse reports"),
    ("otx",           "AlienVault OTX",    "Threat-intel pulses on IPs / domains"),
    ("google_cse",    "Google CSE Key",    "Google Compare view search"),
    ("google_cx",     "Google CSE CX",     "Google Compare search-engine id"),
]


class ApiKeysDialog(FramelessDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent, title="TOP RECON — API Keys", width=560, height=640)
        self._settings = settings
        self._fields: dict[str, QLineEdit] = {}
        self._build()

    def _build(self) -> None:
        intro = QLabel(
            "Every key is optional. A source with no key shows “Needs Key” and is "
            "skipped — the rest of the engine runs regardless. Keys are saved to "
            "config/.env (git-ignored) and applied to this session immediately.")
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_UI};"
                            " font-size:11px;")
        self.body.addWidget(intro)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        host = QWidget(); col = QVBoxLayout(host); col.setSpacing(10)
        col.setContentsMargins(2, 4, 8, 4)
        from config.settings import KEY_ENV
        for kid, name, unlocks in KEY_SOURCES:
            env_name = KEY_ENV.get(kid, kid.upper())
            row = QVBoxLayout(); row.setSpacing(2)
            head = QHBoxLayout()
            lbl = QLabel(name)
            lbl.setStyleSheet(f"color:{theme.TEXT_BRIGHT}; font-family:{theme.FONT_MONO};"
                              " font-size:12px; font-weight:700;")
            env = QLabel(env_name)
            env.setStyleSheet(f"color:{theme.TEXT_FAINT}; font-family:{theme.FONT_MONO};"
                              " font-size:9px;")
            head.addWidget(lbl); head.addStretch(); head.addWidget(env)
            row.addLayout(head)
            hint = QLabel(unlocks)
            hint.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_UI};"
                               " font-size:10px;")
            row.addWidget(hint)
            edit = QLineEdit(self._settings.get_key(kid))
            edit.setEchoMode(QLineEdit.EchoMode.Password)
            edit.setPlaceholderText("not set")
            self._fields[kid] = edit
            row.addWidget(edit)
            col.addLayout(row)
        col.addStretch()
        scroll.setWidget(host)
        self.body.addWidget(scroll, 1)

        show = QPushButton("Show keys"); show.setCheckable(True)
        show.toggled.connect(self._toggle_echo)
        row = QHBoxLayout(); row.addWidget(show); row.addStretch()
        cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject)
        save = QPushButton("Save keys"); save.setObjectName("primary")
        save.clicked.connect(self._save)
        row.addWidget(cancel); row.addWidget(save)
        self.body.addLayout(row)

    def _toggle_echo(self, show: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password
        for edit in self._fields.values():
            edit.setEchoMode(mode)

    def _save(self) -> None:
        values = {kid: edit.text().strip() for kid, edit in self._fields.items()}
        try:
            self._settings.persist_keys(values)
        except Exception:  # noqa: BLE001 — a write failure must not crash the app
            pass
        self.accept()
