"""
Scan history, diff-since-last-scan, and demo/replay mode.

HistoryDialog lists saved scans for the target and can diff the current scan
against the previous one (new exposures highlighted). ReplayDialog reconstructs
a saved scan and plays it back node-by-node in discovery order — for presenting
a scan to a non-technical audience.
"""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QListWidget,
                             QListWidgetItem, QPushButton, QSlider)

from gui import theme
from gui.widgets.entity_graph import EntityGraphView
from gui.widgets.dialog import FramelessDialog
from core.entities import Entity, EntityType, ENTITY_META
from core.graph import EntityGraph
from profiles import store


def _entity_from_dict(d: dict) -> Entity:
    etype = EntityType(d["type"])
    e = Entity(etype=etype, value=d["value"], depth=d.get("depth", 0),
               sources=set(d.get("sources", [])), data=d.get("data", {}))
    e.discovered_at = d.get("discovered_at", 0.0)
    e.risk = d.get("risk"); e.risk_reason = d.get("risk_reason", "")
    return e


def _rebuild_graph(snapshot: dict) -> EntityGraph:
    g = EntityGraph()
    nodes = snapshot.get("graph", {}).get("nodes", [])
    seed = snapshot.get("graph", {}).get("seed")
    for n in nodes:
        e = _entity_from_dict(n)
        if e.key == seed:
            g.set_seed(e)
        else:
            g.add_entity(e)
    for edge in snapshot.get("graph", {}).get("edges", []):
        g.add_edge(edge["src"], edge["dst"], edge.get("kind", "discovered"))
    return g


class HistoryDialog(FramelessDialog):
    def __init__(self, settings, apex: str, current_graph, parent=None):
        super().__init__(parent, title=f"Scan History — {apex}", width=660)
        self._settings = settings
        self._apex = apex
        self._graph = current_graph
        self.resize(660, 540)
        v = self.body

        v.addWidget(self._h("SAVED SCANS"))
        self._list = QListWidget()
        v.addWidget(self._list, 1)
        self._reload()

        v.addWidget(self._h("DIFF SINCE LAST SCAN"))
        self._diff = QListWidget()
        v.addWidget(self._diff, 1)

        row = QHBoxLayout(); row.addStretch()
        b_diff = QPushButton("Diff vs Previous"); b_diff.clicked.connect(self._do_diff)
        b_replay = QPushButton("Replay Selected"); b_replay.clicked.connect(self._replay)
        close = QPushButton("Close"); close.setObjectName("primary"); close.clicked.connect(self.accept)
        for b in (b_diff, b_replay, close):
            row.addWidget(b)
        v.addLayout(row)

    def _h(self, t: str) -> QLabel:
        l = QLabel(t); l.setObjectName("sectionLabel"); return l

    def _reload(self) -> None:
        self._list.clear()
        for snap in store.list_snapshots(self._settings.profiles_dir, self._apex):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(snap["saved"]))
            it = QListWidgetItem(f"{when}   ·   {snap['entities']} entities   ·   {snap['ts']}")
            it.setData(Qt.ItemDataRole.UserRole, snap["path"])
            self._list.addItem(it)
        if self._list.count() == 0:
            self._list.addItem(QListWidgetItem("(no saved scans yet)"))

    def _do_diff(self) -> None:
        prev = store.previous_snapshot(self._settings.profiles_dir, self._apex)
        self._diff.clear()
        if not prev:
            self._diff.addItem(QListWidgetItem("No previous scan to diff against."))
            return
        d = store.diff_against(prev, self._graph)
        head = QListWidgetItem(
            f"vs {d['prev_ts']}:  {len(d['new'])} NEW, {len(d['removed'])} removed  "
            f"({d['prev_count']} → {d['cur_count']} entities)")
        head.setForeground(QColor(theme.ACCENT_TEAL))
        self._diff.addItem(head)
        for e in d["new_entities"][:200]:
            it = QListWidgetItem(f"  + [{ENTITY_META[e.etype].short}] {e.value}")
            it.setForeground(QColor(theme.ACCENT))
            self._diff.addItem(it)
        for key in d["removed"][:80]:
            it = QListWidgetItem(f"  - {key}")
            it.setForeground(QColor(theme.TEXT_MUTED))
            self._diff.addItem(it)

    def _replay(self) -> None:
        item = self._list.currentItem()
        if item is None:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path:
            return
        snap = store.load_snapshot(path)
        ReplayDialog(snap, self).exec()


class ReplayDialog(FramelessDialog):
    """Play back a saved scan node-by-node in discovery order."""

    def __init__(self, snapshot: dict, parent=None):
        super().__init__(parent, title="Demo / Replay Mode", width=1100, height=760)
        self.resize(1100, 760)
        self._full = _rebuild_graph(snapshot)
        # order entities by discovery time
        nodes, _ = self._full.snapshot()
        self._order = sorted(nodes, key=lambda e: (e.discovered_at, e.depth))
        self._edges = snapshot.get("graph", {}).get("edges", [])
        self._seed = snapshot.get("graph", {}).get("seed")
        self._idx = 0
        self._live = EntityGraph()

        v = self.body
        top = QHBoxLayout()
        self._caption = QLabel("Ready to replay — press Play")
        self._caption.setStyleSheet(f"color:{theme.ACCENT}; font-family:{theme.FONT_MONO};"
                                    "font-size:12px;")
        top.addWidget(self._caption); top.addStretch()
        self._progress = QLabel(f"0 / {len(self._order)}")
        self._progress.setStyleSheet(f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO};")
        top.addWidget(self._progress)
        v.addLayout(top)

        self._view = EntityGraphView(self._live)
        v.addWidget(self._view, 1)

        ctl = QHBoxLayout()
        self._play = QPushButton("▶ Play"); self._play.setObjectName("primary")
        self._play.clicked.connect(self._toggle)
        step = QPushButton("Step ▸"); step.clicked.connect(self._step)
        reset = QPushButton("⟲ Reset"); reset.clicked.connect(self._reset)
        ctl.addWidget(self._play); ctl.addWidget(step); ctl.addWidget(reset)
        ctl.addSpacing(16)
        ctl.addWidget(QLabel("Speed"))
        self._speed = QSlider(Qt.Orientation.Horizontal)
        self._speed.setMinimum(1); self._speed.setMaximum(20); self._speed.setValue(6)
        self._speed.setFixedWidth(160)
        ctl.addWidget(self._speed)
        ctl.addStretch()
        close = QPushButton("Close"); close.clicked.connect(self.accept)
        ctl.addWidget(close)
        v.addLayout(ctl)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._step)

    def _toggle(self) -> None:
        if self._timer.isActive():
            self._timer.stop(); self._play.setText("▶ Play")
        else:
            self._timer.start(int(1100 / self._speed.value()))
            self._play.setText("⏸ Pause")

    def _reset(self) -> None:
        self._timer.stop(); self._play.setText("▶ Play")
        self._idx = 0
        self._live = EntityGraph()
        self._view._model = self._live
        self._view._nodes.clear(); self._view._edges.clear(); self._view._pos.clear()
        self._view._scene.clear()
        self._progress.setText(f"0 / {len(self._order)}")
        self._caption.setText("Ready to replay — press Play")

    def _step(self) -> None:
        if self._idx >= len(self._order):
            self._timer.stop(); self._play.setText("▶ Play")
            self._caption.setText("Replay complete.")
            return
        ent = self._order[self._idx]
        if ent.key == self._seed:
            self._live.set_seed(ent)
        else:
            self._live.add_entity(ent)
        # add edges among present nodes
        for e in self._edges:
            if self._live.has(e["src"]) and self._live.has(e["dst"]):
                self._live.add_edge(e["src"], e["dst"], e.get("kind", "discovered"),
                                    e.get("label", ""))
        self._view.mark_dirty(); self._view.refresh()
        if self._idx % 4 == 0:
            self._view.fit()
        meta = ENTITY_META[ent.etype]
        self._caption.setText(f"Discovered  [{meta.label}]  {ent.value}")
        self._caption.setStyleSheet(f"color:{meta.color}; font-family:{theme.FONT_MONO}; font-size:12px;")
        self._idx += 1
        self._progress.setText(f"{self._idx} / {len(self._order)}")
