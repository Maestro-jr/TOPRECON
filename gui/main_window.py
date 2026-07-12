"""
TOP RECON — main dashboard window.

Assembles the reference layout: a metrics top bar, a persistent authorized-scope
banner, a left column of intel panels, the central entity graph (with a Google-
comparison toggle), a right column of module/queue panels, a bottom intelligence
summary + risk/detail/timeline tabs, and an engine-status footer. Drives the
async :class:`PivotEngine` and fans its events into the panels.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
                             QLabel, QFrame, QDockWidget, QStackedWidget,
                             QPushButton, QSplitter, QTabWidget,
                             QListWidget, QListWidgetItem, QFileDialog,
                             QTextBrowser, QMenu, QSizeGrip)

from gui import theme
from gui.widgets.titlebar import TitleBar
from gui.widgets.icon_rail import IconRail
from gui.widgets.entity_graph import EntityGraphView
from gui.signals import EngineBridge
from gui.panels.left_panels import (InputSeedPanel, EntityTypesPanel,
                                     DiscoveryDepthPanel, LiveFeedPanel)
from gui.panels.right_panels import (ActiveModulesPanel, PivotQueuePanel,
                                     RecentDiscoveriesPanel)
from gui.panels.summary import IntelligenceSummaryPanel
from gui.panels.risk import RiskPanel
from gui.panels.detail import EntityDetailPanel
from gui.panels.google_compare import GoogleComparePanel
from gui.widgets.common import Panel
from gui.widgets.dialog import FramelessDialog

from core.engine import PivotEngine, EngineState
from core.entities import EntityType, ENTITY_META
from reports import exporter

try:
    import psutil
    _PSUTIL = True
except Exception:  # noqa: BLE001
    _PSUTIL = False


class MainWindow(QMainWindow):
    def __init__(self, settings, registry, gate_result):
        super().__init__()
        self._settings = settings
        self._registry = registry
        self._gate = gate_result
        self._bridge = EngineBridge()
        self._engine = PivotEngine(registry, settings, self._bridge.dispatch)
        self._graph = self._engine.graph
        self._engine_task: Optional[asyncio.Task] = None
        self._last_findings: list = []
        self._started_at = time.monotonic()

        # Frameless: we paint our own title bar for a cohesive console look.
        self.setObjectName("mainWindow")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setWindowTitle("TOP RECON — Attack Surface Reconnaissance")
        self.setStyleSheet(theme.stylesheet())
        self.setMinimumSize(1120, 720)
        self.resize(1560, 940)

        self._build_topbar()
        self._build_central()
        self._build_icon_rail()
        self._build_left_dock()
        self._build_right_dock()
        self._build_bottom_dock()
        self._build_footer()
        self._wire_signals()

        # Throttled UI sync so a burst of discoveries doesn't thrash the graph.
        self._sync_timer = QTimer(self)
        self._sync_timer.setInterval(450)
        self._sync_timer.timeout.connect(self._sync_ui)
        self._sync_timer.start()
        self._footer_timer = QTimer(self)
        self._footer_timer.setInterval(1500)
        self._footer_timer.timeout.connect(self._update_footer)
        self._footer_timer.start()
        self._clock_timer = QTimer(self)
        self._clock_timer.setInterval(1000)
        self._clock_timer.timeout.connect(self._tick_clock)
        self._clock_timer.start()
        self._tick_clock()

    # ================================================================ topbar
    def _build_topbar(self) -> None:
        self._titlebar = TitleBar("HIVE PIVOT ENGINE",
                                  "AUTONOMOUS OSINT · ENTITY PIVOTING · INTEL FUSION")
        self._titlebar.new_recon_requested.connect(self.new_recon)
        self._titlebar.keys_requested.connect(self._open_keys)
        self._titlebar.minimize_requested.connect(self.showMinimized)
        self._titlebar.maximize_requested.connect(self._toggle_max)
        self._titlebar.close_requested.connect(self.close)
        # Expose the metric tiles under the names the rest of the window uses.
        t = self._titlebar.tiles
        self._m_status, self._m_depth, self._m_entities = t["status"], t["depth"], t["entities"]
        self._m_requests, self._m_success = t["requests"], t["success"]
        self._m_elapsed, self._m_thru = t["elapsed"], t["thru"]
        self.setMenuWidget(self._topbar_wrap(self._titlebar))

    def _topbar_wrap(self, bar: QWidget) -> QWidget:
        wrap = QWidget(); v = QVBoxLayout(wrap)
        v.setContentsMargins(0, 0, 0, 0); v.setSpacing(0)
        v.addWidget(bar)
        v.addWidget(self._build_subheader())
        return wrap

    def _build_subheader(self) -> QFrame:
        sub = QFrame(); sub.setObjectName("subHeader"); sub.setFixedHeight(40)
        h = QHBoxLayout(sub); h.setContentsMargins(14, 0, 14, 0); h.setSpacing(10)

        lab = QLabel("AUTHORISED SCOPE"); lab.setObjectName("subKey")
        h.addWidget(lab)
        chip = QFrame(); chip.setObjectName("scopeChip")
        ch = QHBoxLayout(chip); ch.setContentsMargins(10, 3, 12, 3); ch.setSpacing(6)
        dot = QLabel("●"); dot.setStyleSheet(f"color:{theme.ACCENT}; font-size:9px;")
        self._scope_chip_text = QLabel(); self._scope_chip_text.setObjectName("scopeChipText")
        ch.addWidget(dot); ch.addWidget(self._scope_chip_text)
        h.addWidget(chip)
        h.addSpacing(6)

        self._pill_active = QLabel("ACTIVE")
        self._pill_passive = QLabel("PASSIVE")
        h.addWidget(self._pill_active); h.addWidget(self._pill_passive)
        h.addSpacing(10)

        self._org_lbl = QLabel(); self._org_lbl.setObjectName("subMuted")
        h.addWidget(self._org_lbl)
        for txt in ("INFRASTRUCTURE ONLY", "NO PERSON TARGETING"):
            sep = QLabel("·"); sep.setObjectName("subMuted"); h.addWidget(sep)
            lbl = QLabel(txt); lbl.setObjectName("subMuted"); h.addWidget(lbl)
        h.addStretch()

        cfg = QPushButton("⚙  CONFIG"); cfg.setObjectName("configBtn")
        cfg.clicked.connect(self._open_keys)
        h.addWidget(cfg)
        self._refresh_banner()
        return sub

    def _refresh_banner(self) -> None:
        self._scope_chip_text.setText(self._gate.target)
        self._org_lbl.setText(f"ORG:  {self._gate.apex.upper()}")
        active = self._gate.active_scan
        self._pill_active.setObjectName("pillOn" if active else "pillOff")
        self._pill_passive.setObjectName("pillOn")
        for w in (self._pill_active, self._pill_passive):
            w.style().unpolish(w); w.style().polish(w)

    def _tick_clock(self) -> None:
        self._titlebar.set_clock(time.strftime("%H:%M:%S UTC", time.gmtime()))

    def _toggle_max(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self._titlebar.set_maximized(self.isMaximized())

    # =============================================================== central
    def _build_central(self) -> None:
        wrap = QWidget(); v = QVBoxLayout(wrap)
        v.setContentsMargins(8, 8, 8, 8); v.setSpacing(6)

        # toolbar: legend + controls
        tb = QHBoxLayout(); tb.setSpacing(8)
        title = QLabel("ENTITY GRAPH"); title.setObjectName("panelTitle")
        tb.addWidget(title)
        tb.addSpacing(12)
        for et in (EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS,
                   EntityType.CERTIFICATE, EntityType.PORT, EntityType.EMAIL):
            dot = QLabel(f"● {ENTITY_META[et].label.split()[0]}")
            dot.setStyleSheet(f"color:{ENTITY_META[et].color}; font-family:{theme.FONT_MONO};"
                              "font-size:9px;")
            tb.addWidget(dot)
        tb.addSpacing(10)
        obs = QLabel("──  observed"); obs.setStyleSheet(
            f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO}; font-size:9px;")
        piv = QLabel("╌╌  inferred"); piv.setStyleSheet(
            f"color:{theme.TEXT_MUTED}; font-family:{theme.FONT_MONO}; font-size:9px;")
        tb.addWidget(obs); tb.addWidget(piv)
        tb.addStretch()
        self._btn_relations = QPushButton("Relations"); self._btn_relations.setCheckable(True)
        self._btn_relations.setToolTip("Label every edge with the relationship it represents")
        self._btn_relations.toggled.connect(self._graph_view_set_relations)
        self._btn_google = QPushButton("GOOGLE COMPARE"); self._btn_google.setCheckable(True)
        self._btn_google.clicked.connect(self._toggle_google)
        btn_layout = QPushButton("Auto Layout"); btn_layout.clicked.connect(lambda: self._graph_view.auto_layout())
        btn_fit = QPushButton("Fit"); btn_fit.clicked.connect(lambda: self._graph_view.fit())
        self._btn_pause = QPushButton("⏸  PAUSE"); self._btn_pause.setObjectName("pauseBtn")
        self._btn_pause.setToolTip("Pause / resume outgoing requests")
        self._btn_pause.clicked.connect(self._toggle_pause)
        self._btn_stop = QPushButton("⏹  STOP"); self._btn_stop.setObjectName("stopBtn")
        self._btn_stop.setToolTip("Stop the scan — halt all outgoing requests")
        self._btn_stop.clicked.connect(self._on_stop)
        btn_hist = QPushButton("History"); btn_hist.clicked.connect(self._show_history)
        btn_summary = QPushButton("Summary"); btn_summary.setObjectName("primary")
        btn_summary.clicked.connect(self._show_summary)
        btn_export = QPushButton("Export ▾"); btn_export.clicked.connect(self._export_menu)
        for b in (self._btn_relations, self._btn_google, btn_layout, btn_fit,
                  self._btn_pause, self._btn_stop, btn_hist, btn_summary, btn_export):
            tb.addWidget(b)
        v.addLayout(tb)

        hint = QLabel("Click a node to trace its exposure path from the seed · "
                      "click a primary node to isolate or centralise it · "
                      "node size grows with risk and connectivity")
        hint.setStyleSheet(f"color:{theme.TEXT_FAINT}; font-family:{theme.FONT_MONO};"
                           " font-size:9px;")
        v.addWidget(hint)
        v.addWidget(self._build_focus_bar())

        self._stack = QStackedWidget()
        self._graph_view = EntityGraphView(self._graph)
        self._graph_view.node_clicked.connect(self._on_node_clicked)
        self._google = GoogleComparePanel(self._graph)
        self._stack.addWidget(self._graph_view)
        self._stack.addWidget(self._google)
        v.addWidget(self._stack, 1)
        self.setCentralWidget(wrap)

    def _build_focus_bar(self) -> QFrame:
        """Node-focus controls — shown when a non-seed node is selected."""
        self._focus_key: Optional[str] = None
        bar = QFrame(); bar.setObjectName("focusBar")
        h = QHBoxLayout(bar); h.setContentsMargins(12, 6, 10, 6); h.setSpacing(10)
        icon = QLabel("◎"); icon.setStyleSheet(f"color:{theme.ACCENT_TEAL}; font-size:14px;")
        self._focus_chip = QLabel("—"); self._focus_chip.setObjectName("focusChip")
        tag = QLabel("FOCUS NODE"); tag.setObjectName("focusHint")
        h.addWidget(icon); h.addWidget(self._focus_chip); h.addSpacing(6); h.addWidget(tag)
        h.addStretch()
        self._btn_isolate = QPushButton("⛶  ISOLATE"); self._btn_isolate.setObjectName("focusBtn")
        self._btn_isolate.setCheckable(True)
        self._btn_isolate.setToolTip("Show only this node and its sub-links; hide the rest")
        self._btn_isolate.toggled.connect(self._on_isolate)
        self._btn_centralize = QPushButton("✦  CENTRALISE"); self._btn_centralize.setObjectName("focusBtn")
        self._btn_centralize.setCheckable(True)
        self._btn_centralize.setToolTip("Re-root the layout on this node and arrange its links around it")
        self._btn_centralize.toggled.connect(self._on_centralize)
        exitb = QPushButton("✕"); exitb.setObjectName("focusBtn")
        exitb.setToolTip("Exit focus — restore the full graph")
        exitb.clicked.connect(self._reset_focus)
        for b in (self._btn_isolate, self._btn_centralize, exitb):
            h.addWidget(b)
        bar.setVisible(False)
        self._focus_bar = bar
        return bar

    # ============================================================== icon rail
    def _build_icon_rail(self) -> None:
        rail = IconRail()
        rail.add_button("▦", "Overview — fit the graph", self._rail_overview).setChecked(True)
        rail.add_button("⬡", "Entity graph", self._rail_graph)
        rail.add_button("▤", "Intelligence summary", lambda: self._rail_tab("_summary"))
        rail.add_button("◈", "Attack surface risk", lambda: self._rail_tab("_risk"))
        rail.add_button("◎", "Entity detail", lambda: self._rail_tab("_detail"))
        rail.add_button("◷", "Discovery timeline", lambda: self._rail_tab("_timeline"))
        rail.add_button("⧉", "Google comparison", self._rail_google)
        rail.add_spacer()
        rail.add_button("⚿", "API keys", self._open_keys, checkable=False)
        dock = QDockWidget("", self); dock.setObjectName("dock_rail")
        dock.setTitleBarWidget(QWidget())
        dock.setFeatures(QDockWidget.DockWidgetFeature.NoDockWidgetFeatures)
        dock.setFixedWidth(52); dock.setWidget(rail)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)
        self._rail_dock = dock

    def _rail_overview(self) -> None:
        self._btn_google.setChecked(False); self._stack.setCurrentWidget(self._graph_view)
        self._graph_view.fit()

    def _rail_graph(self) -> None:
        self._btn_google.setChecked(False); self._stack.setCurrentWidget(self._graph_view)

    def _rail_google(self) -> None:
        self._btn_google.setChecked(True); self._toggle_google()

    def _rail_tab(self, attr: str) -> None:
        self._stack.setCurrentWidget(self._graph_view); self._btn_google.setChecked(False)
        w = getattr(self, attr, None)
        if w is not None:
            self._bottom_tabs.setCurrentWidget(w)

    # -- node focus (isolate / centralise) ----------------------------------
    def _on_isolate(self, on: bool) -> None:
        if self._focus_key:
            self._graph_view.isolate(self._focus_key, on)

    def _on_centralize(self, on: bool) -> None:
        if self._focus_key:
            self._graph_view.centralize(self._focus_key, on)

    def _reset_focus(self) -> None:
        for b in (self._btn_isolate, self._btn_centralize):
            b.blockSignals(True); b.setChecked(False); b.blockSignals(False)
        self._graph_view.isolate(None, False)
        self._graph_view.centralize(None, False)
        self._focus_bar.setVisible(False)
        self._focus_key = None

    # ============================================================== left dock
    def _build_left_dock(self) -> None:
        self._input_seed = InputSeedPanel()
        self._input_seed.set_seed(self._gate.target, self._gate.apex,
                                  self._gate.active_scan)
        self._entity_types = EntityTypesPanel()
        self._entity_types.filter_changed.connect(self._on_filter)
        self._depth = DiscoveryDepthPanel()
        self._live_feed = LiveFeedPanel()

        split = QSplitter(Qt.Orientation.Vertical)
        for w in (self._input_seed, self._entity_types, self._depth, self._live_feed):
            split.addWidget(w)
        split.setSizes([90, 320, 150, 240])
        intel = self._add_dock("INTELLIGENCE", split,
                               Qt.DockWidgetArea.LeftDockWidgetArea, 300)
        # Keep the icon rail pinned to the far left, intel panel to its right.
        if getattr(self, "_rail_dock", None) is not None:
            self.splitDockWidget(self._rail_dock, intel, Qt.Orientation.Horizontal)

    # ============================================================= right dock
    def _build_right_dock(self) -> None:
        self._modules = ActiveModulesPanel()
        self._modules.build(self._engine.module_list())
        self._pivot_q = PivotQueuePanel()
        self._recent = RecentDiscoveriesPanel()
        split = QSplitter(Qt.Orientation.Vertical)
        for w in (self._modules, self._pivot_q, self._recent):
            split.addWidget(w)
        split.setSizes([340, 260, 200])
        self._add_dock("OPERATIONS", split, Qt.DockWidgetArea.RightDockWidgetArea, 340)

    # ============================================================ bottom dock
    def _build_bottom_dock(self) -> None:
        tabs = QTabWidget()
        self._summary = IntelligenceSummaryPanel(self._graph)
        self._risk = RiskPanel(self._graph)
        self._risk.finding_clicked.connect(self._focus_entity)
        self._detail = EntityDetailPanel(self._graph)
        self._detail.relation_clicked.connect(self._focus_entity)
        self._timeline = self._build_timeline()
        tabs.addTab(self._summary, "INTELLIGENCE SUMMARY")
        tabs.addTab(self._risk, "ATTACK SURFACE RISK")
        tabs.addTab(self._detail, "ENTITY DETAIL")
        tabs.addTab(self._timeline, "TIMELINE")
        # Show every tab title in full — never elide or cram them.
        tabs.setDocumentMode(True)
        tb = tabs.tabBar()
        tb.setElideMode(Qt.TextElideMode.ElideNone)
        tb.setExpanding(False)
        tb.setUsesScrollButtons(True)
        self._bottom_tabs = tabs
        self._add_dock("ANALYSIS", tabs, Qt.DockWidgetArea.BottomDockWidgetArea, 250)

    def _build_timeline(self) -> Panel:
        p = Panel("Discovery Timeline")
        self._timeline_list = QListWidget()
        p.body.addWidget(self._timeline_list)
        return p

    def _add_dock(self, title: str, widget: QWidget, area, size: int) -> QDockWidget:
        dock = QDockWidget(title, self)
        dock.setObjectName(f"dock_{title}")
        dock.setWidget(widget)
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable |
                         QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        dock.setStyleSheet(
            f"QDockWidget {{ color:{theme.ACCENT_TEAL}; font-family:{theme.FONT_MONO};"
            "font-size:10px; titlebar-close-icon:none; }}"
            f"QDockWidget::title {{ background:{theme.BG_PANEL}; padding:4px;"
            f" border-bottom:1px solid {theme.BORDER}; }}")
        self.addDockWidget(area, dock)
        return dock

    # ================================================================ footer
    def _build_footer(self) -> None:
        sb = self.statusBar()
        sb.setStyleSheet(f"QStatusBar {{ background:{theme.BG_PANEL};"
                         f" color:{theme.TEXT_MUTED}; border-top:1px solid {theme.BORDER};"
                         f" font-family:{theme.FONT_MONO}; font-size:10px; }}"
                         "QStatusBar::item { border: none; }")
        self._foot = QLabel("ENGINE IDLE")
        sb.addWidget(self._foot)
        # Frameless windows lose native edge-resize; a size grip restores it.
        grip = QSizeGrip(sb)
        sb.addPermanentWidget(grip)

    # =============================================================== signals
    def _wire_signals(self) -> None:
        self._bridge.entity_added.connect(self._on_entity_added)
        self._bridge.module_status.connect(self._modules.update_module)
        self._bridge.stats.connect(self._on_stats)
        self._bridge.log.connect(self._live_feed.append)
        self._bridge.state.connect(self._on_state)

    def start_scan(self) -> None:
        loop = asyncio.get_event_loop()
        seed_type = EntityType.DOMAIN
        self._engine_task = loop.create_task(
            self._engine.run(self._gate.target, seed_type,
                             active_enabled=self._gate.active_scan,
                             max_depth=self._settings.max_depth))

    # -- event handlers -----------------------------------------------------
    def _on_entity_added(self, entity) -> None:
        self._recent.add(entity)
        ts = time.strftime("%H:%M:%S")
        it = QListWidgetItem(f"{ts}  [{ENTITY_META[entity.etype].short}] {entity.value}")
        it.setForeground(QColor(ENTITY_META[entity.etype].color))
        self._timeline_list.insertItem(0, it)
        while self._timeline_list.count() > 500:
            self._timeline_list.takeItem(self._timeline_list.count() - 1)
        self._graph_view.mark_dirty()

    def _on_stats(self, s: dict) -> None:
        self._m_entities.set_value(str(s.get("entities", 0)))
        self._m_requests.set_value(f"{s.get('requests', 0):,}")
        self._m_success.set_value(f"{s.get('success_rate', 100):.1f}%")
        self._m_depth.set_value(f"{s.get('depth_reached', 0)} / {s.get('max_depth', 4)}")
        self._m_thru.set_value(f"{s.get('throughput', 0)} req/s")
        el = int(s.get("elapsed", 0))
        self._m_elapsed.set_value(f"{el//3600:02d}:{(el%3600)//60:02d}:{el%60:02d}")

    def _on_state(self, state: str, stats: dict) -> None:
        stopped = getattr(self, "_user_stopped", False)
        if state == EngineState.DONE and stopped:
            self._m_status.set_value("STOPPED"); self._m_status.set_color(theme.ERRORC)
        else:
            self._m_status.set_value(state)
            col = {EngineState.RUNNING: theme.ACCENT, EngineState.PAUSED: theme.QUEUED,
                   EngineState.DONE: theme.ACCENT_TEAL, EngineState.IDLE: theme.TEXT_MUTED}
            self._m_status.set_color(col.get(state, theme.TEXT))
        if state == EngineState.RUNNING and not stopped:
            self._btn_pause.setEnabled(True); self._btn_stop.setEnabled(True)
        if state == EngineState.DONE:
            self._btn_pause.setText("⏸  PAUSE"); self._btn_pause.setEnabled(False)
            self._btn_stop.setEnabled(False)
            self._sync_ui()
            self._save_snapshot()

    def _save_snapshot(self) -> None:
        try:
            from profiles import store
            from audit.attestation import record_event
            path = store.save_snapshot(self._settings.profiles_dir,
                                       self._gate.apex, self._graph, self._meta())
            record_event(self._settings.audit_dir, "scan_complete",
                         f"{len(self._graph)} entities → {path.name}", self._gate.target)
            self.statusBar().showMessage(f"Scan saved to history: {path.name}", 5000)
        except Exception:  # noqa: BLE001
            pass

    def _show_history(self) -> None:
        from gui.panels.history_replay import HistoryDialog
        HistoryDialog(self._settings, self._gate.apex, self._graph, self).exec()

    def _open_keys(self) -> None:
        """Open the API Keys dialog; on save, re-evaluate module availability so
        newly-keyed sources flip from 'Needs Key' to 'Idle' without a restart."""
        from gui.panels.keys_dialog import ApiKeysDialog
        dlg = ApiKeysDialog(self._settings, self)
        if dlg.exec() != ApiKeysDialog.DialogCode.Accepted:
            return
        self._engine.refresh_module_availability()
        self._modules.reset(self._engine.module_list())
        self.statusBar().showMessage(
            "API keys saved to config/.env and applied to this session.", 5000)

    # ---- New Recon (switch target in-app, no restart) ---------------------
    def new_recon(self) -> None:
        """Open the Authorization Gate again for a NEW target and, once the
        operator re-attests, reset the whole console and scan the new scope."""
        from gui.authorization_gate import AuthorizationGate
        gate = AuthorizationGate(self._settings, self)
        if gate.exec() != AuthorizationGate.DialogCode.Accepted:
            return
        result = gate.result()
        if result is None:
            return
        # Tear down the current scan, keep the graph object identity.
        self._engine.stop()
        if self._engine_task is not None:
            self._engine_task.cancel()
            self._engine_task = None
        self._engine.reset()
        self._gate = result
        self._reset_ui_state()
        self._refresh_banner()
        self._input_seed.set_seed(result.target, result.apex, result.active_scan)
        self.statusBar().showMessage(f"New recon authorized: {result.target}", 4000)
        self.start_scan()

    def _reset_ui_state(self) -> None:
        """Clear every panel so a re-scan starts from a blank console."""
        self._reset_focus()
        self._graph_view.clear_all()
        self._live_feed.clear()
        self._recent.clear()
        self._detail.clear()
        self._timeline_list.clear()
        self._entity_types.reset_filter()
        self._entity_types.update_counts({})
        self._depth.update_depths({}, self._settings.max_depth)
        self._pivot_q.update_queue([])
        self._modules.reset(self._engine.module_list())
        self._risk.refresh()
        self._summary.update_summary(self._engine.module_list(), 0)
        self._google.update_recon(0)
        self._user_stopped = False
        self._last_graph_v = -1
        self._btn_pause.setEnabled(True); self._btn_pause.setText("⏸  PAUSE")
        self._btn_stop.setEnabled(True)
        self._btn_google.setChecked(False)
        self._stack.setCurrentWidget(self._graph_view)
        self._last_findings = []
        self._bottom_tabs.setCurrentWidget(self._summary)
        for m in (self._m_entities, self._m_requests):
            m.set_value("0")
        self._m_status.set_value("IDLE")
        self._m_elapsed.set_value("00:00:00")

    # -- throttled UI sync --------------------------------------------------
    def _sync_ui(self) -> None:
        try:
            # Graph-derived panels only recompute when the graph actually changed
            # — idle frames (a settled scan) cost nothing.
            gv = self._graph.version
            if gv != getattr(self, "_last_graph_v", -1):
                self._last_graph_v = gv
                self._graph_view.refresh()
                self._entity_types.update_counts(self._graph.counts_by_type())
                by_depth = {int(k) if not isinstance(k, int) else k: v
                            for k, v in self._graph.counts_by_depth().items()}
                self._depth.update_depths(by_depth, self._engine.max_depth)
                self._summary.update_summary(self._engine.module_list(),
                                             self._engine.rate.total_requests)
                self._last_findings = self._risk.refresh()
                self._google.update_recon(len(self._last_findings))
            # The pivot queue changes as work is dequeued even with no new
            # entities, so it updates every tick (internally change-gated).
            self._pivot_q.update_queue(self._engine.pending_list())
        except Exception:  # noqa: BLE001 — a sync hiccup must not crash the UI
            pass

    def _update_footer(self) -> None:
        mem = cpu = "—"
        if _PSUTIL:
            try:
                cpu = f"{psutil.cpu_percent():.0f}%"
                vm = psutil.virtual_memory()
                mem = f"{vm.used/1e9:.1f}/{vm.total/1e9:.1f} GB"
            except Exception:  # noqa: BLE001
                pass
        up = int(time.monotonic() - self._started_at)
        s = self._engine.stats()
        avail = sum(1 for m in self._engine.module_list()
                    if m.status not in ("Needs Key", "Not Installed", "Disabled"))
        self._foot.setText(
            f"ENGINE {s['state']}   ·   WORKERS {s['inflight']}/{s['workers']}   ·   "
            f"RATE LIMIT {s['rate_per_min']:,}/min   ·   MEM {mem}   ·   CPU {cpu}   ·   "
            f"UPTIME {up//60:02d}m {up%60:02d}s   ·   MODULES {avail}/{len(self._engine.modules)} READY   ·   "
            f"LAST UPDATE {time.strftime('%H:%M:%S')}")

    # -- interactions -------------------------------------------------------
    def _graph_view_set_relations(self, on: bool) -> None:
        self._graph_view.set_show_relations(on)

    def _on_filter(self, etype) -> None:
        self._graph_view.set_filter(etype)

    def _on_node_clicked(self, key: str) -> None:
        self._detail.show_entity(key)
        self._bottom_tabs.setCurrentWidget(self._detail)
        # A non-seed node can be focused (isolated / centralised) via the bar.
        ent = self._graph.get(key)
        if ent is not None and key != self._graph.seed_key:
            self._focus_key = key
            self._focus_chip.setText(ent.value)
            if self._btn_isolate.isChecked():
                self._graph_view.isolate(key, True)
            if self._btn_centralize.isChecked():
                self._graph_view.centralize(key, True)
            self._focus_bar.setVisible(True)
        else:
            self._reset_focus()

    def _focus_entity(self, key: str) -> None:
        self._stack.setCurrentWidget(self._graph_view)
        self._btn_google.setChecked(False)
        self._graph_view.select_key(key)
        self._detail.show_entity(key)
        self._bottom_tabs.setCurrentWidget(self._detail)

    def _toggle_pause(self) -> None:
        if self._engine.state == EngineState.RUNNING:
            self._engine.pause()
            self._btn_pause.setText("▶  RESUME")
            self.statusBar().showMessage(
                "Paused — outgoing requests halted. Press RESUME to continue.", 4000)
        elif self._engine.state == EngineState.PAUSED:
            self._engine.resume()
            self._btn_pause.setText("⏸  PAUSE")
            self.statusBar().showMessage("Resumed — sending requests again.", 3000)

    def _on_stop(self) -> None:
        """Halt the scan entirely — no further requests are sent."""
        self._engine.stop()
        self._user_stopped = True
        self._btn_stop.setEnabled(False)
        self._btn_pause.setEnabled(False)
        self._btn_pause.setText("⏸  PAUSE")
        # Immediate feedback — the engine winds down any single in-flight call,
        # but no NEW requests go out from this moment.
        self._m_status.set_value("STOPPED")
        self._m_status.set_color(theme.ERRORC)
        self.statusBar().showMessage(
            "Scan stopped — no further requests will be sent. "
            "Use ＋ NEW RECON to start a new target.", 6000)

    def closeEvent(self, event) -> None:
        """Quiesce cleanly so the async loop's thread-pool isn't left mid-request
        on shutdown (avoids the executor-join hang / KeyboardInterrupt on exit)."""
        try:
            self._engine.stop()
            if self._engine_task is not None:
                self._engine_task.cancel()
        except Exception:  # noqa: BLE001
            pass
        for name in ("_sync_timer", "_footer_timer", "_clock_timer"):
            t = getattr(self, name, None)
            if t is not None:
                try:
                    t.stop()
                except Exception:  # noqa: BLE001
                    pass
        super().closeEvent(event)

    def _toggle_google(self) -> None:
        if self._btn_google.isChecked():
            self._stack.setCurrentWidget(self._google)
            self._google.update_recon(len(self._last_findings))
            loop = asyncio.get_event_loop()
            loop.create_task(self._fetch_google())
        else:
            self._stack.setCurrentWidget(self._graph_view)

    async def _fetch_google(self) -> None:
        from transforms.websearch import fetch_google
        try:
            results, note = await fetch_google(self._settings, self._gate.apex)
            self._google.set_google_results(results, note)
        except Exception:  # noqa: BLE001
            self._google.set_google_results([], "Google search unavailable.")

    # -- summary + export ---------------------------------------------------
    def _show_summary(self) -> None:
        dlg = FramelessDialog(self, title="TOP RECON — Scan Summary", width=900, height=700)
        dlg.resize(900, 700)
        view = QTextBrowser(); view.setOpenExternalLinks(True)
        meta = {"target": self._gate.target, "apex": self._gate.apex}
        view.setHtml(exporter._report_html(self._graph, meta))
        dlg.body.addWidget(view, 1)
        row = QHBoxLayout(); row.addStretch()
        for label, fn in (("Export JSON", self._export_json),
                          ("Export HTML", self._export_html),
                          ("Export PDF", self._export_pdf)):
            b = QPushButton(label); b.clicked.connect(fn); row.addWidget(b)
        close = QPushButton("Close"); close.setObjectName("primary")
        close.clicked.connect(dlg.accept); row.addWidget(close)
        dlg.body.addLayout(row)
        dlg.exec()

    def _export_menu(self) -> None:
        m = QMenu(self)
        m.addAction("Export JSON", self._export_json)
        m.addAction("Export HTML report", self._export_html)
        m.addAction("Export PDF report", self._export_pdf)
        m.exec(self.cursor().pos())

    def _meta(self) -> dict:
        return {"target": self._gate.target, "apex": self._gate.apex,
                "scope_note": self._gate.scope_note,
                "active_scan": self._gate.active_scan}

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", str(self._settings.reports_dir /
            f"{self._gate.apex}_recon.json"), "JSON (*.json)")
        if path:
            from pathlib import Path
            exporter.export_json(self._graph, Path(path), self._meta())
            self.statusBar().showMessage(f"Saved {path}", 4000)

    def _export_html(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export HTML", str(self._settings.reports_dir /
            f"{self._gate.apex}_recon.html"), "HTML (*.html)")
        if path:
            from pathlib import Path
            exporter.export_html(self._graph, Path(path), self._meta())
            self.statusBar().showMessage(f"Saved {path}", 4000)

    def _export_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF", str(self._settings.reports_dir /
            f"{self._gate.apex}_recon.pdf"), "PDF (*.pdf)")
        if path:
            from pathlib import Path
            out, is_pdf = exporter.export_pdf(self._graph, Path(path), self._meta())
            msg = f"Saved {out}" if is_pdf else f"No PDF engine — saved HTML: {out}"
            self.statusBar().showMessage(msg, 5000)
