"""
Interactive entity graph — the relationship map at the centre of TOP RECON.

The view renders the recon graph as colour-coded octagon nodes rooted on the
seed domain. Every edge is a *typed relationship* (resolves, exposes, presents
cert, CNAME, impersonated-by, …), not a generic link — so the graph reads as an
attack-surface map rather than a cloud of dots.

Reading it:
  * Node colour  = entity type; node size grows with risk and connectivity.
  * Solid edge   = directly observed relationship (``discovered``).
  * Dashed edge  = inferred / pivoted relationship (``pivot``).
  * Click a node = trace and highlight the exposure path from the seed to it,
    dimming everything else, and label that node's direct relationships.

Layout is force-directed (networkx spring layout), recomputed on a throttled
timer as the graph grows. Pan (drag), zoom (wheel), and per-type filtering.
"""

from __future__ import annotations

import math
from typing import Optional

import networkx as nx
from PyQt6.QtCore import Qt, QRectF, QPointF, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QPainter, QPen, QPolygonF, QFont
from PyQt6.QtWidgets import (QGraphicsView, QGraphicsScene, QGraphicsItem,
                             QGraphicsObject)

from gui import theme
from core.entities import EntityType, ENTITY_META
from core.graph import EDGE_PIVOT


def _octagon(r: float) -> QPolygonF:
    return QPolygonF([
        QPointF(r * math.cos(math.pi / 8 + i * math.pi / 4),
                r * math.sin(math.pi / 8 + i * math.pi / 4))
        for i in range(8)])


# Source/destination entity types → the human relationship an edge represents.
# ``raw`` is the label the producing transform recorded (record type, etc.).
def relationship(dst_type: EntityType, kind: str, raw: str) -> str:
    r = (raw or "").strip()
    ru = r.upper()
    rl = r.lower()
    if dst_type == EntityType.PORT:
        return "exposes"
    if dst_type == EntityType.SERVICE:
        return "runs"
    if dst_type == EntityType.CERTIFICATE:
        return "presents"
    if dst_type == EntityType.IP_ADDRESS:
        return "resolves"
    if dst_type == EntityType.DNS_RECORD:
        return "CNAME→" if ru.startswith("CNAME") else (ru or "DNS")
    if dst_type == EntityType.SUBDOMAIN:
        if rl in ("ct", "san", "certificate transparency"):
            return "SAN"
        if "ptr" in rl or "reverse" in rl:
            return "rev-DNS"
        return "subdomain"
    if dst_type == EntityType.DOMAIN:
        return "related"
    if dst_type == EntityType.TYPOSQUAT:
        return "look-alike"
    if dst_type == EntityType.EMAIL:
        return "email"
    if dst_type == EntityType.WEB_TECH:
        return "tech"
    if dst_type == EntityType.URL:
        return "url"
    if dst_type == EntityType.CLOUD_BUCKET:
        return "bucket"
    if dst_type == EntityType.LEAKED_SECRET:
        return "leak"
    if dst_type == EntityType.BREACH_RECORD:
        return "breach"
    if dst_type in (EntityType.ASN, EntityType.NETBLOCK):
        return "hosted-in"
    if dst_type == EntityType.WHOIS_RECORD:
        return "whois"
    return "pivot" if kind == EDGE_PIVOT else "linked"


_RISK_BUMP = {"critical": 10, "high": 7, "medium": 3}


class _NodeItem(QGraphicsObject):
    """A single octagon node, sized by risk and connectivity."""

    def __init__(self, key: str, etype: EntityType, label: str,
                 seed: bool = False, risk: Optional[str] = None):
        super().__init__()
        self.key = key
        self.etype = etype
        self._label = label
        self._seed = seed
        self._risk = risk
        self._hover = False
        self._selected = False
        self._dim = False
        self._r = 26.0 if seed else 14.0
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)

    def boundingRect(self) -> QRectF:
        m = self._r + 26
        return QRectF(-m, -m, 2 * m, 2 * m + 14)

    @property
    def radius(self) -> float:
        return self._r

    def set_selected(self, on: bool) -> None:
        self._selected = on
        self.update()

    def set_dim(self, on: bool) -> None:
        if on != self._dim:
            self._dim = on
            self.update()

    def set_metrics(self, risk: Optional[str], degree: int) -> None:
        self._risk = risk
        if not self._seed:
            self.prepareGeometryChange()
            self._r = 14.0 + min(11, _RISK_BUMP.get(risk or "", 0) + min(6, degree // 3))
        self.update()

    def paint(self, p: QPainter, *_):
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(ENTITY_META[self.etype].color)
        alpha = 90 if self._dim else 255
        if self._selected or self._hover:
            p.setPen(QPen(QColor(color).lighter(130), 2.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPolygon(_octagon(self._r + 5))
        risk_col = theme.SEV.get(self._risk or "", None)
        border = QColor(risk_col) if risk_col else QColor(color)
        border.setAlpha(alpha)
        fill = QColor(color); fill.setAlpha((70 if self._seed else 46) * alpha // 255)
        p.setPen(QPen(border, 2.4 if self._seed else 1.6))
        p.setBrush(QBrush(fill))
        p.drawPolygon(_octagon(self._r))
        tag_col = QColor(theme.TEXT_BRIGHT if self._seed else color).lighter(140)
        tag_col.setAlpha(alpha)
        p.setPen(tag_col)
        p.setFont(QFont("Consolas", 8 if not self._seed else 9, QFont.Weight.Bold))
        p.drawText(QRectF(-self._r, -self._r, 2 * self._r, 2 * self._r),
                   Qt.AlignmentFlag.AlignCenter, ENTITY_META[self.etype].short)
        lbl_col = QColor(theme.TEXT_BRIGHT if self._seed else theme.TEXT)
        lbl_col.setAlpha(alpha)
        p.setPen(lbl_col)
        p.setFont(QFont("Consolas", 8))
        lbl = self._label if len(self._label) <= 26 else self._label[:24] + "…"
        p.drawText(QRectF(-70, self._r + 2, 140, 14),
                   Qt.AlignmentFlag.AlignHCenter, lbl)

    def hoverEnterEvent(self, e):
        self._hover = True; self.update()

    def hoverLeaveEvent(self, e):
        self._hover = False; self.update()


class _EdgeItem(QGraphicsItem):
    """A directed, typed edge: line + arrowhead + optional relationship label."""

    def __init__(self, relation: str, color: QColor, pivot: bool):
        super().__init__()
        self._p1 = QPointF()
        self._p2 = QPointF()
        self._rel = relation
        self._color = color
        self._pivot = pivot
        self._show_label = False
        self._dim = False
        self._hot = False
        self.setZValue(1)
        self.setAcceptHoverEvents(True)
        self.setToolTip(relation)

    def set_endpoints(self, p1: QPointF, p2: QPointF) -> None:
        self.prepareGeometryChange()
        self._p1, self._p2 = p1, p2

    def set_show_label(self, on: bool) -> None:
        if on != self._show_label:
            self._show_label = on
            self.update()

    def set_dim(self, on: bool) -> None:
        if on != self._dim:
            self._dim = on
            self.update()

    def set_highlight(self, on: bool) -> None:
        if on != self._hot:
            self._hot = on
            self.update()

    def boundingRect(self) -> QRectF:
        pad = 34
        return (QRectF(self._p1, self._p2).normalized()
                .adjusted(-pad, -pad, pad, pad))

    def paint(self, p: QPainter, *_):
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        col = QColor(self._color)
        col.setAlpha(38 if self._dim else (220 if self._hot else 120))
        pen = QPen(col, 2.2 if self._hot else 1.2)
        if self._pivot:
            pen.setStyle(Qt.PenStyle.DashLine); pen.setDashPattern([4, 4])
        p.setPen(pen)
        p.drawLine(self._p1, self._p2)
        # arrowhead a little short of the destination node
        dx, dy = self._p2.x() - self._p1.x(), self._p2.y() - self._p1.y()
        dist = math.hypot(dx, dy) or 1.0
        ux, uy = dx / dist, dy / dist
        tip = QPointF(self._p2.x() - ux * 16, self._p2.y() - uy * 16)
        ah = 6.0
        left = QPointF(tip.x() - ux * ah + uy * ah, tip.y() - uy * ah - ux * ah)
        right = QPointF(tip.x() - ux * ah - uy * ah, tip.y() - uy * ah + ux * ah)
        p.setBrush(QBrush(col)); p.setPen(Qt.PenStyle.NoPen)
        p.drawPolygon(QPolygonF([tip, left, right]))
        if self._show_label and self._rel:
            mid = QPointF((self._p1.x() + self._p2.x()) / 2,
                          (self._p1.y() + self._p2.y()) / 2)
            p.setFont(QFont("Consolas", 7, QFont.Weight.Bold))
            fm = p.fontMetrics(); w = fm.horizontalAdvance(self._rel) + 8
            box = QRectF(mid.x() - w / 2, mid.y() - 8, w, 14)
            bg = QColor(theme.BG_PANEL); bg.setAlpha(235)
            p.setBrush(bg); p.setPen(QPen(QColor(self._color), 0.8))
            p.drawRoundedRect(box, 3, 3)
            tc = QColor(theme.TEXT_BRIGHT if self._hot else theme.TEXT_MUTED)
            p.setPen(tc)
            p.drawText(box, Qt.AlignmentFlag.AlignCenter, self._rel)


class EntityGraphView(QGraphicsView):
    node_clicked = pyqtSignal(str)   # entity key

    def __init__(self, graph_model, parent=None):
        super().__init__(parent)
        self._model = graph_model
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QColor(theme.BG_DEEP))
        self.setMinimumHeight(320)
        self.setViewportUpdateMode(
            QGraphicsView.ViewportUpdateMode.BoundingRectViewportUpdate)

        self._nodes: dict[str, _NodeItem] = {}
        self._edges: dict[tuple, _EdgeItem] = {}
        self._pos: dict[str, tuple[float, float]] = {}
        self._metrics: dict[str, tuple] = {}   # key -> (risk, degree), change-gated
        self._filter: Optional[EntityType] = None
        self._selected_key: Optional[str] = None
        self._show_all_relations = False
        self._dirty = False

        self._layout_timer = QTimer(self)
        self._layout_timer.setInterval(1400)
        self._layout_timer.timeout.connect(self._maybe_relayout)
        self._layout_timer.start()

    # -- public API used by the main window ---------------------------------
    def mark_dirty(self) -> None:
        self._dirty = True

    def clear_all(self) -> None:
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()
        self._pos.clear()
        self._metrics.clear()
        self._selected_key = None
        self._filter = None
        self._dirty = False
        self.resetTransform()

    def set_show_relations(self, on: bool) -> None:
        """Toggle always-on relationship labels for every edge."""
        self._show_all_relations = on
        self.select_key(self._selected_key)

    def set_filter(self, etype: Optional[EntityType]) -> None:
        self._filter = etype
        for key, item in self._nodes.items():
            ent = self._model.get(key)
            visible = (etype is None or (ent and ent.etype == etype)
                       or key == self._model.seed_key)
            item.setVisible(visible)
        for (s, t), eitem in self._edges.items():
            sv = self._nodes.get(s); tv = self._nodes.get(t)
            eitem.setVisible(bool(sv and tv and sv.isVisible() and tv.isVisible()))

    def select_key(self, key: Optional[str]) -> None:
        """Select a node and highlight its exposure path from the seed."""
        self._selected_key = key
        path = self._model.path_from_seed(key) if key else []
        path_nodes = set(path)
        path_edges = {frozenset((a, b)) for a, b in zip(path, path[1:])}
        active = bool(key) and bool(path_nodes)

        for k, item in self._nodes.items():
            item.set_selected(k == key)
            item.set_dim(active and k not in path_nodes)
        for (s, t), eitem in self._edges.items():
            on_path = frozenset((s, t)) in path_edges
            touches = key in (s, t)
            eitem.set_highlight(on_path)
            eitem.set_dim(active and not on_path)
            eitem.set_show_label(self._show_all_relations or on_path or touches)

        item = self._nodes.get(key) if key else None
        if item is not None:
            self.centerOn(item)

    def clear_selection(self) -> None:
        self.select_key(None)

    def auto_layout(self) -> None:
        self._relayout(force=True)
        self.fit()

    def fit(self) -> None:
        if self._scene.items():
            self.fitInView(self._scene.itemsBoundingRect().adjusted(-60, -60, 60, 60),
                           Qt.AspectRatioMode.KeepAspectRatio)

    # -- sync from the model ------------------------------------------------
    def refresh(self) -> None:
        nodes, edges = self._model.snapshot()
        seed_key = self._model.seed_key
        changed = False
        # Node degrees in one pass over the edge list — avoids a locked
        # model.degree() call per node per frame.
        degree: dict[str, int] = {}
        for s, t, _kind, _label in edges:
            degree[s] = degree.get(s, 0) + 1
            degree[t] = degree.get(t, 0) + 1
        for ent in nodes:
            item = self._nodes.get(ent.key)
            if item is None:
                item = _NodeItem(ent.key, ent.etype, ent.value,
                                 seed=(ent.key == seed_key), risk=ent.risk)
                pos = self._seed_or_near(ent, seed_key)
                item.setPos(*pos)
                self._pos[ent.key] = pos
                self._scene.addItem(item)
                self._nodes[ent.key] = item
                changed = True
            # Only repaint a node when its risk or connectivity actually changed.
            m = (ent.risk, degree.get(ent.key, 0))
            if self._metrics.get(ent.key) != m:
                self._metrics[ent.key] = m
                item.set_metrics(ent.risk, m[1])
        for s, t, kind, label in edges:
            ek = (s, t)
            if ek not in self._edges and s in self._nodes and t in self._nodes:
                dst = self._model.get(t)
                col = QColor(ENTITY_META[dst.etype].color) if dst else QColor(theme.BORDER_HI)
                rel = relationship(dst.etype, kind, label) if dst else label
                edge = _EdgeItem(rel, col, pivot=(kind == EDGE_PIVOT))
                self._scene.addItem(edge)
                self._edges[ek] = edge
                changed = True
        if changed:
            self._dirty = True
        self._update_edges()
        if self._selected_key or self._show_all_relations:
            self.select_key(self._selected_key)
        if self._filter is not None:
            self.set_filter(self._filter)

    def _seed_or_near(self, ent, seed_key):
        if ent.key == seed_key:
            return (0.0, 0.0)
        for other, _direction, _kind in self._model.neighbors(ent.key):
            if other.key in self._pos:
                ox, oy = self._pos[other.key]
                ang = hash(ent.key) % 360 * math.pi / 180
                return (ox + 80 * math.cos(ang), oy + 80 * math.sin(ang))
        n = len(self._nodes) + 1
        ang = n * 2.399963  # golden angle
        rad = 60 + 12 * math.sqrt(n)
        return (rad * math.cos(ang), rad * math.sin(ang))

    def _maybe_relayout(self) -> None:
        if self._dirty:
            self._relayout()
            self._dirty = False

    def _relayout(self, force: bool = False) -> None:
        n = len(self._nodes)
        if n < 2:
            return
        g = nx.Graph()
        g.add_nodes_from(self._nodes)
        g.add_edges_from(self._edges)
        seed = self._model.seed_key
        init = {k: (self._pos.get(k, (0, 0))[0] / 400.0,
                    self._pos.get(k, (0, 0))[1] / 400.0) for k in self._nodes}
        fixed = [seed] if seed in init else None
        if fixed:
            init[seed] = (0.0, 0.0)
        try:
            pos = nx.spring_layout(
                g, pos=init, fixed=fixed, k=1.8 / math.sqrt(max(n, 1)),
                iterations=40 if force else 22, seed=7, scale=1.0)
        except Exception:  # noqa: BLE001 — layout must never crash the UI
            return
        scale = 420 + 26 * math.sqrt(n)
        for key, (x, y) in pos.items():
            item = self._nodes.get(key)
            if item is None:
                continue
            px, py = x * scale, y * scale
            self._pos[key] = (px, py)
            item.setPos(px, py)
        self._update_edges()

    def _update_edges(self) -> None:
        for (s, t), edge in self._edges.items():
            a = self._nodes.get(s); b = self._nodes.get(t)
            if a is not None and b is not None:
                edge.set_endpoints(a.pos(), b.pos())

    # -- interaction --------------------------------------------------------
    def wheelEvent(self, e):
        factor = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
        cur = self.transform().m11()
        if not (0.08 < cur * factor < 6):
            return
        self.scale(factor, factor)

    def mousePressEvent(self, e):
        node = self.itemAt(e.pos())
        while node is not None and not isinstance(node, _NodeItem):
            node = node.parentItem()
        if isinstance(node, _NodeItem):
            self.select_key(node.key)
            self.node_clicked.emit(node.key)
        elif e.button() == Qt.MouseButton.LeftButton:
            self.clear_selection()
        super().mousePressEvent(e)
