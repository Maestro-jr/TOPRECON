"""
Engine → Qt bridge.

The engine speaks plain :class:`core.events.Event`; the GUI speaks Qt signals.
This QObject is the single adapter: the engine's ``emit`` callback is
``EngineBridge.dispatch`` and each Event kind fans out to a typed signal the
panels connect to. Signals are auto-queued if the engine ever runs off-thread.
"""

from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal

from core.events import Event, EventType


class EngineBridge(QObject):
    entity_added   = pyqtSignal(object)   # Entity
    entity_updated = pyqtSignal(object)   # Entity
    edge_added     = pyqtSignal(str, str, str)   # src_key, dst_key, kind
    pivot_queued   = pyqtSignal(object, str)     # Entity, transform
    module_status  = pyqtSignal(str, dict)       # transform name, payload
    stats          = pyqtSignal(dict)
    log            = pyqtSignal(dict)             # {ts,text,level}
    state          = pyqtSignal(str, dict)        # state, stats

    def dispatch(self, ev: Event) -> None:
        k = ev.kind
        if k == EventType.ENTITY_ADDED:
            self.entity_added.emit(ev.entity)
        elif k == EventType.ENTITY_UPDATED:
            self.entity_updated.emit(ev.entity)
        elif k == EventType.EDGE_ADDED:
            self.edge_added.emit(ev.src_key, ev.dst_key, ev.edge_kind)
        elif k == EventType.PIVOT_QUEUED:
            self.pivot_queued.emit(ev.entity, ev.transform)
        elif k == EventType.MODULE_STATUS:
            self.module_status.emit(ev.transform, ev.payload)
        elif k == EventType.STATS:
            self.stats.emit(ev.payload)
        elif k == EventType.LOG:
            self.log.emit({"ts": ev.ts, "text": ev.text, "level": ev.level})
        elif k == EventType.STATE:
            self.state.emit(ev.text, ev.payload)
