"""
TOP RECON — engine event objects.

The engine is GUI-agnostic: it calls a single ``emit(event)`` callback. The GUI
adapter (a QObject) turns these into Qt signals. Keeping events as plain
dataclasses means the engine is unit-testable with no Qt at all.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .entities import Entity


class EventType:
    ENTITY_ADDED     = "entity_added"      # a new (deduped) entity landed
    ENTITY_UPDATED   = "entity_updated"    # existing entity re-sourced/enriched
    EDGE_ADDED       = "edge_added"
    PIVOT_QUEUED     = "pivot_queued"      # (entity, transform) enqueued
    PIVOT_STARTED    = "pivot_started"
    PIVOT_FINISHED   = "pivot_finished"
    MODULE_STATUS    = "module_status"     # a transform changed status/hit-count
    STATS            = "stats"             # periodic engine metrics
    LOG              = "log"               # live-feed line
    STATE            = "state"             # engine RUNNING/IDLE/DONE/PAUSED


@dataclass
class Event:
    kind: str
    ts: float = field(default_factory=time.time)
    entity: Optional[Entity] = None
    transform: str = ""
    src_key: str = ""
    dst_key: str = ""
    edge_kind: str = ""
    text: str = ""
    level: str = "info"           # info|discovery|pivot|warn|error
    payload: dict[str, Any] = field(default_factory=dict)
