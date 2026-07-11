"""
TOP RECON — the pivot engine ("hive mind").

Drives the whole recon loop:

  seed entity → every transform that accepts its type is queued → each run emits
  child entities → children are deduped into the graph → each *new* child is
  itself queued into its consuming transforms … until the depth cap is hit or
  the queue drains.

Design goals:
  * GUI-agnostic — communicates only through an ``emit(Event)`` callback, so it
    is fully unit-testable without Qt.
  * Non-blocking — an async worker pool with global + per-source rate limiting.
  * Transparent metrics — entities, requests, success rate, depth reached,
    per-module hit counts and a live pivot queue.
  * Safe by default — ACTIVE transforms (that touch the target) never run unless
    the operator explicitly enabled active scanning.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .entities import Depth, Entity, EntityType
from .events import Event, EventType
from .graph import EntityGraph
from .ratelimit import RateLimiter
from .transforms import (ModuleStatus, Transform, TransformContext,
                         TransformRegistry)


class EngineState:
    IDLE    = "IDLE"
    RUNNING = "RUNNING"
    PAUSED  = "PAUSED"
    DONE    = "DONE"


@dataclass
class ModuleRuntime:
    """Live status + hit count for one transform, feeds the ACTIVE MODULES panel."""
    name: str
    display: str
    category: str
    active: bool
    status: str
    hits: int = 0            # entities this module has produced
    runs: int = 0
    errors: int = 0
    last_run: float = 0.0


@dataclass
class _PendingKey:
    entity_key: str
    entity_value: str
    from_type: str
    tool: str
    tool_display: str
    status: str = "Queued"


class PivotEngine:
    """Async, rate-limited, auto-pivoting recon orchestrator."""

    def __init__(self, registry: TransformRegistry, settings: Any,
                 emit: Callable[[Event], None]) -> None:
        self.registry = registry
        self.settings = settings
        self._emit = emit
        self.graph = EntityGraph()

        self.state = EngineState.IDLE
        self.max_depth = int(getattr(settings, "max_depth", Depth.DEEP))
        self.workers = int(getattr(settings, "workers", 24))
        self.active_enabled = False
        self.seed_target = ""

        self.rate = RateLimiter(int(getattr(settings, "rate_per_min", 1250)))
        self.modules: dict[str, ModuleRuntime] = {}
        self._pending: "OrderedDict[str, _PendingKey]" = OrderedDict()

        self._queue: Optional[asyncio.Queue] = None
        self._tasks: list[asyncio.Task] = []
        self._stats_task: Optional[asyncio.Task] = None
        self._pause_ev: Optional[asyncio.Event] = None
        self._stop = False
        self._inflight = 0
        self._started_at = 0.0

        # metrics
        self.runs_total = 0
        self.runs_ok = 0
        self.runs_failed = 0

        self._init_modules()

    # ------------------------------------------------------------------ setup
    def _init_modules(self) -> None:
        for t in self.registry.all():
            self.modules[t.name] = ModuleRuntime(
                name=t.name, display=t.display, category=t.category,
                active=t.active, status=t.availability(self.settings))

    def refresh_module_availability(self) -> None:
        """Re-evaluate each idle module's availability (e.g. after new API keys
        are saved) so newly-keyed sources flip from "Needs Key" to "Idle" live."""
        for name, mod in self.modules.items():
            if mod.status in (ModuleStatus.RUNNING, ModuleStatus.QUEUED):
                continue
            t = self.registry.get(name)
            if t is not None:
                mod.status = t.availability(self.settings)
                self._emit_module(mod)

    def module_list(self) -> list[ModuleRuntime]:
        # Running first, then queued, then by descending hit count.
        order = {ModuleStatus.RUNNING: 0, ModuleStatus.QUEUED: 1}
        return sorted(self.modules.values(),
                      key=lambda m: (order.get(m.status, 2), -m.hits, m.display))

    def pending_list(self) -> list[_PendingKey]:
        return list(self._pending.values())

    # ------------------------------------------------------------- public API
    async def run(self, seed_value: str, seed_type: EntityType,
                  *, active_enabled: bool = False,
                  max_depth: Optional[int] = None) -> None:
        """Run a full scan to completion (or until :meth:`stop`)."""
        self.active_enabled = active_enabled
        self.seed_target = seed_value
        if max_depth is not None:
            self.max_depth = int(max_depth)
        self._stop = False
        self._queue = asyncio.Queue()
        self._pause_ev = asyncio.Event()
        self._pause_ev.set()
        self._started_at = time.monotonic()
        self.state = EngineState.RUNNING
        self._log(f"Engine start — target scope: {seed_value}", level="info")
        self._set_state()

        seed = Entity(etype=seed_type, value=seed_value, depth=Depth.SEED,
                      sources={"seed"})
        seed = self.graph.set_seed(seed)
        self._emit(Event(EventType.ENTITY_ADDED, entity=seed))
        self._log(f"Seed established: {seed.value} ({seed_type})",
                  level="discovery")
        self._enqueue_pivots(seed)

        self._stats_task = asyncio.create_task(self._stats_loop())
        self._tasks = [asyncio.create_task(self._worker(i))
                       for i in range(self.workers)]
        # Wait for the queue to drain (all discovered work processed).
        await self._queue.join()
        await self._shutdown()

    def stop(self) -> None:
        self._stop = True
        if self._pause_ev:
            self._pause_ev.set()

    def reset(self) -> None:
        """Wipe all scan state so a NEW target can be run on the same engine.

        Keeps the ``graph`` object's identity so the GUI's live references (the
        graph view, summary, risk, detail panels) stay valid across a re-scan.
        """
        self._stop = True
        for t in list(self._tasks):
            t.cancel()
        if self._stats_task:
            self._stats_task.cancel()
        self._tasks = []
        self._stats_task = None
        self._queue = None
        self.graph.clear()
        self._pending.clear()
        self.rate = RateLimiter(int(getattr(self.settings, "rate_per_min", 1250)))
        self.runs_total = self.runs_ok = self.runs_failed = 0
        self._inflight = 0
        self._started_at = 0.0
        self.state = EngineState.IDLE
        for name, mod in self.modules.items():
            t = self.registry.get(name)
            if t is not None:
                mod.status = t.availability(self.settings)
            mod.hits = mod.runs = mod.errors = 0
            mod.last_run = 0.0
        self._stop = False

    def pause(self) -> None:
        if self.state == EngineState.RUNNING and self._pause_ev:
            self._pause_ev.clear()
            self.state = EngineState.PAUSED
            self._set_state()

    def resume(self) -> None:
        if self.state == EngineState.PAUSED and self._pause_ev:
            self._pause_ev.set()
            self.state = EngineState.RUNNING
            self._set_state()

    # ------------------------------------------------------------- internals
    def _enqueue_pivots(self, entity: Entity) -> None:
        """Queue *entity* into every transform that accepts its type."""
        if entity.depth >= self.max_depth:
            return  # children would exceed the depth cap
        for t in self.registry.consumers(entity.etype):
            mod = self.modules.get(t.name)
            if mod is None:
                continue
            # Skip unavailable modules (needs key / missing binary / disabled).
            if mod.status in (ModuleStatus.NEEDS_KEY, ModuleStatus.MISSING,
                              ModuleStatus.DISABLED):
                continue
            if t.active and not self.active_enabled:
                continue  # active module, active scanning not confirmed
            pk = f"{entity.key}|{t.name}"
            if pk in self._pending:
                continue
            self._pending[pk] = _PendingKey(
                entity_key=entity.key, entity_value=entity.value,
                from_type=entity.etype.value, tool=t.name, tool_display=t.display)
            if mod.status == ModuleStatus.IDLE:
                mod.status = ModuleStatus.QUEUED
                self._emit_module(mod)
            self._emit(Event(EventType.PIVOT_QUEUED, entity=entity,
                             transform=t.name))
            self._queue.put_nowait((entity, t, pk))

    async def _worker(self, wid: int) -> None:
        assert self._queue is not None
        while True:
            try:
                entity, transform, pk = await self._queue.get()
            except asyncio.CancelledError:
                return
            try:
                if self._stop:
                    continue
                if self._pause_ev:
                    await self._pause_ev.wait()
                await self._process(entity, transform, pk)
            except Exception as exc:  # a transform must never kill a worker
                self._log(f"{transform.display} error: {exc}", level="error")
            finally:
                self._queue.task_done()

    async def _process(self, entity: Entity, transform: Transform, pk: str) -> None:
        mod = self.modules[transform.name]
        self._inflight += 1
        mod.status = ModuleStatus.RUNNING
        mod.last_run = time.time()
        if pk in self._pending:
            self._pending[pk].status = "Running"
        self._emit_module(mod)
        self._emit(Event(EventType.PIVOT_STARTED, entity=entity,
                         transform=transform.name))
        self._log(f"Pivot: {entity.etype.value.title()} → {transform.display} "
                  f"({entity.value})", level="pivot")

        emitted: list = []
        ok = True
        try:
            await self.rate.acquire(transform.name, transform.request_weight)
            ctx = TransformContext(settings=self.settings,
                                   seed_target=self.seed_target, log=self._log)
            coro = transform.run(entity, ctx)
            emitted = await asyncio.wait_for(coro, timeout=transform.timeout)
            emitted = emitted or []
        except asyncio.TimeoutError:
            ok = False
            self._log(f"{transform.display} timed out on {entity.value}",
                      level="warn")
        except Exception as exc:
            ok = False
            mod.errors += 1
            self._log(f"{transform.display} failed: {exc}", level="error")
        finally:
            self._inflight -= 1
            self.runs_total += 1
            mod.runs += 1

        if ok:
            self.runs_ok += 1
        else:
            self.runs_failed += 1

        # Fold emitted entities into the graph + auto-pivot the new ones.
        for em in emitted:
            child = em.entity
            child.depth = min(entity.depth + 1, self.max_depth + 1)
            existing = self.graph.has(child.key)
            stored = self.graph.add_entity(child)
            self.graph.add_edge(entity.key, stored.key, em.edge_kind,
                                em.edge_label)
            mod.hits += 1
            self._emit(Event(EventType.EDGE_ADDED, src_key=entity.key,
                             dst_key=stored.key, edge_kind=em.edge_kind))
            if not existing:
                self._emit(Event(EventType.ENTITY_ADDED, entity=stored,
                                 transform=transform.name))
                self._log(
                    f"{stored.etype.value.title()} discovered: {stored.value}",
                    level="discovery")
                self._enqueue_pivots(stored)
            else:
                self._emit(Event(EventType.ENTITY_UPDATED, entity=stored,
                                 transform=transform.name))

        # Retire this pending entry; recompute module status.
        self._pending.pop(pk, None)
        mod.status = (ModuleStatus.RUNNING if self._module_has_pending(mod.name)
                      else (ModuleStatus.IDLE if mod.runs else
                            transform.availability(self.settings)))
        if self._module_queued_only(mod.name):
            mod.status = ModuleStatus.QUEUED
        self._emit_module(mod)
        self._emit(Event(EventType.PIVOT_FINISHED, entity=entity,
                         transform=transform.name,
                         payload={"emitted": len(emitted), "ok": ok}))

    def _module_has_pending(self, name: str) -> bool:
        return any(p.tool == name and p.status == "Running"
                   for p in self._pending.values())

    def _module_queued_only(self, name: str) -> bool:
        return any(p.tool == name for p in self._pending.values())

    async def _stats_loop(self) -> None:
        try:
            while not self._stop:
                self._emit_stats()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            return

    async def _shutdown(self) -> None:
        self.state = EngineState.DONE
        for t in self._tasks:
            t.cancel()
        if self._stats_task:
            self._stats_task.cancel()
        self._emit_stats()
        self._set_state()
        self._log(
            f"Scan complete — {len(self.graph)} entities, "
            f"{self.runs_total} transform runs.", level="info")

    # ---------------------------------------------------------------- emitters
    def stats(self) -> dict[str, Any]:
        elapsed = (time.monotonic() - self._started_at) if self._started_at else 0
        success = (self.runs_ok / self.runs_total * 100.0) if self.runs_total else 100.0
        depth_reached = max((e.depth for e in self.graph), default=0)
        return {
            "state": self.state,
            "entities": len(self.graph),
            "edges": self.graph.edge_count(),
            "requests": self.rate.total_requests,
            "success_rate": success,
            "elapsed": elapsed,
            "throughput": self.rate.current_rate(),
            "depth_reached": min(depth_reached, self.max_depth),
            "max_depth": self.max_depth,
            "workers": self.workers,
            "inflight": self._inflight,
            "pending": len(self._pending),
            "rate_per_min": self.rate.global_per_min,
            "runs_total": self.runs_total,
        }

    def _emit_stats(self) -> None:
        self._emit(Event(EventType.STATS, payload=self.stats()))

    def _emit_module(self, mod: ModuleRuntime) -> None:
        self._emit(Event(EventType.MODULE_STATUS, transform=mod.name,
                         payload={"status": mod.status, "hits": mod.hits,
                                  "runs": mod.runs}))

    def _set_state(self) -> None:
        self._emit(Event(EventType.STATE, text=self.state,
                         payload=self.stats()))

    def _log(self, text: str, level: str = "info") -> None:
        self._emit(Event(EventType.LOG, text=text, level=level))
