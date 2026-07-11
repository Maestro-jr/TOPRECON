"""
TOP RECON — Entity graph.

A thin, dedup-aware wrapper over ``networkx.DiGraph``. Nodes are :class:`Entity`
objects keyed by their dedup key; edges are typed ``discovered`` (directly
observed) or ``pivot`` (inferred) relationships.

Pure model — no Qt. The GUI reads snapshots from here; the engine mutates it.
"""

from __future__ import annotations

import threading
from collections import Counter
from typing import Iterator, Optional

import networkx as nx

from .entities import Entity, EntityType


EDGE_DISCOVERED = "discovered"
EDGE_PIVOT = "pivot"


class EntityGraph:
    """Dedup-aware store of entities and their relationships.

    Thread-safe for the coarse operations the engine needs (a single lock; the
    graph is small relative to network latency, so contention is a non-issue).
    """

    def __init__(self) -> None:
        self._g = nx.DiGraph()
        self._lock = threading.RLock()
        self._seed_key: Optional[str] = None
        self._version = 0   # bumped on every mutation; lets the UI skip idle work

    @property
    def version(self) -> int:
        return self._version

    # -- mutation ------------------------------------------------------------

    def set_seed(self, entity: Entity) -> Entity:
        e = self.add_entity(entity)
        self._seed_key = e.key
        return e

    def clear(self) -> None:
        """Empty the graph in place (keeps object identity for live GUI refs)."""
        with self._lock:
            self._g.clear()
            self._seed_key = None
            self._version += 1

    def add_entity(self, entity: Entity) -> Entity:
        """Insert or merge *entity*; returns the canonical stored node.

        Returns the existing node (after merge) if the key was already present,
        else the freshly stored node. Callers can compare ``is`` / identity is
        not guaranteed, so use the returned object.
        """
        with self._lock:
            key = entity.key
            self._version += 1
            if self._g.has_node(key):
                existing: Entity = self._g.nodes[key]["entity"]
                existing.merge(entity)
                return existing
            self._g.add_node(key, entity=entity)
            return entity

    def add_edge(self, src_key: str, dst_key: str, kind: str = EDGE_DISCOVERED,
                 label: str = "") -> None:
        with self._lock:
            if not (self._g.has_node(src_key) and self._g.has_node(dst_key)):
                return
            # A discovered edge is "stronger" than a pivot edge — never downgrade.
            if self._g.has_edge(src_key, dst_key):
                if self._g.edges[src_key, dst_key].get("kind") == EDGE_DISCOVERED:
                    return
            self._g.add_edge(src_key, dst_key, kind=kind, label=label)
            self._version += 1

    # -- queries -------------------------------------------------------------

    @property
    def seed_key(self) -> Optional[str]:
        return self._seed_key

    def has(self, key: str) -> bool:
        with self._lock:
            return self._g.has_node(key)

    def get(self, key: str) -> Optional[Entity]:
        with self._lock:
            if self._g.has_node(key):
                return self._g.nodes[key]["entity"]
            return None

    def entities(self, etype: Optional[EntityType] = None) -> list[Entity]:
        with self._lock:
            out = [d["entity"] for _, d in self._g.nodes(data=True)]
        if etype is not None:
            out = [e for e in out if e.etype == etype]
        return out

    def __iter__(self) -> Iterator[Entity]:
        return iter(self.entities())

    def __len__(self) -> int:
        with self._lock:
            return self._g.number_of_nodes()

    def edge_count(self) -> int:
        with self._lock:
            return self._g.number_of_edges()

    def counts_by_type(self) -> dict[EntityType, int]:
        c: Counter = Counter(e.etype for e in self.entities())
        return {t: c.get(t, 0) for t in EntityType}

    def counts_by_depth(self) -> dict[int, int]:
        c: Counter = Counter(e.depth for e in self.entities())
        return dict(c)

    def path_from_seed(self, key: str) -> list[str]:
        """Keys along the shortest relationship path seed → *key*.

        Traced on the undirected view so a chain like domain → subdomain → IP →
        port reads regardless of individual edge direction. Empty if unreachable.
        """
        with self._lock:
            if not self._seed_key or not self._g.has_node(key):
                return []
            if key == self._seed_key:
                return [key]
            ug = self._g.to_undirected(as_view=True)
            try:
                return nx.shortest_path(ug, self._seed_key, key)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return []

    def degree(self, key: str) -> int:
        with self._lock:
            return self._g.degree(key) if self._g.has_node(key) else 0

    def neighbors(self, key: str) -> list[tuple[Entity, str, str]]:
        """Return (neighbor_entity, direction, edge_kind) for a node.

        direction is "out" (this → neighbor) or "in" (neighbor → this).
        """
        out: list[tuple[Entity, str, str]] = []
        with self._lock:
            if not self._g.has_node(key):
                return out
            for _, dst, d in self._g.out_edges(key, data=True):
                out.append((self._g.nodes[dst]["entity"], "out", d.get("kind", "")))
            for src, _, d in self._g.in_edges(key, data=True):
                out.append((self._g.nodes[src]["entity"], "in", d.get("kind", "")))
        return out

    def snapshot(self) -> tuple[list[Entity], list[tuple[str, str, str, str]]]:
        """A consistent (nodes, edges) copy for the GUI to render.

        edges are ``(src_key, dst_key, kind, label)`` tuples, where ``label`` is
        the relationship the producing transform recorded (e.g. record type).
        """
        with self._lock:
            nodes = [d["entity"] for _, d in self._g.nodes(data=True)]
            edges = [(s, t, d.get("kind", EDGE_DISCOVERED), d.get("label", ""))
                     for s, t, d in self._g.edges(data=True)]
        return nodes, edges

    def to_dict(self) -> dict:
        nodes, edges = self.snapshot()
        return {
            "seed": self._seed_key,
            "nodes": [e.to_dict() for e in nodes],
            "edges": [{"src": s, "dst": t, "kind": k, "label": lbl}
                      for s, t, k, lbl in edges],
        }
