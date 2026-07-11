"""
TOP RECON — Transform base + registry.

A TRANSFORM is a tool wrapper: it declares the entity types it consumes
(``input_types``) and the types it can emit (``output_types``), plus whether it
is passive or active (touches the target directly) and whether it needs an API
key. The engine uses the registry to auto-pivot: a new entity is queued into
every transform whose ``input_types`` include the entity's type.

Each concrete transform implements ``async run(entity, ctx) -> list[Emit]``.
Emits are (entity, edge_kind) pairs the engine folds into the graph.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .entities import Entity, EntityType
from .graph import EDGE_DISCOVERED, EDGE_PIVOT


# Module categories (used to group the ACTIVE MODULES panel).
class Category:
    DNS          = "Domain & DNS"
    SUBDOMAIN    = "Subdomain Enum"
    CERT         = "Certificate Intel"
    HOST         = "Host / Service"
    WEBTECH      = "Web Technology"
    EMAIL        = "Email / Footprint"
    BREACH       = "Breach Exposure"
    CLOUD        = "Cloud & Secrets"
    BRAND        = "Brand / Impersonation"
    THREATINTEL  = "Threat Intel"
    ANALYSIS     = "Analysis"


class ModuleStatus:
    IDLE      = "Idle"
    QUEUED    = "Queued"
    RUNNING   = "Running"
    NEEDS_KEY = "Needs Key"
    MISSING   = "Not Installed"
    DISABLED  = "Disabled"
    ERROR     = "Error"


@dataclass
class Emit:
    """One produced entity + the edge kind linking it to the source entity."""
    entity: Entity
    edge_kind: str = EDGE_DISCOVERED
    edge_label: str = ""

    @staticmethod
    def discovered(entity: Entity, label: str = "") -> "Emit":
        return Emit(entity, EDGE_DISCOVERED, label)

    @staticmethod
    def pivot(entity: Entity, label: str = "") -> "Emit":
        return Emit(entity, EDGE_PIVOT, label)


@dataclass
class TransformContext:
    """Runtime context handed to a transform's ``run``.

    Gives a transform read access to config/keys and the emit-child helper so it
    can attach depth + provenance without knowing engine internals.
    """
    settings: Any
    seed_target: str
    log: Callable[[str], None]

    def child(self, etype: EntityType, value: str, *, source: str,
              depth: int, **data: Any) -> Entity:
        return Entity(etype=etype, value=value, depth=depth,
                      sources={source}, data=dict(data))


class Transform(abc.ABC):
    """Base class for every tool wrapper.

    Subclasses set the class attributes and implement :meth:`run`. They must not
    raise for expected conditions (missing key/tool) — return ``[]`` and set an
    appropriate availability via :meth:`availability`.
    """

    name: str = "transform"
    display: str = "Transform"
    category: str = Category.DNS
    input_types: tuple[EntityType, ...] = ()
    output_types: tuple[EntityType, ...] = ()
    active: bool = False          # True = directly touches the target
    needs_key: str = ""           # settings key that must be present, "" if none
    requires_bin: str = ""        # external binary that must be on PATH, "" if none
    timeout: float = 30.0
    # Approximate per-run request weight, for the requests/min accounting.
    request_weight: int = 1

    def availability(self, settings: Any) -> str:
        """Return a ModuleStatus reflecting whether this transform can run."""
        import shutil
        if self.needs_key and not settings.get_key(self.needs_key):
            return ModuleStatus.NEEDS_KEY
        if self.requires_bin and not shutil.which(self.requires_bin):
            return ModuleStatus.MISSING
        return ModuleStatus.IDLE

    def accepts(self, etype: EntityType) -> bool:
        return etype in self.input_types

    @abc.abstractmethod
    async def run(self, entity: Entity, ctx: TransformContext) -> list[Emit]:
        """Consume *entity*, return emitted child entities."""
        raise NotImplementedError


class TransformRegistry:
    """Holds transform instances and answers "who consumes this entity type?"."""

    def __init__(self) -> None:
        self._by_name: dict[str, Transform] = {}
        self._by_input: dict[EntityType, list[Transform]] = {}

    def register(self, transform: Transform) -> None:
        if transform.name in self._by_name:
            return
        self._by_name[transform.name] = transform
        for t in transform.input_types:
            self._by_input.setdefault(t, []).append(transform)

    def all(self) -> list[Transform]:
        return list(self._by_name.values())

    def get(self, name: str) -> Optional[Transform]:
        return self._by_name.get(name)

    def consumers(self, etype: EntityType) -> list[Transform]:
        return list(self._by_input.get(etype, []))

    def __len__(self) -> int:
        return len(self._by_name)
