"""Typed PST nodes, mirroring cedar_policy::pst. Built by Rust, not parsed.

Every node is a frozen, hashable dataclass. Each closed set of the Rust enums
is a `typing.Literal` or a union of node types here, so a `match` over one can
be checked for exhaustiveness.

Compatibility contract: this module tracks the Cedar engine, not cedarpy's
usual pure-additive API stability. The Rust enums it mirrors are
``#[non_exhaustive]`` and grow as the Cedar language does, so a cedarpy
release that bumps the engine may add node types, fields, or `Literal`
members here, and a ``match`` that was exhaustive may need new arms. Until a
new engine construct is modelled, ``to_pst`` / ``policies_to_pst`` raise
``ValueError`` naming the unmodelled variant rather than building an
incomplete tree. ``tests/unit/test_pst_variant_coverage.py`` audits this
mirror against the engine's own source on every engine bump.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Literal, NoReturn, TypeVar

__all__ = [
    "ActionConstraint", "ActionEq", "ActionIn", "BinaryOp", "BinaryOpName",
    "BoolLit", "Char", "Clause", "Effect", "entity_uids", "EntityLit",
    "EntityOrSlot", "EntityType", "EntityUid", "Expr", "FrozenMap", "GetAttr",
    "HasAttr", "IfThenElse", "Is", "Like", "Lit", "LongLit", "PatternElem",
    "PolicySet", "PrincipalOrResourceConstraint", "PstNode", "Record",
    "ScopeAny", "ScopeEq", "ScopeIn", "ScopeIs", "ScopeIsIn", "Set", "Slot",
    "SlotName", "StringLit", "Template", "TemplateLink", "UnaryOp",
    "UnaryOpName", "Unless", "Var", "VarName", "When", "Wildcard",
]

_K = TypeVar("_K", bound=str)
_V = TypeVar("_V")


class FrozenMap(dict[_K, _V]):
    """An immutable, hashable string-keyed mapping.

    A plain dict would leave `frozen=True` unenforced one field deep and make
    any node holding one unhashable. This subclasses `dict` so `asdict`,
    `json.dumps`, and `==` against a plain dict keep working.

    Defined here because Python has no frozen mapping to reach for: the
    stdlib offers only `types.MappingProxyType` (an unhashable view that
    breaks `asdict`), PEP 603's `frozenmap` never landed, and cedarpy has no
    runtime Python dependencies, which taking `immutables` or `frozendict`
    for one class would end.
    """

    __slots__ = ()

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(frozenset(self.items()))

    def _immutable(self, *_args: object, **_kwargs: object) -> NoReturn:
        raise TypeError(f"{type(self).__name__} is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    __ior__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable


@dataclass(frozen=True, slots=True)
class EntityType:
    """An entity type name: `User`, or `MyApp::Photo` with a namespace."""
    basename: str
    namespace: tuple[str, ...] = ()

    def __str__(self) -> str:
        return "::".join((*self.namespace, self.basename))


@dataclass(frozen=True, slots=True)
class EntityUid:
    type: EntityType
    id: str

    def __str__(self) -> str:
        return f'{self.type}::"{self.id}"'


SlotName = Literal["principal", "resource"]
VarName = Literal["principal", "action", "resource", "context"]
Effect = Literal["permit", "forbid"]


@dataclass(frozen=True, slots=True)
class Slot:
    name: SlotName


EntityOrSlot = EntityUid | Slot


@dataclass(frozen=True, slots=True)
class Var:
    name: VarName


@dataclass(frozen=True, slots=True)
class BoolLit:
    value: bool


@dataclass(frozen=True, slots=True)
class LongLit:
    value: int


@dataclass(frozen=True, slots=True)
class StringLit:
    value: str


@dataclass(frozen=True, slots=True)
class EntityLit:
    value: EntityUid


Lit = BoolLit | LongLit | StringLit | EntityLit

UnaryOpName = Literal[
    "not", "neg", "is_empty", "datetime", "decimal", "duration", "ip",
    "is_ipv4", "is_ipv6", "is_loopback", "is_multicast", "to_date", "to_time",
    "to_milliseconds", "to_seconds", "to_minutes", "to_hours", "to_days",
]

BinaryOpName = Literal[
    "eq", "not_eq", "less", "less_eq", "greater", "greater_eq", "and", "or",
    "add", "sub", "mul", "in", "contains", "contains_all", "contains_any",
    "get_tag", "has_tag", "is_in_range", "offset", "duration_since",
    "decimal_less_than", "decimal_less_eq", "decimal_greater",
    "decimal_greater_eq",
]


@dataclass(frozen=True, slots=True)
class UnaryOp:
    op: UnaryOpName
    arg: Expr


@dataclass(frozen=True, slots=True)
class BinaryOp:
    op: BinaryOpName
    left: Expr
    right: Expr


@dataclass(frozen=True, slots=True)
class GetAttr:
    base: Expr
    attr: str


@dataclass(frozen=True, slots=True)
class HasAttr:
    base: Expr
    attrs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.attrs:
            raise ValueError("HasAttr.attrs must name at least one attribute")


@dataclass(frozen=True, slots=True)
class Char:
    value: str


@dataclass(frozen=True, slots=True)
class Wildcard:
    pass


PatternElem = Char | Wildcard


@dataclass(frozen=True, slots=True)
class Like:
    base: Expr
    pattern: tuple[PatternElem, ...]


@dataclass(frozen=True, slots=True)
class Is:
    base: Expr
    entity_type: EntityType
    in_expr: Expr | None


@dataclass(frozen=True, slots=True)
class IfThenElse:
    cond: Expr
    then_expr: Expr
    else_expr: Expr


@dataclass(frozen=True, slots=True)
class Set:
    elements: tuple[Expr, ...]


@dataclass(frozen=True, slots=True)
class Record:
    fields: Mapping[str, Expr]


Expr = (
    Var | Slot | BoolLit | LongLit | StringLit | EntityLit | UnaryOp | BinaryOp
    | GetAttr | HasAttr | Like | Is | IfThenElse | Set | Record
)


@dataclass(frozen=True, slots=True)
class When:
    expr: Expr


@dataclass(frozen=True, slots=True)
class Unless:
    expr: Expr


Clause = When | Unless


@dataclass(frozen=True, slots=True)
class ScopeAny:
    pass


@dataclass(frozen=True, slots=True)
class ScopeEq:
    entity: EntityOrSlot


@dataclass(frozen=True, slots=True)
class ScopeIn:
    entity: EntityOrSlot


@dataclass(frozen=True, slots=True)
class ScopeIs:
    entity_type: EntityType


@dataclass(frozen=True, slots=True)
class ScopeIsIn:
    entity_type: EntityType
    entity: EntityOrSlot


PrincipalOrResourceConstraint = ScopeAny | ScopeEq | ScopeIn | ScopeIs | ScopeIsIn


@dataclass(frozen=True, slots=True)
class ActionEq:
    entity: EntityUid


@dataclass(frozen=True, slots=True)
class ActionIn:
    entities: tuple[EntityUid, ...]


ActionConstraint = ScopeAny | ActionEq | ActionIn


@dataclass(frozen=True, slots=True)
class Template:
    id: str
    effect: Effect
    principal: PrincipalOrResourceConstraint
    action: ActionConstraint
    resource: PrincipalOrResourceConstraint
    clauses: tuple[Clause, ...]
    annotations: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class TemplateLink:
    template_id: str
    new_id: str
    values: Mapping[SlotName, EntityUid]


@dataclass(frozen=True, slots=True)
class PolicySet:
    templates: Mapping[str, Template]
    static_policies: Mapping[str, Template]
    template_links: tuple[TemplateLink, ...]


PstNode = (
    PolicySet | Template | TemplateLink | Clause | Expr | EntityUid | EntityType
    | PrincipalOrResourceConstraint | ActionConstraint | PatternElem
)


def _is_node(value: object) -> bool:
    """True for an instance of a node type defined in this module."""
    cls = type(value)
    return is_dataclass(cls) and cls.__module__ == __name__


def entity_uids(
    node: PstNode | Mapping[str, PstNode] | tuple[PstNode, ...],
) -> frozenset[EntityUid]:
    """Every entity uid named anywhere under `node`, at any depth.

    Use it to decide which entities to load before evaluating. Takes a node, or
    a mapping or tuple of nodes such as a `PolicySet`'s `templates`. Anything
    else raises `TypeError`, so passing a `cedarpy.PolicySet` handle by mistake
    cannot look like "names no entities".
    """
    if _is_node(node):
        roots: tuple[object, ...] = (node,)
    elif isinstance(node, Mapping):
        roots = tuple(node.values())
    elif isinstance(node, tuple):
        roots = node
    else:
        raise TypeError(
            f"entity_uids expects a cedarpy.pst node, or a mapping or tuple of "
            f"them, not {type(node).__name__}"
        )

    unwalkable = [r for r in roots if not _is_node(r)]
    if unwalkable:
        raise TypeError(
            f"entity_uids expects cedarpy.pst nodes, got "
            f"{type(unwalkable[0]).__name__}"
        )

    found: set[EntityUid] = set()

    def walk(value: Any) -> None:
        if isinstance(value, EntityUid):
            found.add(value)
            return
        if isinstance(value, Mapping):
            for item in value.values():
                walk(item)
            return
        if isinstance(value, tuple):
            for item in value:
                walk(item)
            return
        if is_dataclass(value) and not isinstance(value, type):
            for f in fields(value):
                walk(getattr(value, f.name))

    for root in roots:
        walk(root)
    return frozenset(found)
