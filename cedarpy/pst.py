"""Typed PST nodes, mirroring cedar_policy::pst. Built by Rust, not parsed.

Every node is a frozen, hashable dataclass, and every closed set the Rust
enums define stays closed here as a `typing.Literal` or a union of node
types, so a consumer can `match` over one and have a type checker prove the
match is exhaustive.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Literal, Mapping, NoReturn, TypeVar

__all__ = [
    "ActionConstraint", "ActionEq", "ActionIn", "BinaryOp", "BinaryOpName",
    "BoolLit", "Char", "Clause", "EntityLit", "EntityOrSlot", "EntityType",
    "EntityUid", "Effect", "Expr", "FrozenMap", "GetAttr", "HasAttr",
    "IfThenElse", "Is", "Like", "Lit", "LongLit", "PatternElem", "PolicySet",
    "PrincipalOrResourceConstraint", "Record", "ResidualError", "ScopeAny",
    "ScopeEq", "ScopeIn", "ScopeIs", "ScopeIsIn", "Set", "Slot", "SlotName",
    "entity_uids",
    "StringLit", "Template", "TemplateLink", "UnaryOp", "UnaryOpName",
    "Unknown", "Unless", "Var", "VarName", "When", "Wildcard",
]

_K = TypeVar("_K", bound=str)
_V = TypeVar("_V")


class FrozenMap(dict[_K, _V]):
    """An immutable, hashable string-keyed mapping.

    A PST node is a value, so its mappings have to be values too: a plain
    dict would leave `frozen=True` unenforced one field deep, and would make
    any node containing one unhashable. Subclasses `dict` so `asdict`,
    `json.dumps`, and `==` against a plain dict keep working. Nodes declare
    these fields as `Mapping`, which has no mutating methods, so a write is a
    type error as well as a `TypeError`.
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


@dataclass(frozen=True, slots=True)
class Unknown:
    name: str


@dataclass(frozen=True, slots=True)
class ResidualError:
    pass  # TPE residual subexpression known to error if evaluated


Expr = (
    Var | Slot | BoolLit | LongLit | StringLit | EntityLit | UnaryOp | BinaryOp
    | GetAttr | HasAttr | Like | Is | IfThenElse | Set | Record | Unknown
    | ResidualError
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


def entity_uids(node: Any) -> frozenset[EntityUid]:
    """Every entity uid named anywhere under `node`, at any depth.

    Answers "which entities does this policy or residual actually reference",
    which is what a caller needs to decide what to load before evaluating.
    Walks the fields generically, so a node kind added later is covered.
    """
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

    walk(node)
    return frozenset(found)
