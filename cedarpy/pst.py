"""Typed PST nodes, mirroring cedar_policy::pst. Built by Rust, not parsed."""
from dataclasses import dataclass
from typing import Mapping, Union


@dataclass(frozen=True)
class EntityUid:
    type: str
    id: str


@dataclass(frozen=True)
class Slot:
    name: str  # "principal" or "resource"


EntityOrSlot = Union[EntityUid, Slot]


@dataclass(frozen=True)
class Var:
    name: str  # "principal", "action", "resource", or "context"


@dataclass(frozen=True)
class Literal:
    value: Union[bool, int, str, EntityUid]


@dataclass(frozen=True)
class UnaryOp:
    op: str
    arg: "Expr"


@dataclass(frozen=True)
class BinaryOp:
    op: str
    left: "Expr"
    right: "Expr"


@dataclass(frozen=True)
class GetAttr:
    base: "Expr"
    attr: str


@dataclass(frozen=True)
class HasAttr:
    base: "Expr"
    attrs: tuple


@dataclass(frozen=True)
class Char:
    value: str


@dataclass(frozen=True)
class Wildcard:
    pass


PatternElem = Union[Char, Wildcard]


@dataclass(frozen=True)
class Like:
    base: "Expr"
    pattern: tuple  # tuple[PatternElem, ...]


@dataclass(frozen=True)
class Is:
    base: "Expr"
    entity_type: str
    in_expr: "Expr | None"


@dataclass(frozen=True)
class IfThenElse:
    cond: "Expr"
    then_expr: "Expr"
    else_expr: "Expr"


@dataclass(frozen=True)
class Set:
    elements: tuple  # tuple[Expr, ...]


@dataclass(frozen=True)
class Record:
    fields: Mapping[str, "Expr"]


@dataclass(frozen=True)
class Unknown:
    name: str


@dataclass(frozen=True)
class ResidualError:
    pass  # TPE residual subexpression known to error if evaluated


Expr = Union[
    Var, Slot, Literal, UnaryOp, BinaryOp, GetAttr, HasAttr, Like, Is,
    IfThenElse, Set, Record, Unknown, ResidualError,
]


@dataclass(frozen=True)
class When:
    expr: Expr


@dataclass(frozen=True)
class Unless:
    expr: Expr


Clause = Union[When, Unless]


@dataclass(frozen=True)
class ScopeAny:
    pass


@dataclass(frozen=True)
class ScopeEq:
    entity: EntityOrSlot


@dataclass(frozen=True)
class ScopeIn:
    entity: EntityOrSlot


@dataclass(frozen=True)
class ScopeIs:
    entity_type: str


@dataclass(frozen=True)
class ScopeIsIn:
    entity_type: str
    entity: EntityOrSlot


PrincipalOrResourceConstraint = Union[ScopeAny, ScopeEq, ScopeIn, ScopeIs, ScopeIsIn]


@dataclass(frozen=True)
class ActionEq:
    entity: EntityUid


@dataclass(frozen=True)
class ActionIn:
    entities: tuple  # tuple[EntityUid, ...]


ActionConstraint = Union[ScopeAny, ActionEq, ActionIn]


@dataclass(frozen=True)
class Template:
    id: str
    effect: str  # "permit" or "forbid"
    principal: PrincipalOrResourceConstraint
    action: ActionConstraint
    resource: PrincipalOrResourceConstraint
    clauses: tuple  # tuple[Clause, ...]
    annotations: Mapping[str, str]


@dataclass(frozen=True)
class TemplateLink:
    template_id: str
    new_id: str
    values: Mapping[str, EntityUid]


@dataclass(frozen=True)
class PolicySet:
    templates: Mapping[str, Template]
    static_policies: Mapping[str, Template]
    template_links: tuple  # tuple[TemplateLink, ...]
