# Policy Syntax Tree Guide

`policies_to_pst` parses Cedar policy text into typed nodes from `cedarpy.pst`,
which mirrors `cedar_policy::pst`. Each node is a frozen dataclass, so you can
use structural pattern matching instead of walking a tree keyed by string
operators. `PolicySet.from_pst` turns nodes back into a policy set the engine
authorizes against, so policies can be read as data, rewritten, and re-used.

Use the PST when, for example:

- You **read policy structure to drive behavior**, such as deciding which
  principal attributes or entities to load before evaluating.
- You **build or rewrite policies programmatically** and want the type checker,
  not string manipulation, to keep them well-formed.
- You **analyze a policy set** — which actions it names, which entity types it
  touches, which conditions gate an action.

## Compatibility

`cedarpy.pst` tracks the engine: new engine variants mean new node types or
`Literal` members in cedarpy minor releases, and unmodelled syntax raises
`ValueError` until then. See the `cedarpy.pst` module docstring for the full
contract.

Static policies and unlinked templates only. A residual from
`is_authorized_partial` cannot be represented this way, because PST rejects any
clause holding an unresolved `unknown(...)` node and every non-trivial residual
has one.

## Inspecting policies

```python
from cedarpy import policies_to_pst
from cedarpy.pst import BinaryOp, GetAttr, Var

policies = """
    permit(principal, action == Action::"view", resource)
    when { resource.owner == principal };
"""

result = policies_to_pst(policies)
clause = result.static_policies["policy0"].clauses[0]

match clause.expr:
    case BinaryOp(op="eq", left=GetAttr(attr="owner"), right=Var(name="principal")):
        print("matched")
```

## Closed sets stay closed

Each closed set Cedar defines is closed in the Python type, so a type checker
can prove a `match` over one is exhaustive:

* `UnaryOp.op` and `BinaryOp.op` are `Literal` aliases of the operator names
  (`UnaryOpName`, `BinaryOpName`).
* `Template.effect` is `Literal["permit", "forbid"]`, and `Var.name` and
  `Slot.name` are constrained the same way.
* Cedar's `Bool` and `Long` literals are separate `BoolLit` and `LongLit`
  nodes. `bool` is a subclass of `int` in Python, so one node holding either
  could not tell them apart.
* An entity type keeps its namespace as structure.
  `EntityType(basename='User', namespace=('MyApp',))` rather than the string
  `'MyApp::User'`, and `str()` gives the Cedar form.

```python
from typing import assert_never  # typing_extensions on Python < 3.11

from cedarpy.pst import BoolLit, EntityLit, Expr, LongLit, StringLit

def render_literal(expr: Expr) -> str:
    match expr:
        case BoolLit(value=v):
            return "true" if v else "false"
        case LongLit(value=v) | StringLit(value=v):
            return repr(v)
        case EntityLit(value=uid):
            return str(uid)
        case _:
            return "<non-literal>"
```

## Nodes are values

Every node is frozen, slotted, and hashable, so nodes work as dict keys and
set members. Mapping-valued fields such as `Record.fields` and
`Template.annotations` are declared `Mapping`, so writing to one is a type
error. At runtime they hold a `FrozenMap`, a `dict` subclass that raises on
mutation; `dataclasses.asdict`, `json.dumps`, and comparison against a plain
dict all still work.

## Finding the entities a policy names

`pst.entity_uids(node)` collects every entity uid named anywhere under a node,
at any depth. Use it to find out what a policy references before you load
anything. It takes a node, or a mapping or tuple of nodes such as a
`PolicySet`'s `templates`.

```python
from cedarpy.pst import EntityType, EntityUid, entity_uids

assert entity_uids(result.static_policies["policy0"]) == frozenset({
    EntityUid(EntityType("Action"), "view")
})
```

Anything it cannot walk raises `TypeError` rather than returning an empty set,
so passing the `cedarpy.PolicySet` handle by mistake cannot look like "this
policy names no entities".

## Rebuilding a policy set from nodes

`PolicySet.from_pst` is the inverse of `PolicySet.to_pst`, so you can read a
policy set as nodes, change it, and hand it back to the engine.
`policies_to_pst(text)` is `PolicySet.from_str(text).to_pst()`.

```python
import dataclasses

from cedarpy import Decision, PolicySet, is_authorized, policies_to_pst
from cedarpy.pst import EntityType, EntityUid, ScopeEq

nodes = policies_to_pst('permit(principal == User::"alice", action, resource);')

# Point the same policy at a different principal
policy = nodes.static_policies["policy0"]
retargeted = dataclasses.replace(policy, principal=ScopeEq(EntityUid(EntityType("User"), "bob")))
edited = dataclasses.replace(nodes, static_policies={"policy0": retargeted})

policy_set = PolicySet.from_pst(edited)

request = {"principal": 'User::"bob"', "action": 'Action::"view"', "resource": 'Doc::"d1"', "context": {}}
assert is_authorized(request, policy_set, "[]").decision == Decision.Allow
```

`from_pst` raises `TypeError` if given something that is not a `cedarpy.pst`
node, and `ValueError` if the nodes do not form a valid policy set, such as a
template link naming a template that is not present.
