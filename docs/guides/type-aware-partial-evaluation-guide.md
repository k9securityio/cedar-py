# Type-Aware Partial Evaluation Guide

`tpe_authorize` evaluates an authorization request in which the principal or
the resource is known only by type, not by id. It requires a schema, because
the types are what it reasons from, and it returns *residual policies* as typed
`cedarpy.pst.Template` nodes for the parts it could not decide.

Use `tpe_authorize` when, for example:

- The caller **has not picked a resource** yet, and you want to know whether
  any `Doc` could be viewed before you list them.
- You **know the shape of the request but not the ids**, such as authorizing a
  request template ahead of the concrete call.
- You want to **decide what to load** before loading it: a residual names the
  entities and attributes still needed to finish the evaluation.

## TPE and `is_authorized_partial` are different features

Both leave part of a request unknown, and they are separate entry points.
`tpe_authorize` does not call `is_authorized_partial` and does not change it.

| | `is_authorized_partial` | `tpe_authorize` |
| --- | --- | --- |
| Schema | Optional | Required |
| Unknowns | Any entity, attribute, or context value | Principal or resource identity, entity data, context |
| Residual form | JSON policy fragments | `cedarpy.pst.Template` nodes |
| Cargo feature | `partial-eval` | `tpe` |

Reach for `is_authorized_partial` when you know which entity you mean but have
not loaded it. Reach for `tpe_authorize` when you know the type and not the id.

## Basic usage

```python
from cedarpy import tpe_authorize

schema = """
    entity User;
    entity Doc = { status: String, owner: User };
    action "view" appliesTo { principal: [User], resource: [Doc] };
"""
policies = """
    permit(principal, action == Action::"view", resource)
    when { resource.status == "active" };
"""

result = tpe_authorize('User::"alice"', 'Action::"view"', "Doc", policies, "[]", schema)

# Cedar can't decide yet: the policy depends on resource.status, and the
# resource is only known to be some Doc.
assert result.decision is None
assert result.permits.residual_ids == ("policy0",)
```

## Arguments

`principal` and `resource` each accept two kinds of value:

- A concrete entity, as a surface-syntax string such as `'User::"alice"'`, or a
  `{"type": ..., "id": ...}` dict.
- A type whose id is unknown, as a bare type string such as `"User"`, a
  `pst.EntityType`, or a dict carrying only `type`.

`action` must be concrete, in either of the two concrete forms.

`policies`, `entities`, and `schema` take the same values the rest of the
library accepts, including the pre-parsed `PolicySet`, `Entities`, and `Schema`
handles. `entities` also accepts a `PartialEntities` document, described below.

`context` follows `is_authorized_partial`. Omitting it, or passing `None`,
means the context is unknown, so a policy reading it stays residual. Passing
`{}` means a known-empty context.

## The result

`TpeAuthzResult.decision` is `Decision.Allow` or `Decision.Deny` when the
unknowns cannot change the outcome, and `None` when they can.

`permits` and `forbids` are kept separate, each a `TpeClassification` holding
`residual_ids`, `true_ids`, `false_ids`, and `error_ids`. Keeping the two
effects apart matters because Cedar's forbid policies override permits: a
residual forbid is not the same risk as a residual permit.

## Finding what to load

A residual is a `pst.Template`, so `pst.entity_uids` reports the entities it
still names:

```python
from cedarpy.pst import EntityType, EntityUid, entity_uids

policies = """
    permit(principal, action == Action::"view", resource)
    when { resource.owner == User::"bob" };
"""

result = tpe_authorize('User::"alice"', 'Action::"view"', "Doc", policies, "[]", schema)
assert entity_uids(result.residual_policies) == frozenset({EntityUid(EntityType("User"), "bob")})
```

See the [Policy Syntax Tree Guide](policy-syntax-tree-guide.md) for what else
you can do with the nodes.

## The two views of the residuals

`residual_policies` and `residual_policy_set` are not interchangeable.

`residual_policies` is a mapping of policy id to `pst.Template`, holding only
the policies still undecided, reduced by the evaluator with the concrete parts
of the request already substituted in.

`residual_policy_set` is a `PolicySet` handle holding every residual, including
the ones that came out concretely true, false, or erroring, each keeping its
original scope. It is a handle rather than nodes, so call `to_pst()` on it
before `entity_uids` will walk it.

The two views name different entities. Pick `residual_policies` to inspect what
is undecided, and `residual_policy_set` to evaluate against.

## Binding the unknowns later

Once you know the rest of the request, `reauthorize` decides it by evaluating
the residuals rather than the whole policy set. Cedar checks the concrete
request against the partial one first, so a request that contradicts it raises
rather than returning a decision the partial evaluation never sanctioned.

```python
from cedarpy import Decision

decided = result.reauthorize(
    {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'},
    entities='[{"uid": {"type": "Doc", "id": "d1"}, "attrs": {"owner": {"__entity": {"type": "User", "id": "bob"}}, "status": "active"}, "parents": []}]',
)
assert decided.decision == Decision.Allow
```

`reauthorize` returns an `AuthzResult`, the same type `is_authorized` returns.
`entities` defaults to the entities the `tpe_authorize` call ran against, and
is required when that call ran against a `PartialEntities` document.
`cedarpy.tpe_reauthorize(...)` is the same operation as a free function, taking
the `tpe_authorize` inputs explicitly.

To drive the evaluation yourself, authorize against `residual_policy_set`:

```python
from cedarpy import is_authorized

request = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Doc::"d1"',
    "context": {},
}
entities = '[{"uid": {"type": "Doc", "id": "d1"}, "attrs": {"owner": {"__entity": {"type": "User", "id": "bob"}}, "status": "active"}, "parents": []}]'

assert is_authorized(request, result.residual_policy_set, entities, schema).decision == Decision.Allow
```

This path skips the consistency check `reauthorize` performs, so it is on you
to pass a request the partial evaluation actually covers.

## Entities that are only partly known

A concrete entity set asserts that every entity's attributes, parents, and tags
are known. `PartialEntities.from_json` accepts a document in which an entity
exists but one of those is absent, meaning unknown, so policies reading it stay
residual. That is what lets you decide what to fetch before you fetch it.

```python
from cedarpy import PartialEntities

policies = """
    permit(principal, action == Action::"view", resource)
    when { resource.status == "active" };
"""

result = tpe_authorize(
    'User::"alice"', 'Action::"view"', 'Doc::"d1"', policies,
    PartialEntities.from_json([{"uid": {"type": "Doc", "id": "d1"}, "parents": []}]),
    schema,
)

# The Doc exists, but its attrs are not loaded, so status is unknown.
assert result.decision is None
assert result.permits.residual_ids == ("policy0",)
```

Each of `attrs`, `parents`, and `tags` must be wholly present or wholly absent
per entity, and a parent entity cannot itself have unknown parents. Violating
either raises `ValueError`.

## Caveats

A TPE result is not a final authorization decision. Bind the unknowns and
re-evaluate, with `reauthorize` or `is_authorized`, before acting on it.

A residual can hold `pst.ResidualError`, a node for a subexpression TPE knows
will error if it is evaluated. Cedar has no surface syntax for it, so
`PolicySet.from_pst` raises `TypeError` on a node tree containing one. Residual
nodes are for reading, not for rebuilding a policy set.

TPE residuals convert through the same PST machinery as parsed policies, so the
100-level expression nesting limit applies. See the [Policy Syntax Tree
Guide](policy-syntax-tree-guide.md#compatibility).

## API reference

Functions:

- `tpe_authorize(principal, action, resource, policies, entities, schema, context=None, verbose=False)`
  returns a `TpeAuthzResult`.
- `tpe_reauthorize(request, principal, action, resource, policies, entities, schema, context=None, concrete_entities=None, verbose=False)`
  returns an `AuthzResult`.

Classes:

- `TpeAuthzResult`: `decision`, `reason`, `permits`, `forbids`,
  `residual_policies`, `residual_policy_set`, `metrics`, and the `reauthorize`
  method.
- `TpeClassification`: `residual_ids`, `true_ids`, `false_ids`, `error_ids`.
- `PartialEntities`: `from_json(entities)`.

Further reading:

- [Cedar's type-aware partial evaluation RFC](https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md)
- [Partial Authorization Guide](partial-authorization-guide.md)
- [Policy Syntax Tree Guide](policy-syntax-tree-guide.md)
