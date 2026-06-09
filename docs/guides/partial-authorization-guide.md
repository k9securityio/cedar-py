# Partial Authorization Guide

Cedar's partial evaluation lets you evaluate authorization requests
where some information is not yet available.
Instead of a binary allow/deny,
it returns *residual policies* —
simplified policy fragments that capture only the parts depending on unknowns.

Use `is_authorized_partial` when, for example:

- A **resource entity hasn't been loaded** from the database yet
  (you know which resource, but haven't fetched its attributes).
- The **caller hasn't picked a resource**
  (e.g. listing which resources they *could* access).
- **Context will be filled by a downstream service**
  (one service decides access, another provides runtime context).

## Basic usage

```python
from cedarpy import is_authorized_partial, is_authorized, Decision

policies = 'permit(principal, action, resource) when { resource.public == true };'

# Resource entity hasn't been loaded from the database yet
entities = []

request = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Photo::"photo1"',
    "context": {},
}

result = is_authorized_partial(request, policies, entities)

# Cedar can't decide yet: the policy depends on resource.public,
# but Photo::"photo1" hasn't been loaded.
assert result.decision == Decision.NoDecision

# Which entities Cedar needs you to load before it can decide:
assert result.diagnostics.unknown_entities == ['Photo::"photo1"']

# Which policies are still unresolved:
assert result.diagnostics.nontrivial_residuals == ['policy0']
```

Now load the unknown entities and re-evaluate with `is_authorized`:

```python
entities = [
    {"uid": {"__entity": {"type": "Photo", "id": "photo1"}},
     "attrs": {"public": True}, "parents": []}
]

final_result = is_authorized(request, policies, entities)
assert final_result.decision == Decision.Allow
```

### Function signature

```python
def is_authorized_partial(
    request: dict,
    policies: str,
    entities: str | list[dict],
    schema: str | dict | None = None,
    verbose: bool = False,
) -> PartialAuthzResult: ...
```

### Result object

`PartialAuthzResult` exposes:

| Property | Type | Description |
|----------|------|-------------|
| `decision` | `Decision` | `Allow`, `Deny`, or `NoDecision` |
| `allowed` | `bool` | `True` only for `Decision.Allow` |
| `residuals` | `dict` | Policy ID → residual (Cedar JSON AST) - also contains trivial policies (those that already resolve to `Allow` or `Deny`) |
| `diagnostics` | `PartialDiagnostics` | See below |
| `metrics` | `dict` | Timing info (parse, authz, request build durations) |
| `correlation_id` | `str \| None` | Echoed from request if provided |

`PartialDiagnostics` exposes:

| Property | Type | Description |
|----------|------|-------------|
| `errors` | `list[str]` | Parse/validation errors |
| `reasons` | `list[str]` | Definitely-satisfied policy IDs |
| `may_be_determining` | `list[str]` | IDs of policies that *might* affect the decision |
| `must_be_determining` | `list[str]` | IDs of policies that *definitely* affect the decision |
| `nontrivial_residuals` | `list[str]` | IDs of policies with unresolved conditions |
| `unknown_entities` | `list[str]` | Entity UIDs Cedar needs loaded |
| `id_annotations_by_reason` | `dict` | Policy ID → `@id("...")` annotation value |


## How unknowns work

A request field becomes unknown in two ways:

1. **Omit it** from the request dict entirely.
2. **Set it to `None`** explicitly (e.g. `"principal": None`).

Both produce identical behavior — Cedar treats the field as unresolvable
and residualizes any policy condition that depends on it.

### Context: None vs `{}`

Unlike `is_authorized` (which defaults an absent context to empty),
`is_authorized_partial` treats a missing or `None` context as **unknown**:

```python
# Context unknown → residualizes policies that reference context attributes
result = is_authorized_partial(
    request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"'},
    policies='permit(principal, action, resource) when { context.is_admin };',
    entities=[],
)
assert result.decision == Decision.NoDecision

# Context explicitly empty → no unknown, policy condition fails
result = is_authorized_partial(
    request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"', "context": {}},
    policies='permit(principal, action, resource) when { context.is_admin };',
    entities=[],
)
assert result.decision == Decision.Deny
```

To tell Cedar that the context is known but empty,
pass `context={}` explicitly.


## Understanding residuals

Each entry in `result.residuals` is a Cedar JSON AST dict representing
the simplified policy after partial evaluation.

### Structure

```python
{
    "effect": "permit",              # or "forbid"
    "principal": {"op": "All"},      # scope (always "All" in residuals)
    "action": {"op": "All"},
    "resource": {"op": "All"},
    "conditions": [
        {"kind": "when", "body": ...}  # the residual expression
    ],
}
```

### Why residuals contain `true && ...` chains

Residual condition bodies often look like `true && (true && (expr && true))`
with seemingly redundant `true` leaves.
This reflects Cedar's internal evaluation structure:
a policy has four evaluation positions —
principal scope, action scope, resource scope, and condition body —
joined in a right-associative conjunction:

```
principal_check && (action_check && (resource_check && condition_body))
```

During partial evaluation,
each resolved (known) position is replaced with `true`
and each unresolved position retains its expression.
If there is no explicit `when` condition, the condition body is also `true`.

For example,
`permit(principal == User::"alice", action == Action::"view", resource) when { context.is_admin }`
evaluated with principal, action, and resource known but context unknown produces:

```python
"body": {
    "&&": {
        "left": {"Value": True},                 # principal scope resolved
        "right": {
            "&&": {
                "left": {"Value": True},         # action scope resolved
                "right": {
                    "&&": {
                        "left": {"Value": True}, # resource scope resolved
                        "right": {               # condition body (unresolved)
                            ".": {"left": {"unknown": [{"Value": "context"}]}, "attr": "is_admin"}
                        },
                    }
                },
            }
        },
    }
}
```

Cedar preserves these `true` nodes rather than simplifying them away
to ensure the residual policy performs the same type checks as the original
(i.e., the right-hand side must be a boolean expression).
In practice, consumers should skip `true` leaves when walking the AST
(as the SQL translation pattern in this guide does).

### Unknown markers

Unknowns in the residual expression tree appear as:

```python
# A bare unknown variable (e.g. principal is unknown)
{"unknown": [{"Value": "principal"}]}

# Attribute access on an unknown entity
{".": {"left": {"unknown": [{"Value": 'Photo::"p"'}]}, "attr": "public"}}

# Attribute access on unknown context
{".": {"left": {"unknown": [{"Value": "context"}]}, "attr": "is_admin"}}
```

### Trivial vs nontrivial residuals

When a policy's outcome is fully determined (even with unknowns present),
its residual condition simplifies to a constant:

- **Trivial true:** `{"Value": True}` — the policy is definitely satisfied.
- **Trivial false:** `{"Value": False}` — the policy definitely does not apply.

The `nontrivial_residuals` diagnostic lists policy IDs whose condition body
is *not* a constant — these are the ones that depend on the unknowns.

### unknown_entities

When Cedar encounters an entity reference in the request
(e.g. `resource = 'Photo::"p"'`) but that entity isn't in the `entities` list,
it reports it in `diagnostics.unknown_entities`.
This tells you which entities to load before re-evaluating.


## Edge cases and caveats

### Partial-eval results are not final

> **Always re-run `is_authorized` once unknowns are bound.**

A `Decision.Allow` from `is_authorized_partial` holds only for the specific
set of unknowns provided.
Full schema validation (including per-action context type shapes)
is skipped while fields remain unknown.

### Distinguishing errors from missing information

`Decision.NoDecision` can mean two different things —
check `residuals` and `diagnostics.errors` to tell them apart:

```python
if result.decision == Decision.NoDecision:
    if result.diagnostics.errors:
        # Input problem: invalid policies, malformed entity UID, schema violation, etc.
        # residuals is empty ({})
        print(result.diagnostics.errors)
    else:
        # Unknowns block the decision; residuals tell you what's left to resolve
        print(result.diagnostics.nontrivial_residuals)
        print(result.diagnostics.unknown_entities)
```

### Schema validation with unknown action

Cedar schemas define the expected shape of `context` **for each action**.
When a schema is provided but `action` is unknown,
Cedar cannot look up the action-specific context shape.
In this case, context type-checking is **silently skipped**:

```python
schema = {
    "": {
        "entityTypes": {
            "User": {"memberOfTypes": []},
            "Photo": {"memberOfTypes": []},
        },
        "actions": {
            "view": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Photo"],
                    "context": {
                        "type": "Record",
                        "additionalAttributes": False,
                        "attributes": {
                            "authenticated": {"type": "Boolean", "required": True}
                        },
                    },
                }
            }
        },
    }
}

entities = [
    {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
    {"uid": {"type": "Photo", "id": "p"}, "attrs": {}, "parents": []},
]

# action unknown → context type-check skipped → no error even with wrong type
result = is_authorized_partial(
    request={"principal": 'User::"alice"', "resource": 'Photo::"p"', "context": {"authenticated": "not a boolean"}},
    policies='permit(principal == User::"alice", action, resource);',
    entities=entities,
    schema=schema,
)
assert len(result.diagnostics.errors) == 0  # no type error reported!

# Same request with action known → type-check enforced
result = is_authorized_partial(
    request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"',
             "context": {"authenticated": "not a boolean"}},
    policies='permit(principal == User::"alice", action, resource);',
    entities=entities,
    schema=schema,
)
assert len(result.diagnostics.errors) == 1  # type error caught
```

### Unconditional policies resolve despite unknowns

If a policy's scope and conditions don't depend on the unknowns,
Cedar can still reach a definitive decision:

```python
# Unconditional forbid → Deny even with principal unknown
result = is_authorized_partial(
    request={"action": 'Action::"view"', "resource": 'Photo::"p"'},
    policies="forbid(principal, action, resource);",
    entities=[],
)
assert result.decision == Decision.Deny

# Unconditional permit → Allow even with everything unknown
result = is_authorized_partial(
    request={},
    policies="permit(principal, action, resource);",
    entities=[],
)
assert result.decision == Decision.Allow
```

### Type errors in policy conditions

A type mismatch in one policy produces `definitely_errored` —
reported in `diagnostics.errors` — but does not block other policies:

```python
policies = '''
permit(principal, action, resource) when { context.value > "hello" };
permit(principal, action, resource) when { true };
'''
result = is_authorized_partial(
    request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"', "context": {"value": 5}},
    policies=policies,
    entities=[],
)
# policy0 errored (comparing int > string), but policy1 still allows
assert "type error" in result.diagnostics.errors[0]
assert result.decision == Decision.Allow
```


## Advanced: Translating residuals to SQL WHERE clauses

A powerful pattern for list queries:
evaluate once with the resource unknown,
then translate residual conditions into SQL
so the database only returns rows the caller might be allowed to see.

### Two-phase pipeline

1. **Partial evaluate** with known principal + action, unknown resource.
2. **Filter to nontrivial residuals** — these depend on resource attributes.
3. **Walk the residual AST** and emit SQL predicates
   (mapping `resource.<attr>` to database columns).
4. **Query the database** with the generated WHERE clause.
5. **Verify each row** with `is_authorized` before returning it to the caller.

### Step 1: Partial evaluation

```python
import json
import cedarpy

policies = '''
permit(principal, action, resource) when { resource.public == true };
permit(principal == User::"alice", action, resource) when { resource.owner == principal };
forbid(principal, action, resource) when { resource.archived == true };
'''

result = cedarpy.is_authorized_partial(
    request={
        "principal": 'User::"alice"',
        "action": 'Action::"view"',
        "context": {},
        # resource intentionally omitted → unknown
    },
    policies=policies,
    entities=[],
)

assert result.decision == cedarpy.Decision.NoDecision
# Residuals now contain only conditions that depend on resource attributes
```

### Step 2: Extract nontrivial residuals

```python
nontrivial_ids = set(result.diagnostics.nontrivial_residuals)
nontrivial = {pid: result.residuals[pid] for pid in nontrivial_ids}
```

### Step 3: Walk the AST and emit SQL

The residual conditions use a small set of expression nodes.
A simplified emitter maps them to SQL:

| Cedar residual node | SQL equivalent |
|---------------------|----------------|
| `resource.<attr>` | Column `attr` |
| `== / != / < / > / <= / >=` | Comparison operators |
| `&& / \|\|` | `AND / OR` |
| `!expr` | `NOT` |
| `resource has attr` | `attr IS NOT NULL` |
| `resource.<attr> like "pattern"` | `LIKE` |
| Extension functions (no SQL equivalent) | See below |

### Permissiveness guarantee

When a Cedar expression cannot be translated to SQL:

- For **permit** conditions: fall back to `TRUE` (include the row).
- For **forbid** conditions: fall back to `FALSE` (don't exclude the row).

Both directions widen the candidate set rather than narrow it.
The SQL pre-filter **never falsely denies access** —
correctness is guaranteed by the subsequent `is_authorized` check.
The only cost of an imprecise SQL translation is performance (extra rows fetched then discarded).
Note that this may allow a malicious user
to infer the presence of rows they are not authorized to see based on timing.

### Combining multiple policies

Follow Cedar's standard authorization semantics:

```
(any permit matches) AND (no forbid matches)
```

In SQL terms:

```sql
WHERE (permit_1 OR permit_2 OR ...) AND NOT (forbid_1 AND forbid_2 AND ...)
```

### Step 5: Verify candidates

```python
for row in db_rows:
    entity = row_to_cedar_entity(row)
    final = cedarpy.is_authorized(
        request={**request, "resource": f'{row.type}::"{row.id}"'},
        policies=policies,
        entities=[entity, ...],
    )
    if final.allowed:
        yield row
```

This two-phase approach keeps database queries efficient
while maintaining exact Cedar authorization semantics.


## Advanced: Converting residuals back to Cedar text

Sometimes you want residual policies as Cedar text
rather than JSON AST — for example,
to serialize them for later evaluation,
pass them to `is_authorized` as policies,
or display them to a human.

Note that the Cedar Rust API provides a method
[`reauthorize_with_bindings`](https://docs.rs/cedar-policy/latest/cedar_policy/struct.PartialResponse.html#method.reauthorize_with_bindings)
that may be better suited for re-evaluating residuals with unknowns bound to variables,
but it is not currently exposed in cedarpy.


### Converting residual JSON to Cedar text

Use `policies_from_json_str` to convert the JSON AST back to Cedar's text format:

```python
import json
import cedarpy

result = cedarpy.is_authorized_partial(
    request={"principal": 'User::"alice"', "action": 'Action::"view"', "context": {}},
    policies='permit(principal == User::"alice", action == Action::"view", resource) when { resource.public == true };',
    entities=[],
)

# Convert nontrivial residuals to Cedar text
residuals_json = json.dumps({
    "staticPolicies": {
        k: v
        for k, v in result.residuals.items()
        if k in result.diagnostics.nontrivial_residuals
    },
    "templates": {},
    "templateLinks": [],
})

residuals_text = cedarpy.policies_from_json_str(residuals_json)
```

### Replacing unknown markers with Cedar variables

Cedar's JSON-to-text renderer emits unknowns as synthetic function calls
like `unknown("principal")`.
These are not valid Cedar syntax for regular evaluation.
To produce policies that can be passed back to `is_authorized`,
replace the unknown markers with Cedar variable references:

```python
cedar_text = (
    residuals_text
    .replace('unknown("principal")', 'principal')
    .replace('unknown("action")', 'action')
    .replace('unknown("resource")', 'resource')
    .replace('unknown("context")', 'context')
)
```

The resulting `cedar_text` is valid Cedar policy text
that can be passed to `is_authorized` or `is_authorized_partial`
as the `policies` argument.

### When is text-level replacement safe?

The replacement targets (`unknown("principal")`, etc.) are synthetic forms
that Cedar's JSON-to-text renderer produces exclusively for unknown markers.
They cannot appear in user-authored policy text
(Cedar's parser would reject `unknown(...)` as an invalid built-in function call).
String literals in policies are always quoted and would not match
the unquoted replacement patterns.

### Entity-level unknowns

When an entity is unknown (referenced in the request but not in the entities list),
residuals reference it by its full UID:

```python
# In the JSON AST:
{"unknown": [{"Value": 'Photo::"p"'}]}

# In the rendered text:
# unknown("Photo::\"p\"")
```

To replace entity-level unknowns,
match the specific entity UID pattern.
However, the simpler approach is to load the entity and re-run
`is_authorized_partial` rather than performing text substitution on entity unknowns.


## API reference

### Functions

- **`is_authorized_partial(request, policies, entities, schema=None, verbose=False)`**
  — Partially evaluate a request. Returns `PartialAuthzResult`.
- **`is_authorized(request, policies, entities, schema=None, verbose=False)`**
  — Fully evaluate a request. Use for final decisions after binding unknowns.
- **`policies_from_json_str(json_str)`**
  — Convert Cedar JSON policy AST to human-readable Cedar text.
- **`policies_to_json_str(cedar_text)`**
  — Convert Cedar text to JSON policy AST.

### Classes

- **`PartialAuthzResult`** — Result of partial evaluation
  ([source](../../cedarpy/__init__.py)).
- **`PartialDiagnostics`** — Diagnostics specific to partial evaluation
  ([source](../../cedarpy/__init__.py)).
- **`Decision`** — Enum: `Allow`, `Deny`, `NoDecision`.

### Further reading

- [Tests](../../tests/unit/test_authorize_partial.py) —
  comprehensive examples covering all edge cases described in this guide.
