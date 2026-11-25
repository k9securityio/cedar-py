# Type-Aware Partial Evaluation Guide

`tpe_authorize` evaluates policies against a schema when the principal or resource id, the context, or some entity data is unknown. Unlike `is_authorized_partial`, it requires a concrete action and returns undecided policies as typed `cedarpy.pst.Template` nodes rather than JSON. Cedar's `tpe` feature is [experimental](https://github.com/cedar-policy/rfcs/blob/main/README.md#experimental-features) and may change in any release.

## Authorize a document once its id is known

```python
from cedarpy import Decision, tpe_authorize

schema = """
    entity User;
    entity Doc = { status: String };
    action "view" appliesTo { principal: [User], resource: [Doc] };
"""
policies = """
    permit(principal, action == Action::"view", resource)
    when { resource.status == "active" };
"""

result = tpe_authorize('User::"alice"', 'Action::"view"', "Doc", policies, "[]", schema)
assert result.decision is None
assert result.permits.residual_ids == ("policy0",)

request = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'}
docs = [{"uid": {"type": "Doc", "id": "d1"}, "attrs": {"status": "active"}, "parents": []}]
assert result.reauthorize(request, entities=docs).decision == Decision.Allow
```

## Known and unknown inputs

- Pass a concrete uid as a Cedar string or a dict such as `{"type": "Doc", "id": "d1"}`. For a principal or resource with an unknown id, pass `"Doc"`, `pst.EntityType("Doc")`, or `{"type": "Doc"}`.
- Omitting `context` or passing `None` leaves the context unknown. `{}` means a known empty context and must satisfy the action's schema.
- `policies`, `entities`, and `schema` accept the usual text or pre-parsed handles. To supply partial entity data, pass a `PartialEntities.from_json(...)` document instead of a concrete entity set. Within an entity, omitting `attrs`, `parents`, or `tags` leaves that whole field unknown. A listed parent cannot itself have unknown parents.

## Read the result

`decision` is `Decision.Allow` or `Decision.Deny` if Cedar can decide for all consistent completions of the request and entities. `None` means Cedar could not decide. `permits` and `forbids` each group policy ids into `true_ids`, `false_ids`, `error_ids`, and `residual_ids`. An undecided forbid can still override a satisfied permit.

`residual_policies` maps only undecided policy ids to `pst.Template` nodes. `pst.entity_uids(result.residual_policies)` finds literal entity references in those nodes, not every entity you may need to load. A `pst.ResidualError` represents a subexpression that will error if evaluated. `PolicySet.from_pst` raises `TypeError` for a tree containing this node.

`residual_policy_set` is a `PolicySet` handle for **all reduced policies**, including true, false, and error results. Their scopes are unconstrained; any remaining checks are in the conditions.

## Reauthorize with concrete data

`result.reauthorize(request, entities=...)` returns an `AuthzResult`. It uses a snapshot of the original partial inputs. If the original entities were concrete, they are the default; if you supplied `PartialEntities`, you must pass concrete entities. The free function `tpe_reauthorize` takes the partial inputs explicitly.

Both forms re-run TPE on the original policies on every call. Cedar then checks the concrete request and entities against the schema and the partial inputs before evaluating the reduced policies. A contradiction, such as changing the known principal from Alice to Bob, raises `ValueError`.

Calling `is_authorized` directly with `result.residual_policy_set` avoids the TPE re-run but skips the consistency checks against the partial inputs. Use that path only if you enforce those constraints yourself.
