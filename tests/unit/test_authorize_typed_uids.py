from copy import deepcopy

import pytest

from cedarpy import Decision, is_authorized, is_authorized_batch, is_authorized_partial, pst


@pytest.fixture
def request_with_uids():
    # Deliberately not a normalized Cedar string literal.
    raw_id = '"雪"\\\n\x00::'
    fields = {"principal": "User", "action": "Action", "resource": "Photo"}
    return {
        **{key: pst.EntityUid(pst.EntityType(name, ("App", "Media")), raw_id) for key, name in fields.items()},
        "context": {key: {"__entity": {"type": f"App::Media::{name}", "id": raw_id}} for key, name in fields.items()},
        "correlation_id": "typed-1",
    }


MATCH_CONTEXT = """permit(principal, action, resource) when {
    principal == context.principal && action == context.action && resource == context.resource
};"""


@pytest.mark.parametrize("authorize", [is_authorized, is_authorized_partial])
def test_typed_request_preserves_all_uid_components(authorize, request_with_uids):
    before = deepcopy(request_with_uids)
    result = authorize(request_with_uids, MATCH_CONTEXT, [])
    assert result.decision == Decision.Allow
    assert result.correlation_id == "typed-1"
    assert request_with_uids == before


def test_batch_accepts_mixed_forms_in_order(request_with_uids):
    second = {**request_with_uids, "principal": 'User::"someone else"',
              "action": request_with_uids["context"]["action"]["__entity"], "correlation_id": "mixed-2"}
    batch = [request_with_uids, second]
    before = deepcopy(batch)
    results = is_authorized_batch(batch, MATCH_CONTEXT, [])
    assert [(r.decision, r.correlation_id) for r in results] == [(Decision.Allow, "typed-1"), (Decision.Deny, "mixed-2")]
    assert batch == before


def test_partial_unknown_uid_and_unknown_vs_empty_context():
    uid = pst.EntityUid(pst.EntityType("User"), "alice")
    policy = 'permit(principal == User::"alice", action, resource) when { context has ok };'
    for request in ({"principal": uid}, {"principal": uid, "context": None},
                    {"principal": None, "context": {"ok": True}}, {"context": {"ok": True}}):
        result = is_authorized_partial(request, policy, [])
        assert result.decision == Decision.NoDecision
        assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert is_authorized_partial({"principal": uid, "context": {}}, policy, []).decision == Decision.Deny


def test_typed_partial_action_validates_context_against_schema():
    schema = 'entity User; action view appliesTo { principal: User, resource: User, context: { ok: Bool } };'
    request = {"action": pst.EntityUid(pst.EntityType("Action"), "view"), "context": {"ok": "yes"}}
    result = is_authorized_partial(request, "permit(principal, action, resource);", [], schema)
    assert result.decision == Decision.NoDecision
    assert result.diagnostics.errors
    assert not result.residuals


@pytest.mark.parametrize("authorize", [is_authorized, is_authorized_partial])
def test_malformed_uids_are_not_coerced(authorize, request_with_uids):
    class EntityUid:  # Same name and fields, but not a cedarpy.pst.EntityUid.
        type = pst.EntityType("User")
        id = "alice"

    for value in (EntityUid(), pst.EntityUid("User", "alice"), pst.EntityUid(pst.EntityType("User"), 42)):
        with pytest.raises(TypeError):
            authorize({**request_with_uids, "principal": value}, MATCH_CONTEXT, [])
    malformed = authorize({**request_with_uids, "principal": "invalid"}, MATCH_CONTEXT, [])
    assert malformed.decision == Decision.NoDecision
    assert any("Failed to parse principal" in e for e in malformed.diagnostics.errors)


def test_legacy_dict_error_behavior(request_with_uids):
    request = {**request_with_uids, "principal": {"type": "User"}}
    with pytest.raises(KeyError):
        is_authorized(request, MATCH_CONTEXT, [])
    with pytest.raises(TypeError):
        is_authorized_partial(request, MATCH_CONTEXT, [])
