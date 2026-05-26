from cedarpy import is_authorized_partial, is_authorized, Decision
from unit import load_file_as_str


def test_unknown_principal_produces_residuals():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    );
    '''
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert not result.determined
    assert result.allowed is None
    assert len(result.nontrivial_residual_ids) == 1
    assert "policy0" in result.residuals
    assert "alice" in result.residuals["policy0"]


def test_unknown_resource_produces_residuals():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource == Photo::"photo1"
    );
    '''
    result = is_authorized_partial(
        request={"principal": 'User::"alice"', "action": 'Action::"view"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) == 1
    assert "photo1" in result.residuals["policy0"]


def test_unknown_context_produces_residuals():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    ) when { context.is_admin };
    '''
    result = is_authorized_partial(
        request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"photo1"'},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) == 1
    assert "context" in result.residuals["policy0"] or "is_admin" in result.residuals["policy0"]


def test_all_known_produces_definitive_allow():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    );
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
            "context": {},
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.Allow
    assert result.determined
    assert result.allowed is True
    assert "policy0" in result.satisfied


def test_all_known_matches_is_authorized():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    );
    '''
    request = {
        "principal": 'User::"alice"',
        "action": 'Action::"view"',
        "resource": 'Photo::"photo1"',
        "context": {},
    }
    partial_result = is_authorized_partial(
        request=request, policies=policies, entities="[]"
    )
    full_result = is_authorized(request=request, policies=policies, entities="[]")
    assert partial_result.decision == full_result.decision


def test_unconditional_forbid_with_unknowns():
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"'},
        policies="forbid(principal, action, resource);",
        entities="[]",
    )
    assert result.decision == Decision.Deny
    assert result.allowed is False


def test_unconditional_permit_with_unknowns():
    result = is_authorized_partial(
        request={},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert result.decision == Decision.Allow
    assert result.allowed is True


def test_id_annotations():
    policies = '''
    @id("alice-can-view")
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    );
    '''
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert "policy0" in result.id_annotations
    assert result.id_annotations["policy0"] == "alice-can-view"


def test_correlation_id_passthrough():
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
            "context": {},
            "correlation_id": "req-123",
        },
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert result.correlation_id == "req-123"


def test_error_invalid_policies():
    result = is_authorized_partial(
        request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"'},
        policies="this is not valid cedar",
        entities="[]",
    )
    assert len(result.diagnostics_errors) > 0


def test_error_invalid_principal():
    result = is_authorized_partial(
        request={"principal": "not-a-valid-uid", "action": 'Action::"view"', "resource": 'Photo::"p"'},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert len(result.diagnostics_errors) > 0


def test_metrics_present():
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert "parse_policies_duration_micros" in result.metrics
    assert "authz_duration_micros" in result.metrics
    assert "build_request_duration_micros" in result.metrics


def test_entities_as_list():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    );
    '''
    entities = [
        {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []}
    ]
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
            "context": {},
        },
        policies=policies,
        entities=entities,
    )
    assert result.decision == Decision.Allow


def test_multiple_policies_categorization():
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    );
    forbid(
        principal,
        action == Action::"delete",
        resource
    );
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
            "context": {},
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.Allow
    assert "policy0" in result.satisfied


def test_none_values_treated_as_unknown():
    policies = "permit(principal == User::\"alice\", action, resource);"
    result = is_authorized_partial(
        request={"principal": None, "action": 'Action::"view"', "resource": 'Photo::"p"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) > 0


def test_context_as_dict():
    policies = '''
    permit(principal, action, resource) when { context.level > 5 };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
            "context": {"level": 10},
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.Allow


def test_partial_with_schema_unknown_principal():
    schema = load_file_as_str("resources/sandbox_b/schema.json")
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {"authenticated": True},
        },
        policies=policies,
        entities=entities,
        schema=schema,
    )
    assert result.decision is None
    assert result.diagnostics_errors == []
    assert len(result.nontrivial_residual_ids) == 1
    assert "alice" in result.residuals["policy0"]


def test_partial_with_schema_all_known():
    schema = load_file_as_str("resources/sandbox_b/schema.json")
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {"authenticated": True},
        },
        policies=policies,
        entities=entities,
        schema=schema,
    )
    assert result.decision == Decision.Allow
    assert result.diagnostics_errors == []
    assert "policy0" in result.satisfied


def test_partial_with_schema_wrong_principal_type():
    schema = load_file_as_str("resources/sandbox_b/schema.json")
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = 'permit(principal, action == Action::"view", resource);'
    result = is_authorized_partial(
        request={
            "principal": 'Photo::"vacation.jpg"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {"authenticated": True},
        },
        policies=policies,
        entities=entities,
        schema=schema,
    )
    assert len(result.diagnostics_errors) > 0
    assert result.decision is None


def test_partial_with_schema_unknown_context():
    schema = load_file_as_str("resources/sandbox_b/schema.json")
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    ) when { context.authenticated };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
        },
        policies=policies,
        entities=entities,
        schema=schema,
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) >= 1
    assert "authenticated" in result.residuals["policy0"]


def test_definitely_errored_type_mismatch():
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = '''
    permit(principal, action, resource) when { resource.missing_attr };
    permit(principal, action, resource) when { true };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
        },
        policies=policies,
        entities=entities,
    )
    assert "policy0" in result.errored
    assert "policy1" in result.satisfied
    assert result.decision == Decision.Allow


def test_may_be_determining_specific_ids():
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = '''
    permit(principal == User::"alice", action == Action::"view", resource);
    permit(principal == User::"bob", action == Action::"view", resource);
    '''
    result = is_authorized_partial(
        request={
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {},
        },
        policies=policies,
        entities=entities,
    )
    assert result.decision is None
    assert "policy0" in result.may_be_determining
    assert "policy1" in result.may_be_determining


def test_must_be_determining_with_definitive_decision():
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = '''
    forbid(principal, action, resource);
    permit(principal, action, resource) when { context.x };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
        },
        policies=policies,
        entities=entities,
    )
    assert result.decision == Decision.Deny
    assert "policy0" in result.must_be_determining
    assert "policy0" in result.may_be_determining


def test_determining_sets_exclude_irrelevant():
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = '''
    permit(principal == User::"alice", action == Action::"view", resource);
    permit(principal == User::"alice", action == Action::"delete", resource);
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {},
        },
        policies=policies,
        entities=entities,
    )
    assert result.decision == Decision.Allow
    assert "policy0" in result.may_be_determining
    assert "policy0" in result.must_be_determining
    assert "policy1" not in result.may_be_determining
    assert "policy1" not in result.must_be_determining


def test_residual_for_principal_check():
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
            "context": {},
        },
        policies=policies,
        entities=entities,
    )
    residual = result.residuals["policy0"]
    assert residual == 'permit(principal, action, resource) when { ((unknown("principal")) == User::"alice") && true };'


def test_residual_for_context_condition():
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = '''
    permit(
        principal == User::"alice",
        action == Action::"view",
        resource
    ) when { context.is_admin };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
        },
        policies=policies,
        entities=entities,
    )
    assert result.decision is None
    residual = result.residuals["policy0"]
    assert residual == 'permit(principal, action, resource) when { true && (true && (true && ((unknown("context")).is_admin))) };'
