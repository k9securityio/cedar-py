import pytest
from cedarpy import is_authorized_partial, is_authorized, Decision
from unit import load_file_as_str


def test_unknown_principal_produces_residuals():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert result.allowed is None
    assert len(result.nontrivial_residual_ids) == 1
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
    }


def test_unknown_resource_produces_residuals():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource == Photo::"photo1");'
    result = is_authorized_partial(
        request={"principal": 'User::"alice"', "action": 'Action::"view"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) == 1
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ true && (true && (((unknown("resource")) == Photo::"photo1") && true)) };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {
                                                "==": {
                                                    "left": {"unknown": [{"Value": "resource"}]},
                                                    "right": {"Value": {"__entity": {"type": "Photo", "id": "photo1"}}},
                                                }
                                            },
                                            "right": {"Value": True},
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }


def test_unknown_context_produces_residuals():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource) when { context.is_admin };'
    result = is_authorized_partial(
        request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"photo1"'},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) == 1
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ true && (true && (true && ((unknown("context")).is_admin))) };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                ".": {
                                                    "left": {"unknown": [{"Value": "context"}]},
                                                    "attr": "is_admin",
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }


def test_all_known_produces_definitive_allow():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
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
    assert result.allowed is True
    assert "policy0" in result.diagnostics.reasons
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_all_known_matches_is_authorized():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
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
    assert result.residuals == {
        "policy0": 'forbid(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "forbid",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_unconditional_permit_with_unknowns():
    result = is_authorized_partial(
        request={},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert result.decision == Decision.Allow
    assert result.allowed is True
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_id_annotations():
    policies = '''
    @id("alice-can-view")
    permit(principal == User::"alice", action == Action::"view", resource);
    '''
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert "policy0" in result.diagnostics.id_annotations_by_reason
    assert result.diagnostics.id_annotations_by_reason["policy0"] == "alice-can-view"
    assert result.residuals == {
        "policy0": (
            '@id("alice-can-view")\n'
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
            "annotations": {"id": "alice-can-view"},
        },
    }


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
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_error_invalid_policies():
    with pytest.raises(ValueError, match="policy parse errors"):
        is_authorized_partial(
            request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"'},
            policies="this is not valid cedar",
            entities="[]",
        )


def test_error_invalid_principal():
    with pytest.raises(ValueError, match="Failed to parse principal"):
        is_authorized_partial(
            request={"principal": "not-a-valid-uid", "action": 'Action::"view"', "resource": 'Photo::"p"'},
            policies="permit(principal, action, resource);",
            entities="[]",
        )


def test_metrics_present():
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert "parse_policies_duration_micros" in result.metrics
    assert "authz_duration_micros" in result.metrics
    assert "build_request_duration_micros" in result.metrics
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_entities_as_list():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
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
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_multiple_policies_categorization():
    policies = '''
    permit(principal == User::"alice", action == Action::"view", resource);
    forbid(principal, action == Action::"delete", resource);
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
    assert "policy0" in result.diagnostics.reasons
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
        "policy1": 'forbid(principal, action, resource) when { false };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
        "policy1": {
            "effect": "forbid",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": False}}],
        },
    }


def test_none_values_treated_as_unknown():
    policies = "permit(principal == User::\"alice\", action, resource);"
    result = is_authorized_partial(
        request={"principal": None, "action": 'Action::"view"', "resource": 'Photo::"p"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert len(result.nontrivial_residual_ids) > 0
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
    }


def test_context_as_dict():
    policies = 'permit(principal, action, resource) when { context.level > 5 };'
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
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


# --- Schema tests ---


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
    assert len(result.diagnostics.errors) == 0
    assert len(result.nontrivial_residual_ids) == 1
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
    }


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
    assert len(result.diagnostics.errors) == 0
    assert "policy0" in result.diagnostics.reasons
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_partial_with_schema_wrong_principal_type():
    schema = load_file_as_str("resources/sandbox_b/schema.json")
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = 'permit(principal, action == Action::"view", resource);'
    with pytest.raises(ValueError, match="Request validation failed"):
        is_authorized_partial(
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


def test_partial_with_schema_unknown_context():
    schema = load_file_as_str("resources/sandbox_b/schema.json")
    entities = load_file_as_str("resources/sandbox_b/entities.json")
    policies = 'permit(principal == User::"alice", action == Action::"view", resource) when { context.authenticated };'
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
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ true && (true && (true && ((unknown("context")).authenticated))) };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                ".": {
                                                    "left": {"unknown": [{"Value": "context"}]},
                                                    "attr": "authenticated",
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }


# --- definitely_errored ---


def test_definitely_errored_type_mismatch():
    policies = '''
    permit(principal, action, resource) when { context.value > "hello" };
    permit(principal, action, resource) when { true };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
            "context": {"value": 5},
        },
        policies=policies,
        entities="[]",
    )
    assert any("policy0" in e for e in result.diagnostics.errors)
    assert "policy1" in result.diagnostics.reasons
    assert result.decision == Decision.Allow
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { false };',
        "policy1": 'permit(principal, action, resource) when { true };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": False}}],
        },
        "policy1": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


# --- Determining sets ---


def test_may_be_determining_specific_ids():
    policies = '''
    permit(principal == User::"alice", action == Action::"view", resource);
    permit(principal == User::"bob", action == Action::"view", resource);
    '''
    result = is_authorized_partial(
        request={
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
            "context": {},
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert "policy0" in result.may_be_determining
    assert "policy1" in result.may_be_determining
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
        "policy1": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"bob") && true };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
        "policy1": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "bob"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
    }


def test_must_be_determining_with_definitive_decision():
    policies = '''
    forbid(principal, action, resource);
    permit(principal, action, resource) when { context.x };
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.Deny
    assert "policy0" in result.must_be_determining
    assert "policy0" in result.may_be_determining
    assert result.residuals == {
        "policy0": 'forbid(principal, action, resource) when { true };',
        "policy1": (
            'permit(principal, action, resource) when '
            '{ true && (true && (true && ((unknown("context")).x))) };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "forbid",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
        "policy1": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                ".": {
                                                    "left": {"unknown": [{"Value": "context"}]},
                                                    "attr": "x",
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }


def test_determining_sets_exclude_irrelevant():
    policies = '''
    permit(principal == User::"alice", action == Action::"view", resource);
    permit(principal == User::"alice", action == Action::"delete", resource);
    '''
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
            "context": {},
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.Allow
    assert "policy0" in result.may_be_determining
    assert "policy0" in result.must_be_determining
    assert "policy1" not in result.may_be_determining
    assert "policy1" not in result.must_be_determining
    assert result.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
        "policy1": 'permit(principal, action, resource) when { false };',
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
        "policy1": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": False}}],
        },
    }


# --- Residual content ---


def test_residual_for_context_condition():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource) when { context.is_admin };'
    result = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"photo1"',
        },
        policies=policies,
        entities="[]",
    )
    assert result.decision is None
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ true && (true && (true && ((unknown("context")).is_admin))) };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                ".": {
                                                    "left": {"unknown": [{"Value": "context"}]},
                                                    "attr": "is_admin",
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }


def test_residuals_json_structure():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
    }
    assert result.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
    }


# --- Progressive evaluation ---


def test_progressive_request_filling():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'

    r1 = is_authorized_partial(request={}, policies=policies, entities="[]")
    assert r1.decision is None
    assert len(r1.nontrivial_residual_ids) == 1
    assert r1.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && '
            '(((unknown("action")) == Action::"view") && true) };'
        ),
    }
    assert r1.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {
                                "&&": {
                                    "left": {
                                        "==": {
                                            "left": {"unknown": [{"Value": "action"}]},
                                            "right": {"Value": {"__entity": {"type": "Action", "id": "view"}}},
                                        }
                                    },
                                    "right": {"Value": True},
                                }
                            },
                        }
                    },
                }
            ],
        },
    }

    r2 = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"p"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert r2.decision is None
    assert r2.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && true };'
        ),
    }
    assert r2.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {"Value": True},
                        }
                    },
                }
            ],
        },
    }

    r3 = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
            "context": {},
        },
        policies=policies,
        entities="[]",
    )
    assert r3.decision == Decision.Allow
    assert r3.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert r3.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }


def test_progressive_entity_addition():
    policies = 'permit(principal, action, resource) when { resource.public == true };'
    request = {
        "principal": 'User::"alice"',
        "action": 'Action::"view"',
        "resource": 'Photo::"p"',
        "context": {},
    }

    r1 = is_authorized_partial(request=request, policies=policies, entities="[]")
    assert r1.decision is None
    assert r1.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ true && (true && (true && (((unknown("Photo::\\"p\\"")).public) == true))) };'
        ),
    }
    assert r1.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                "==": {
                                                    "left": {
                                                        ".": {
                                                            "left": {"unknown": [{"Value": 'Photo::"p"'}]},
                                                            "attr": "public",
                                                        }
                                                    },
                                                    "right": {"Value": True},
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }

    entities_true = [{"uid": {"type": "Photo", "id": "p"}, "attrs": {"public": True}, "parents": []}]
    r2 = is_authorized_partial(request=request, policies=policies, entities=entities_true)
    assert r2.decision == Decision.Allow
    assert r2.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert r2.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }

    entities_false = [{"uid": {"type": "Photo", "id": "p"}, "attrs": {"public": False}, "parents": []}]
    r3 = is_authorized_partial(request=request, policies=policies, entities=entities_false)
    assert r3.decision == Decision.Deny
    assert r3.residuals == {
        "policy0": 'permit(principal, action, resource) when { false };',
    }
    assert r3.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": False}}],
        },
    }


def test_progressive_combined():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource) when { resource.public == true };'

    r1 = is_authorized_partial(
        request={"action": 'Action::"view"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert r1.decision is None
    assert r1.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ ((unknown("principal")) == User::"alice") && '
            '(true && (true && (((unknown("resource")).public) == true))) };'
        ),
    }
    assert r1.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {
                                "==": {
                                    "left": {"unknown": [{"Value": "principal"}]},
                                    "right": {"Value": {"__entity": {"type": "User", "id": "alice"}}},
                                }
                            },
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                "==": {
                                                    "left": {
                                                        ".": {
                                                            "left": {"unknown": [{"Value": "resource"}]},
                                                            "attr": "public",
                                                        }
                                                    },
                                                    "right": {"Value": True},
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }

    r2 = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
            "context": {},
        },
        policies=policies,
        entities="[]",
    )
    assert r2.decision is None
    assert r2.residuals == {
        "policy0": (
            'permit(principal, action, resource) when '
            '{ true && (true && (true && (((unknown("Photo::\\"p\\"")).public) == true))) };'
        ),
    }
    assert r2.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "&&": {
                            "left": {"Value": True},
                            "right": {
                                "&&": {
                                    "left": {"Value": True},
                                    "right": {
                                        "&&": {
                                            "left": {"Value": True},
                                            "right": {
                                                "==": {
                                                    "left": {
                                                        ".": {
                                                            "left": {"unknown": [{"Value": 'Photo::"p"'}]},
                                                            "attr": "public",
                                                        }
                                                    },
                                                    "right": {"Value": True},
                                                }
                                            },
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            ],
        },
    }

    entities = [{"uid": {"type": "Photo", "id": "p"}, "attrs": {"public": True}, "parents": []}]
    r3 = is_authorized_partial(
        request={
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"p"',
            "context": {},
        },
        policies=policies,
        entities=entities,
    )
    assert r3.decision == Decision.Allow
    assert r3.residuals == {
        "policy0": 'permit(principal, action, resource) when { true };',
    }
    assert r3.residuals_json == {
        "policy0": {
            "effect": "permit",
            "principal": {"op": "All"},
            "action": {"op": "All"},
            "resource": {"op": "All"},
            "conditions": [{"kind": "when", "body": {"Value": True}}],
        },
    }
