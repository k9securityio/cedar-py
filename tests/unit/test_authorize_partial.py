from cedarpy import is_authorized_partial, is_authorized, Decision
from unit import load_file_as_str


RESIDUAL_PERMIT_TRUE = {
    "effect": "permit",
    "principal": {"op": "All"},
    "action": {"op": "All"},
    "resource": {"op": "All"},
    "conditions": [{"kind": "when", "body": {"Value": True}}],
}

RESIDUAL_PERMIT_FALSE = {
    "effect": "permit",
    "principal": {"op": "All"},
    "action": {"op": "All"},
    "resource": {"op": "All"},
    "conditions": [{"kind": "when", "body": {"Value": False}}],
}

RESIDUAL_FORBID_TRUE = {
    "effect": "forbid",
    "principal": {"op": "All"},
    "action": {"op": "All"},
    "resource": {"op": "All"},
    "conditions": [{"kind": "when", "body": {"Value": True}}],
}

RESIDUAL_FORBID_FALSE = {
    "effect": "forbid",
    "principal": {"op": "All"},
    "action": {"op": "All"},
    "resource": {"op": "All"},
    "conditions": [{"kind": "when", "body": {"Value": False}}],
}


def test_unknown_principal_produces_residuals():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.NoDecision
    assert result.allowed is False
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.decision == Decision.NoDecision
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.decision == Decision.NoDecision
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_FORBID_TRUE}


def test_unconditional_permit_with_unknowns():
    result = is_authorized_partial(
        request={},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert result.decision == Decision.Allow
    assert result.allowed is True
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


def test_error_invalid_policies():
    result = is_authorized_partial(
        request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p"'},
        policies="this is not valid cedar",
        entities="[]",
    )
    assert result.decision == Decision.NoDecision
    assert result.allowed is False
    assert result.residuals == {}
    assert result.diagnostics.errors == ['policy parse errors:\nunexpected token `is`']
    assert result.diagnostics.may_be_determining == []
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []


def test_error_invalid_principal():
    result = is_authorized_partial(
        request={"principal": "not-a-valid-uid", "action": 'Action::"view"', "resource": 'Photo::"p"'},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert result.decision == Decision.NoDecision
    assert result.allowed is False
    assert result.residuals == {}
    assert result.diagnostics.errors == ['Failed to parse principal as entity Uid: unexpected token `-`']
    assert result.diagnostics.may_be_determining == []
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []


def test_metrics_present():
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies="permit(principal, action, resource);",
        entities="[]",
    )
    assert "parse_policies_duration_micros" in result.metrics
    assert "authz_duration_micros" in result.metrics
    assert "build_request_duration_micros" in result.metrics
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
        "policy0": RESIDUAL_PERMIT_TRUE,
        "policy1": RESIDUAL_FORBID_FALSE,
    }


def test_none_values_treated_as_unknown():
    policies = "permit(principal == User::\"alice\", action, resource);"
    result = is_authorized_partial(
        request={"principal": None, "action": 'Action::"view"', "resource": 'Photo::"p"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.decision == Decision.NoDecision
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


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
    assert result.decision == Decision.NoDecision
    assert len(result.diagnostics.errors) == 0
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == ["policy0"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


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
    assert result.decision == Decision.NoDecision
    assert result.allowed is False
    assert result.residuals == {}
    assert result.diagnostics.errors == ['Request validation failed: principal type `Photo` is not valid for `Action::"view"`']
    assert result.diagnostics.may_be_determining == []
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []


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
    assert result.decision == Decision.NoDecision
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert result.diagnostics.errors == ['error while evaluating policy `policy0`: type error: expected long, got string']
    assert "policy1" in result.diagnostics.reasons
    assert result.decision == Decision.Allow
    assert result.diagnostics.may_be_determining == ["policy1"]
    assert result.diagnostics.must_be_determining == ["policy1"]
    assert result.diagnostics.nontrivial_residuals == []
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
        "policy0": RESIDUAL_PERMIT_FALSE,
        "policy1": RESIDUAL_PERMIT_TRUE,
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
    assert result.decision == Decision.NoDecision
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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


def test_residuals_structure():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
    result = is_authorized_partial(
        request={"action": 'Action::"view"', "resource": 'Photo::"photo1"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert result.diagnostics.may_be_determining == ["policy0"]
    assert result.diagnostics.must_be_determining == []
    assert result.diagnostics.nontrivial_residuals == ["policy0"]
    assert result.diagnostics.unknown_entities == []
    assert result.residuals == {
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
    assert r1.decision == Decision.NoDecision
    assert r1.diagnostics.may_be_determining == ["policy0"]
    assert r1.diagnostics.must_be_determining == []
    assert r1.diagnostics.nontrivial_residuals == ["policy0"]
    assert r1.diagnostics.unknown_entities == []
    assert r1.residuals == {
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
    assert r2.decision == Decision.NoDecision
    assert r2.diagnostics.may_be_determining == ["policy0"]
    assert r2.diagnostics.must_be_determining == []
    assert r2.diagnostics.nontrivial_residuals == ["policy0"]
    assert r2.diagnostics.unknown_entities == []
    assert r2.residuals == {
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
    assert r3.diagnostics.may_be_determining == ["policy0"]
    assert r3.diagnostics.must_be_determining == ["policy0"]
    assert r3.diagnostics.nontrivial_residuals == []
    assert r3.diagnostics.unknown_entities == []
    assert r3.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}


def test_progressive_entity_addition():
    policies = 'permit(principal, action, resource) when { resource.public == true };'
    request = {
        "principal": 'User::"alice"',
        "action": 'Action::"view"',
        "resource": 'Photo::"p"',
        "context": {},
    }

    r1 = is_authorized_partial(request=request, policies=policies, entities="[]")
    assert r1.decision == Decision.NoDecision
    assert r1.diagnostics.may_be_determining == ["policy0"]
    assert r1.diagnostics.must_be_determining == []
    assert r1.diagnostics.nontrivial_residuals == ["policy0"]
    assert r1.diagnostics.unknown_entities == ['Photo::"p"']
    assert r1.residuals == {
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
    assert r2.diagnostics.may_be_determining == ["policy0"]
    assert r2.diagnostics.must_be_determining == ["policy0"]
    assert r2.diagnostics.nontrivial_residuals == []
    assert r2.diagnostics.unknown_entities == []
    assert r2.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}

    entities_false = [{"uid": {"type": "Photo", "id": "p"}, "attrs": {"public": False}, "parents": []}]
    r3 = is_authorized_partial(request=request, policies=policies, entities=entities_false)
    assert r3.decision == Decision.Deny
    assert r3.diagnostics.may_be_determining == []
    assert r3.diagnostics.must_be_determining == []
    assert r3.diagnostics.nontrivial_residuals == []
    assert r3.diagnostics.unknown_entities == []
    assert r3.residuals == {"policy0": RESIDUAL_PERMIT_FALSE}


def test_progressive_combined():
    policies = 'permit(principal == User::"alice", action == Action::"view", resource) when { resource.public == true };'

    r1 = is_authorized_partial(
        request={"action": 'Action::"view"', "context": {}},
        policies=policies,
        entities="[]",
    )
    assert r1.decision == Decision.NoDecision
    assert r1.diagnostics.may_be_determining == ["policy0"]
    assert r1.diagnostics.must_be_determining == []
    assert r1.diagnostics.nontrivial_residuals == ["policy0"]
    assert r1.diagnostics.unknown_entities == []
    assert r1.residuals == {
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
    assert r2.decision == Decision.NoDecision
    assert r2.diagnostics.may_be_determining == ["policy0"]
    assert r2.diagnostics.must_be_determining == []
    assert r2.diagnostics.nontrivial_residuals == ["policy0"]
    assert r2.diagnostics.unknown_entities == ['Photo::"p"']
    assert r2.residuals == {
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
    assert r3.diagnostics.may_be_determining == ["policy0"]
    assert r3.diagnostics.must_be_determining == ["policy0"]
    assert r3.diagnostics.nontrivial_residuals == []
    assert r3.diagnostics.unknown_entities == []
    assert r3.residuals == {"policy0": RESIDUAL_PERMIT_TRUE}
