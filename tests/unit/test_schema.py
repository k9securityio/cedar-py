"""Unit tests for the reusable Schema handle.

A Schema handle lets callers parse a schema once and reuse the parsed object
across authorization, validation, and entity-construction calls, avoiding the
per-call re-parse. These tests assert that the handle path is a
behavior-preserving, opt-in alternative to passing a schema as a string or dict.
"""
import json
import unittest

from cedarpy import (
    Schema,
    Entities,
    Decision,
    is_authorized,
    is_authorized_batch,
    is_authorized_partial,
    validate_policies,
)


SCHEMA_CEDAR = """
    entity User;
    entity Photo = { "owner": User };
    action view appliesTo { principal: User, resource: Photo };
    action edit appliesTo { principal: User, resource: Photo };
"""

SCHEMA_JSON = json.dumps({
    "": {
        "entityTypes": {
            "User": {"shape": {"type": "Record", "attributes": {}}},
            "Photo": {
                "shape": {
                    "type": "Record",
                    "attributes": {"owner": {"type": "Entity", "name": "User"}},
                }
            },
        },
        "actions": {
            "view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Photo"]}},
            "edit": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Photo"]}},
        },
    }
})

ENTITIES_JSON = json.dumps([
    {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
    {"uid": {"type": "Photo", "id": "vacation.jpg"},
     "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}}},
     "parents": []},
])

OWNER_POLICY = (
    'permit(principal, action == Action::"view", resource)\n'
    'when { resource.owner == principal };'
)

ALICE_VIEW = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Photo::"vacation.jpg"',
    "context": {},
}


class SchemaConstructionTestCase(unittest.TestCase):
    def test_from_str_constructs_handle(self) -> None:
        s = Schema.from_str(SCHEMA_CEDAR)
        self.assertIsNotNone(s)

    def test_from_json_str_constructs_handle(self) -> None:
        s = Schema.from_json_str(SCHEMA_JSON)
        self.assertIsNotNone(s)

    def test_from_str_raises_on_invalid(self) -> None:
        with self.assertRaises(ValueError):
            Schema.from_str("not a valid cedar schema {{{{")

    def test_from_json_str_raises_on_invalid(self) -> None:
        with self.assertRaises(ValueError):
            Schema.from_json_str("{not valid json")

    def test_from_json_str_raises_on_invalid_schema_structure(self) -> None:
        with self.assertRaises(ValueError):
            Schema.from_json_str('{"not_a_valid": "cedar json schema"}')

    def test_repr_reports_entity_type_and_action_counts(self) -> None:
        s = Schema.from_str(SCHEMA_CEDAR)
        self.assertEqual("Schema(<2 entity types, 2 actions>)", repr(s))


class SchemaStrTestCase(unittest.TestCase):
    """str() renders the schema to Cedar schema syntax, whichever format the
    handle was constructed from, and the rendering round-trips through
    Schema.from_str."""

    def test_str_renders_cedar_syntax(self) -> None:
        rendered = str(Schema.from_str(SCHEMA_CEDAR))
        self.assertIn("entity User", rendered)
        self.assertIn("entity Photo", rendered)
        self.assertIn('action "view"', rendered)

    def test_str_of_json_constructed_schema_renders_cedar_syntax(self) -> None:
        rendered = str(Schema.from_json_str(SCHEMA_JSON))
        self.assertIn("entity User", rendered)
        self.assertIn('action "view"', rendered)

    def test_str_round_trips_through_from_str(self) -> None:
        for original in (Schema.from_str(SCHEMA_CEDAR), Schema.from_json_str(SCHEMA_JSON)):
            reparsed = Schema.from_str(str(original))
            from_original = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=original)
            from_reparsed = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=reparsed)
            self.assertEqual(Decision.Allow, from_reparsed.decision)
            self.assertEqual(from_original.decision, from_reparsed.decision)


class SchemaAuthzEquivalenceTestCase(unittest.TestCase):
    """A Schema handle must produce identical authorization results to a string."""

    def test_is_authorized_with_schema_handle_matches_string(self) -> None:
        schema_handle = Schema.from_json_str(SCHEMA_JSON)
        from_str = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=SCHEMA_JSON)
        from_handle = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=schema_handle)
        self.assertEqual(Decision.Allow, from_handle.decision)
        self.assertEqual(from_str.decision, from_handle.decision)
        self.assertEqual(
            sorted(from_str.diagnostics.reasons),
            sorted(from_handle.diagnostics.reasons),
        )

    def test_is_authorized_batch_with_schema_handle(self) -> None:
        schema_handle = Schema.from_str(SCHEMA_CEDAR)
        bob_view = {
            "principal": 'User::"alice"',
            "action": 'Action::"edit"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {},
        }
        results = is_authorized_batch(
            [ALICE_VIEW, bob_view], OWNER_POLICY, ENTITIES_JSON, schema=schema_handle)
        self.assertEqual(Decision.Allow, results[0].decision)


class SchemaReuseTestCase(unittest.TestCase):
    """A single Schema handle reused across calls."""

    def test_reuse_across_multiple_is_authorized_calls(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        for _ in range(10):
            result = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=schema)
            self.assertEqual(Decision.Allow, result.decision)


class SchemaPartialTestCase(unittest.TestCase):
    """is_authorized_partial accepts a Schema handle."""

    def test_partial_with_schema_handle(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        result = is_authorized_partial(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=schema)
        self.assertEqual(Decision.Allow, result.decision)


class SchemaValidateTestCase(unittest.TestCase):
    """validate_policies accepts a Schema handle."""

    def test_validate_with_schema_handle_passes(self) -> None:
        schema = Schema.from_str(SCHEMA_CEDAR)
        result = validate_policies(OWNER_POLICY, schema)
        self.assertTrue(result.validation_passed)
        self.assertEqual([], result.errors)

    def test_validate_with_schema_handle_detects_errors(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        bad_policy = 'permit(principal == BadType::"x", action, resource);'
        result = validate_policies(bad_policy, schema)
        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)


class SchemaEntitiesTestCase(unittest.TestCase):
    """Entities.from_json_str and with_added_json_str accept a Schema handle."""

    def test_entities_from_json_str_with_schema_handle(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        e_handle = Entities.from_json_str(ENTITIES_JSON, schema=schema)
        e_str = Entities.from_json_str(ENTITIES_JSON, schema=SCHEMA_JSON)
        self.assertEqual(len(e_str), len(e_handle))

    def test_entities_from_json_str_rejects_invalid_entities_against_handle(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        bad_entities = json.dumps([
            {"uid": {"type": "Photo", "id": "x.jpg"}, "attrs": {}, "parents": []},
        ])
        with self.assertRaises(ValueError):
            Entities.from_json_str(bad_entities, schema=schema)

    def test_entities_with_added_json_str_with_schema_handle(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        base = Entities.from_json_str(
            json.dumps([{"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []}]),
            schema=schema,
        )
        delta = json.dumps([
            {"uid": {"type": "Photo", "id": "p.jpg"},
             "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}}},
             "parents": []},
        ])
        merged = base.with_added_json_str(delta, schema=schema)
        # String-path equivalent
        base_str = Entities.from_json_str(
            json.dumps([{"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []}]),
            schema=SCHEMA_JSON,
        )
        merged_str = base_str.with_added_json_str(delta, schema=SCHEMA_JSON)
        self.assertEqual(len(merged_str), len(merged))


class SchemaMetricsTestCase(unittest.TestCase):
    """The schema_pre_parsed metric distinguishes the reuse path."""

    def test_pre_parsed_flag_set_for_handle(self) -> None:
        schema = Schema.from_json_str(SCHEMA_JSON)
        metrics = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=schema).metrics
        self.assertEqual(1, metrics["schema_pre_parsed"])

    def test_pre_parsed_flag_unset_for_string(self) -> None:
        metrics = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=SCHEMA_JSON).metrics
        self.assertEqual(0, metrics["schema_pre_parsed"])


if __name__ == "__main__":
    unittest.main()
