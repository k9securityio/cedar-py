"""Unit tests for the reusable Entities handle.

An Entities handle lets callers parse an entity graph once and reuse the
parsed object across authorization calls, avoiding the per-call re-parse
(JSON deserialization plus transitive-closure computation). These tests assert
that the handle path is a behavior-preserving, opt-in alternative to passing
entities as a JSON string or list.

The handle also supports an immutable "add a per-request delta" path via
``with_added_json_str``: a large, stable base graph is parsed once and a small
delta (e.g. the entities specific to one request) is merged in per call,
parsing only the delta. ``with_added_json_str`` returns a NEW handle and leaves
the base unchanged.

Feature follow-up from https://github.com/k9securityio/cedar-py/issues/83
"""
import json
import unittest
from concurrent.futures import ThreadPoolExecutor

from cedarpy import (
    Entities,
    Decision,
    is_authorized,
    is_authorized_batch,
    is_authorized_partial,
)


# A small entity graph: alice owns vacation.jpg; the policy below permits an
# owner to view their own photo, so the decision depends on the entity data.
ENTITIES_JSON = json.dumps([
    {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
    {"uid": {"type": "User", "id": "bob"}, "attrs": {}, "parents": []},
    {"uid": {"type": "Photo", "id": "vacation.jpg"},
     "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}}},
     "parents": []},
])

# permit a principal to view a photo they own.
OWNER_POLICY = (
    'permit(principal, action == Action::"view", resource)\n'
    'when { resource.owner == principal };'
)

ALICE_VIEW = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Photo::"vacation.jpg"',
}
BOB_VIEW = {
    "principal": 'User::"bob"',
    "action": 'Action::"view"',
    "resource": 'Photo::"vacation.jpg"',
}


class EntitiesConstructionTestCase(unittest.TestCase):
    def test_from_json_str_constructs_handle(self) -> None:
        e = Entities.from_json_str(ENTITIES_JSON)
        self.assertIsInstance(e, Entities)
        self.assertEqual(3, len(e))

    def test_empty_entities(self) -> None:
        e = Entities.from_json_str("[]")
        self.assertEqual(0, len(e))

    def test_str_renders_back_to_parseable_json(self) -> None:
        e = Entities.from_json_str(ENTITIES_JSON)
        rendered = str(e)
        # rendered JSON must itself parse back into an equivalent set
        self.assertEqual(3, len(Entities.from_json_str(rendered)))

    def test_from_json_str_raises_value_error_on_malformed_json(self) -> None:
        with self.assertRaises(ValueError):
            Entities.from_json_str("{not valid json")

    def test_cannot_construct_directly(self) -> None:
        # No __new__/__init__ is exposed; callers must use from_json_str.
        with self.assertRaises(TypeError):
            Entities(ENTITIES_JSON)  # type: ignore[call-arg]


class EntitiesEquivalenceTestCase(unittest.TestCase):
    """The handle path must produce results identical to the JSON-string path."""

    def setUp(self) -> None:
        self.entities = Entities.from_json_str(ENTITIES_JSON)

    def _assert_equivalent(self, request: dict) -> None:
        from_str = is_authorized(request, OWNER_POLICY, ENTITIES_JSON)
        from_handle = is_authorized(request, OWNER_POLICY, self.entities)
        self.assertEqual(from_str.decision, from_handle.decision)
        self.assertEqual(
            sorted(from_str.diagnostics.reasons),
            sorted(from_handle.diagnostics.reasons),
        )
        self.assertEqual(from_str.diagnostics.errors, from_handle.diagnostics.errors)

    def test_owner_allowed_matches_string_path(self) -> None:
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, OWNER_POLICY, self.entities).decision)
        self._assert_equivalent(ALICE_VIEW)

    def test_non_owner_denied_matches_string_path(self) -> None:
        self.assertEqual(Decision.Deny, is_authorized(BOB_VIEW, OWNER_POLICY, self.entities).decision)
        self._assert_equivalent(BOB_VIEW)


class EntitiesBackwardCompatTestCase(unittest.TestCase):
    """The existing str and list entities forms keep working unchanged, and
    agree with the handle path."""

    def test_str_list_and_handle_all_agree(self) -> None:
        entities_list = json.loads(ENTITIES_JSON)
        handle = Entities.from_json_str(ENTITIES_JSON)
        from_str = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON).decision
        from_list = is_authorized(ALICE_VIEW, OWNER_POLICY, entities_list).decision
        from_handle = is_authorized(ALICE_VIEW, OWNER_POLICY, handle).decision
        self.assertEqual(Decision.Allow, from_str)
        self.assertEqual(from_str, from_list)
        self.assertEqual(from_str, from_handle)


class EntitiesReuseTestCase(unittest.TestCase):
    """A single handle must be reusable across calls, including in batch."""

    def test_batch_accepts_handle(self) -> None:
        e = Entities.from_json_str(ENTITIES_JSON)
        results = is_authorized_batch([ALICE_VIEW, BOB_VIEW], OWNER_POLICY, e)
        self.assertEqual([Decision.Allow, Decision.Deny], [r.decision for r in results])
        # parity with the string path
        results_str = is_authorized_batch([ALICE_VIEW, BOB_VIEW], OWNER_POLICY, ENTITIES_JSON)
        self.assertEqual([r.decision for r in results_str], [r.decision for r in results])


class EntitiesPartialTestCase(unittest.TestCase):
    """is_authorized_partial must also accept a handle."""

    def test_partial_accepts_handle(self) -> None:
        e = Entities.from_json_str(ENTITIES_JSON)
        request = {**ALICE_VIEW, "context": {}}
        from_handle = is_authorized_partial(request, OWNER_POLICY, e)
        from_str = is_authorized_partial(request, OWNER_POLICY, ENTITIES_JSON)
        self.assertEqual(from_str.decision, from_handle.decision)


class EntitiesAddTestCase(unittest.TestCase):
    """with_added_json_str merges a delta, immutably, and matches the merged JSON."""

    BASE_JSON = json.dumps([
        {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
        {"uid": {"type": "User", "id": "bob"}, "attrs": {}, "parents": []},
    ])
    # delta: the photo entity specific to this request, owned by alice
    DELTA_JSON = json.dumps([
        {"uid": {"type": "Photo", "id": "vacation.jpg"},
         "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}}},
         "parents": []},
    ])

    def test_add_matches_passing_merged_json(self) -> None:
        base = Entities.from_json_str(self.BASE_JSON)
        merged_handle = base.with_added_json_str(self.DELTA_JSON)

        merged_list = json.loads(self.BASE_JSON) + json.loads(self.DELTA_JSON)
        merged_json = json.dumps(merged_list)

        from_handle = is_authorized(ALICE_VIEW, OWNER_POLICY, merged_handle)
        from_json = is_authorized(ALICE_VIEW, OWNER_POLICY, merged_json)
        self.assertEqual(Decision.Allow, from_handle.decision)
        self.assertEqual(from_json.decision, from_handle.decision)

    def test_add_returns_new_handle_and_leaves_base_unchanged(self) -> None:
        base = Entities.from_json_str(self.BASE_JSON)
        self.assertEqual(2, len(base))
        merged = base.with_added_json_str(self.DELTA_JSON)
        self.assertEqual(3, len(merged))
        # immutability: base is untouched, a distinct object is returned
        self.assertEqual(2, len(base))
        self.assertIsNot(base, merged)

    def test_duplicate_uid_with_differing_attrs_raises(self) -> None:
        base = Entities.from_json_str(self.BASE_JSON)
        # same uid as base's alice, but different attrs -> disjoint-union error
        clashing = json.dumps([
            {"uid": {"type": "User", "id": "alice"},
             "attrs": {"role": "admin"}, "parents": []},
        ])
        with self.assertRaises(ValueError):
            base.with_added_json_str(clashing)

    def test_identical_duplicate_uid_is_allowed(self) -> None:
        # An entity identical to one already present is a no-op, not an error.
        base = Entities.from_json_str(self.BASE_JSON)
        identical = json.dumps([
            {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
        ])
        merged = base.with_added_json_str(identical)
        self.assertEqual(2, len(merged))

    def test_add_malformed_delta_raises(self) -> None:
        base = Entities.from_json_str(self.BASE_JSON)
        with self.assertRaises(ValueError):
            base.with_added_json_str("{not json")


class EntitiesBasePlusDeltaScenarioTestCase(unittest.TestCase):
    """Realistic 'stable base graph + per-request delta' pattern.

    This mirrors the downstream (emu) use case that motivated the handle: a
    large, stable base entity graph (org users and groups) is parsed once, then
    each request adds only the small set of entities specific to that request
    (the resources being acted on) via with_added_json_str, which parses only the
    delta. The base handle is reused across every request.
    """

    # Stable base: users belonging to groups. Parsed once, reused for all requests.
    BASE_JSON = json.dumps([
        {"uid": {"type": "User", "id": "alice"}, "attrs": {},
         "parents": [{"type": "Group", "id": "engineering"}]},
        {"uid": {"type": "User", "id": "bob"}, "attrs": {},
         "parents": [{"type": "Group", "id": "sales"}]},
        {"uid": {"type": "Group", "id": "engineering"}, "attrs": {}, "parents": []},
        {"uid": {"type": "Group", "id": "sales"}, "attrs": {}, "parents": []},
    ])

    # Engineering group members may view a document they own.
    POLICY = (
        'permit(principal in Group::"engineering", action == Action::"view", resource)\n'
        'when { resource.owner == principal };'
    )

    @staticmethod
    def _doc_delta(doc_id: str, owner: str) -> str:
        """The request-specific entities: the document being viewed."""
        return json.dumps([
            {"uid": {"type": "Document", "id": doc_id},
             "attrs": {"owner": {"__entity": {"type": "User", "id": owner}}},
             "parents": []},
        ])

    def setUp(self) -> None:
        self.base = Entities.from_json_str(self.BASE_JSON)

    def test_base_reused_with_per_request_delta(self) -> None:
        # alice (engineering) owns doc-1 -> allowed
        per_request = self.base.with_added_json_str(self._doc_delta("doc-1", "alice"))
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Document::"doc-1"',
        }
        self.assertEqual(Decision.Allow, is_authorized(request, self.POLICY, per_request).decision)

        # bob is in sales, not engineering -> denied, reusing the SAME base handle
        per_request_bob = self.base.with_added_json_str(self._doc_delta("doc-2", "bob"))
        request_bob = {
            "principal": 'User::"bob"',
            "action": 'Action::"view"',
            "resource": 'Document::"doc-2"',
        }
        self.assertEqual(Decision.Deny, is_authorized(request_bob, self.POLICY, per_request_bob).decision)

        # base must be unchanged after both adds
        self.assertEqual(4, len(self.base))


class EntitiesSchemaTestCase(unittest.TestCase):
    """The schema is applied at construction; well-typed entities pass,
    ill-typed entities are rejected eagerly."""

    SCHEMA = json.dumps({
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
                "view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Photo"]}}
            },
        }
    })

    def test_handle_built_with_schema_matches_string_with_schema(self) -> None:
        handle = Entities.from_json_str(ENTITIES_JSON, schema=self.SCHEMA)
        from_handle = is_authorized(ALICE_VIEW, OWNER_POLICY, handle, schema=self.SCHEMA)
        from_str = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON, schema=self.SCHEMA)
        self.assertEqual(Decision.Allow, from_handle.decision)
        self.assertEqual(from_str.decision, from_handle.decision)

    def test_construction_rejects_entities_violating_schema(self) -> None:
        # Photo missing its required 'owner' attribute -> schema violation.
        bad = json.dumps([
            {"uid": {"type": "Photo", "id": "x.jpg"}, "attrs": {}, "parents": []},
        ])
        with self.assertRaises(ValueError):
            Entities.from_json_str(bad, schema=self.SCHEMA)

    def test_dict_schema_accepted_like_other_apis(self) -> None:
        # schema may be a dict (not just a JSON string), matching is_authorized's
        # convention; the dict form must behave identically to the string form,
        # on both the construction and add paths.
        schema_dict = json.loads(self.SCHEMA)
        self.assertEqual(
            len(Entities.from_json_str(ENTITIES_JSON, schema=self.SCHEMA)),
            len(Entities.from_json_str(ENTITIES_JSON, schema=schema_dict)),
        )
        self.assertEqual(
            len(Entities.from_json_str("[]").with_added_json_str(ENTITIES_JSON, schema=self.SCHEMA)),
            len(Entities.from_json_str("[]").with_added_json_str(ENTITIES_JSON, schema=schema_dict)),
        )


class EntitiesIndependenceTestCase(unittest.TestCase):
    """Multiple distinct handles must not interfere."""

    def test_two_handles_stay_independent(self) -> None:
        alice_owns = json.dumps([
            {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
            {"uid": {"type": "Photo", "id": "p.jpg"},
             "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}}},
             "parents": []},
        ])
        bob_owns = json.dumps([
            {"uid": {"type": "User", "id": "bob"}, "attrs": {}, "parents": []},
            {"uid": {"type": "Photo", "id": "p.jpg"},
             "attrs": {"owner": {"__entity": {"type": "User", "id": "bob"}}},
             "parents": []},
        ])
        e_alice = Entities.from_json_str(alice_owns)
        e_bob = Entities.from_json_str(bob_owns)

        req = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p.jpg"'}
        # under e_alice, alice owns p.jpg -> Allow; under e_bob, bob owns it -> Deny
        self.assertEqual(Decision.Allow, is_authorized(req, OWNER_POLICY, e_alice).decision)
        self.assertEqual(Decision.Deny, is_authorized(req, OWNER_POLICY, e_bob).decision)


class EntitiesConcurrencyTestCase(unittest.TestCase):
    """A single base handle shared across threads must stay correct, including
    when each thread derives its own per-request delta from it.

    The GIL serializes the underlying calls, so this does not exercise true
    parallelism; it guards that the handle is *shareable* (the pyclass is
    Send/Sync, not ``unsendable``) and that deriving deltas from one shared base
    across threads produces correct, uncorrupted results.
    """

    def test_shared_base_with_per_thread_delta(self) -> None:
        base = EntitiesBasePlusDeltaScenarioTestCase.BASE_JSON
        policy = EntitiesBasePlusDeltaScenarioTestCase.POLICY
        shared = Entities.from_json_str(base)

        # (owner, expected) — alice is engineering (Allow), bob is sales (Deny)
        cases = [("alice", Decision.Allow), ("bob", Decision.Deny)] * 40  # 80 calls

        def run(case):
            owner, expected = case
            doc = f"doc-{owner}"
            per_request = shared.with_added_json_str(
                EntitiesBasePlusDeltaScenarioTestCase._doc_delta(doc, owner))
            request = {
                "principal": f'User::"{owner}"',
                "action": 'Action::"view"',
                "resource": f'Document::"{doc}"',
            }
            return is_authorized(request, policy, per_request).decision == expected

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, cases))

        self.assertTrue(all(results))
        self.assertEqual(len(cases), len(results))
        self.assertEqual(4, len(shared))  # base unchanged


class EntitiesTypeErrorTestCase(unittest.TestCase):
    """Wrong-typed entities argument is rejected with TypeError."""

    def test_int_entities_raises_type_error(self) -> None:
        # Not a str, not a list, not an Entities -> no extractor variant matches.
        with self.assertRaises(TypeError):
            is_authorized(ALICE_VIEW, OWNER_POLICY, 123)  # type: ignore[arg-type]


class EntitiesMetricsTestCase(unittest.TestCase):
    """The entities_pre_parsed metric distinguishes the reuse path."""

    def test_pre_parsed_flag_set_for_handle(self) -> None:
        e = Entities.from_json_str(ENTITIES_JSON)
        metrics = is_authorized(ALICE_VIEW, OWNER_POLICY, e).metrics
        self.assertEqual(1, metrics["entities_pre_parsed"])

    def test_pre_parsed_flag_unset_for_string(self) -> None:
        metrics = is_authorized(ALICE_VIEW, OWNER_POLICY, ENTITIES_JSON).metrics
        self.assertEqual(0, metrics["entities_pre_parsed"])


if __name__ == "__main__":
    unittest.main()
