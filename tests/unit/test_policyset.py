"""Unit tests for the reusable PolicySet handle.

A PolicySet handle lets callers parse policies once and reuse the parsed
object across authorization calls, avoiding the per-call re-parse. These
tests assert that the handle path is a behavior-preserving, opt-in
alternative to passing policy text as a string.

Feature from https://github.com/k9securityio/cedar-py/issues/83
"""
import unittest
from concurrent.futures import ThreadPoolExecutor

from cedarpy import (
    PolicySet,
    Decision,
    is_authorized,
    is_authorized_batch,
    is_authorized_partial,
    policies_to_json_str,
)


POLICIES = """
permit(principal == User::"alice", action == Action::"view", resource);
forbid(principal, action == Action::"view", resource == Photo::"secret.jpg");
""".strip()

ENTITIES = "[]"

ALLOW_REQUEST = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Photo::"vacation.jpg"',
}
DENY_REQUEST = {
    "principal": 'User::"alice"',
    "action": 'Action::"view"',
    "resource": 'Photo::"secret.jpg"',
}
# bob is not granted view by any policy -> implicit deny
IMPLICIT_DENY_REQUEST = {
    "principal": 'User::"bob"',
    "action": 'Action::"view"',
    "resource": 'Photo::"vacation.jpg"',
}


class PolicySetConstructionTestCase(unittest.TestCase):
    def test_from_str_constructs_handle(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        self.assertIsInstance(ps, PolicySet)
        self.assertEqual(2, len(ps))

    def test_repr_reports_policy_count(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        self.assertEqual("PolicySet(<2 policies>)", repr(ps))

    def test_str_renders_back_to_cedar_text(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        rendered = str(ps)
        self.assertIn("permit", rendered)
        self.assertIn("forbid", rendered)
        # rendered text must itself parse back into an equivalent set
        self.assertEqual(2, len(PolicySet.from_str(rendered)))

    def test_from_str_raises_value_error_eagerly_on_bad_policies(self) -> None:
        with self.assertRaises(ValueError):
            PolicySet.from_str("this is not valid cedar {{{")

    def test_cannot_construct_directly(self) -> None:
        # No __new__/__init__ is exposed; callers must pick a parse format.
        with self.assertRaises(TypeError):
            PolicySet(POLICIES)  # type: ignore[call-arg]

    def test_from_json_str_round_trips_with_policies_to_json_str(self) -> None:
        est_json = policies_to_json_str(POLICIES)
        ps = PolicySet.from_json_str(est_json)
        self.assertEqual(2, len(ps))

    def test_from_json_str_raises_value_error_on_bad_json(self) -> None:
        with self.assertRaises(ValueError):
            PolicySet.from_json_str('{"not": "a valid policy set"}')


class PolicySetEquivalenceTestCase(unittest.TestCase):
    """The handle path must produce results identical to the string path."""

    def setUp(self) -> None:
        self.ps = PolicySet.from_str(POLICIES)

    def _assert_equivalent(self, request: dict) -> None:
        from_str = is_authorized(request, POLICIES, ENTITIES)
        from_handle = is_authorized(request, self.ps, ENTITIES)
        self.assertEqual(from_str.decision, from_handle.decision)
        self.assertEqual(
            sorted(from_str.diagnostics.reasons),
            sorted(from_handle.diagnostics.reasons),
        )
        self.assertEqual(from_str.diagnostics.errors, from_handle.diagnostics.errors)

    def test_allow_decision_matches_string_path(self) -> None:
        self.assertEqual(Decision.Allow, is_authorized(ALLOW_REQUEST, self.ps, ENTITIES).decision)
        self._assert_equivalent(ALLOW_REQUEST)

    def test_explicit_forbid_matches_string_path(self) -> None:
        self.assertEqual(Decision.Deny, is_authorized(DENY_REQUEST, self.ps, ENTITIES).decision)
        self._assert_equivalent(DENY_REQUEST)

    def test_implicit_deny_matches_string_path(self) -> None:
        self.assertEqual(Decision.Deny, is_authorized(IMPLICIT_DENY_REQUEST, self.ps, ENTITIES).decision)
        self._assert_equivalent(IMPLICIT_DENY_REQUEST)


class PolicySetReuseTestCase(unittest.TestCase):
    """A single handle must be reusable across many independent calls."""

    def test_handle_reused_across_many_calls(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        requests = [ALLOW_REQUEST, DENY_REQUEST, IMPLICIT_DENY_REQUEST] * 5
        expected = [Decision.Allow, Decision.Deny, Decision.Deny] * 5
        actual = [is_authorized(r, ps, ENTITIES).decision for r in requests]
        self.assertEqual(expected, actual)

    def test_batch_accepts_handle(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        results = is_authorized_batch([ALLOW_REQUEST, DENY_REQUEST], ps, ENTITIES)
        self.assertEqual(
            [Decision.Allow, Decision.Deny],
            [r.decision for r in results],
        )
        # parity with the string path
        results_str = is_authorized_batch([ALLOW_REQUEST, DENY_REQUEST], POLICIES, ENTITIES)
        self.assertEqual(
            [r.decision for r in results_str],
            [r.decision for r in results],
        )


class PolicySetPartialTestCase(unittest.TestCase):
    """is_authorized_partial must also accept a handle."""

    def test_partial_accepts_handle(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        # principal known, others concrete -> definitive decision
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {},
        }
        from_handle = is_authorized_partial(request, ps, ENTITIES)
        from_str = is_authorized_partial(request, POLICIES, ENTITIES)
        self.assertEqual(from_str.decision, from_handle.decision)


class PolicySetSchemaTestCase(unittest.TestCase):
    """Handle path must compose with a schema the same way the string path does."""

    SCHEMA = """
        entity User;
        entity Photo;
        action "view" appliesTo { principal: [User], resource: [Photo] };
    """.strip()

    def test_handle_with_schema_matches_string_with_schema(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        from_handle = is_authorized(ALLOW_REQUEST, ps, ENTITIES, schema=self.SCHEMA)
        from_str = is_authorized(ALLOW_REQUEST, POLICIES, ENTITIES, schema=self.SCHEMA)
        self.assertEqual(Decision.Allow, from_handle.decision)
        self.assertEqual(from_str.decision, from_handle.decision)


class PolicySetEdgeCaseTestCase(unittest.TestCase):
    """Empty and template-containing policy sets."""

    def test_empty_policy_set(self) -> None:
        ps = PolicySet.from_str("")
        self.assertEqual(0, len(ps))
        # empty policies -> implicit deny, identical via string and handle
        from_handle = is_authorized(ALLOW_REQUEST, ps, ENTITIES)
        from_str = is_authorized(ALLOW_REQUEST, "", ENTITIES)
        self.assertEqual(Decision.Deny, from_handle.decision)
        self.assertEqual(from_str.decision, from_handle.decision)

    def test_policy_set_with_template_matches_string_path(self) -> None:
        # A set mixing a static policy and an (unlinked) template. Templates are
        # not counted by __len__ (PolicySet.policies() yields static policies),
        # and an unlinked template applies to no request.
        mixed = (
            'permit(principal == User::"alice", action == Action::"view", resource);\n'
            'permit(principal == ?principal, action == Action::"edit", resource);'
        )
        ps = PolicySet.from_str(mixed)
        self.assertEqual(1, len(ps))  # only the static policy is counted

        ps_request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
        }
        from_handle = is_authorized(ps_request, ps, ENTITIES)
        from_str = is_authorized(ps_request, mixed, ENTITIES)
        self.assertEqual(Decision.Allow, from_handle.decision)
        self.assertEqual(from_str.decision, from_handle.decision)
        self.assertEqual(
            sorted(from_str.diagnostics.reasons),
            sorted(from_handle.diagnostics.reasons),
        )

    def test_template_set_via_partial_matches_string_path(self) -> None:
        # is_authorized_partial iterates the policy set for annotations/residuals;
        # exercise that path with a template present through the handle.
        mixed = (
            'permit(principal == User::"alice", action == Action::"view", resource);\n'
            'permit(principal == ?principal, action == Action::"edit", resource);'
        )
        ps = PolicySet.from_str(mixed)
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": {},
        }
        from_handle = is_authorized_partial(request, ps, ENTITIES)
        from_str = is_authorized_partial(request, mixed, ENTITIES)
        self.assertEqual(from_str.decision, from_handle.decision)


class PolicySetIndependenceTestCase(unittest.TestCase):
    """Multiple distinct handles must not interfere."""

    def test_two_handles_stay_independent(self) -> None:
        alice_policies = 'permit(principal == User::"alice", action == Action::"view", resource);'
        bob_policies = 'permit(principal == User::"bob", action == Action::"view", resource);'
        ps_alice = PolicySet.from_str(alice_policies)
        ps_bob = PolicySet.from_str(bob_policies)

        alice_req = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'P::"1"'}
        bob_req = {"principal": 'User::"bob"', "action": 'Action::"view"', "resource": 'P::"1"'}

        # interleave the two handles; each must reflect only its own policies
        self.assertEqual(Decision.Allow, is_authorized(alice_req, ps_alice, ENTITIES).decision)
        self.assertEqual(Decision.Deny, is_authorized(bob_req, ps_alice, ENTITIES).decision)
        self.assertEqual(Decision.Allow, is_authorized(bob_req, ps_bob, ENTITIES).decision)
        self.assertEqual(Decision.Deny, is_authorized(alice_req, ps_bob, ENTITIES).decision)


class PolicySetConcurrencyTestCase(unittest.TestCase):
    """A single handle shared across threads must stay correct.

    The GIL serializes the underlying authorization calls, so this does not
    exercise true parallelism; what it guards is that the handle is *shareable*
    across threads (the pyclass is Send/Sync, not `unsendable`) and that sharing
    one handle across threads produces correct, uncorrupted results. It would
    fail if the pyclass were ever made thread-bound.
    """

    def test_shared_handle_across_threads(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        cases = [
            (ALLOW_REQUEST, Decision.Allow),
            (DENY_REQUEST, Decision.Deny),
            (IMPLICIT_DENY_REQUEST, Decision.Deny),
        ] * 40  # 120 calls

        def run(case):
            request, expected = case
            return is_authorized(request, ps, ENTITIES).decision == expected

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, cases))

        self.assertTrue(all(results))
        self.assertEqual(len(cases), len(results))


class PolicySetTypeErrorTestCase(unittest.TestCase):
    """Wrong-typed policies argument is rejected with TypeError."""

    def test_int_policies_raises_type_error(self) -> None:
        # Not a str and not a PolicySet -> neither extractor variant matches.
        with self.assertRaises(TypeError):
            is_authorized(ALLOW_REQUEST, 123, ENTITIES)  # type: ignore[arg-type]

    def test_bytes_policies_raises_type_error(self) -> None:
        # bytes must not silently coerce to a policies string.
        with self.assertRaises(TypeError):
            is_authorized(ALLOW_REQUEST, b"permit(principal, action, resource);", ENTITIES)  # type: ignore[arg-type]


class PolicySetMetricsTestCase(unittest.TestCase):
    """The policies_pre_parsed metric distinguishes the reuse path."""

    def test_pre_parsed_flag_set_for_handle(self) -> None:
        ps = PolicySet.from_str(POLICIES)
        metrics = is_authorized(ALLOW_REQUEST, ps, ENTITIES).metrics
        self.assertEqual(1, metrics["policies_pre_parsed"])

    def test_pre_parsed_flag_unset_for_string(self) -> None:
        metrics = is_authorized(ALLOW_REQUEST, POLICIES, ENTITIES).metrics
        self.assertEqual(0, metrics["policies_pre_parsed"])


if __name__ == "__main__":
    unittest.main()
