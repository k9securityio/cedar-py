"""Unit tests for tpe_authorize."""
import unittest

from cedarpy import Decision, is_authorized_partial, tpe_authorize
from cedarpy.pst import BinaryOp, GetAttr, Template, Var

SCHEMA = """
    entity User;
    entity Doc = { status: String };
    action "view" appliesTo { principal: [User], resource: [Doc] };
"""

POLICIES = """
    permit(principal, action == Action::"view", resource)
    when { resource.status == "active" };
"""

PERMIT_AND_FORBID = """
    permit(principal, action == Action::"view", resource);
    forbid(principal, action == Action::"view", resource)
    when { resource.status == "blocked" };
"""


def _doc(doc_id, status):
    return f'[{{"uid": {{"type": "Doc", "id": "{doc_id}"}}, "attrs": {{"status": "{status}"}}, "parents": []}}]'


class TestPrincipalAndResourcePartiality(unittest.TestCase):
    def test_type_only_resource_produces_a_residual(self):
        result = tpe_authorize('User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA)
        self.assertIsNone(result.decision)
        self.assertEqual(result.permits.residual_ids, ("policy0",))

    def test_concrete_resource_resolves_allow(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"', POLICIES, _doc("d1", "active"), SCHEMA
        )
        self.assertEqual(result.decision, Decision.Allow)
        self.assertEqual(result.permits.true_ids, ("policy0",))
        self.assertEqual(result.residual_policies, {})

    def test_concrete_resource_resolves_deny(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"', POLICIES, _doc("d1", "inactive"), SCHEMA
        )
        self.assertEqual(result.decision, Decision.Deny)
        self.assertEqual(result.permits.false_ids, ("policy0",))


class TestPermitForbidStaySeparate(unittest.TestCase):
    def test_forbid_true_overrides_permit_true(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"', PERMIT_AND_FORBID, _doc("d1", "blocked"), SCHEMA
        )
        self.assertEqual(result.decision, Decision.Deny)
        self.assertEqual(result.permits.true_ids, ("policy0",))
        self.assertEqual(result.forbids.true_ids, ("policy1",))

    def test_residual_forbid_blocks_an_otherwise_true_permit(self):
        result = tpe_authorize('User::"alice"', 'Action::"view"', "Doc", PERMIT_AND_FORBID, "[]", SCHEMA)
        self.assertIsNone(result.decision)
        self.assertEqual(result.permits.true_ids, ("policy0",))
        self.assertEqual(result.forbids.residual_ids, ("policy1",))


class TestResidualPoliciesAreTypedNodes(unittest.TestCase):
    def test_residual_is_a_template_matching_the_expression(self):
        result = tpe_authorize('User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA)
        residual = result.residual_policies["policy0"]
        self.assertIsInstance(residual, Template)
        match residual.clauses[0].expr:
            case BinaryOp(op="eq", left=GetAttr(base=Var(name="resource"), attr="status")):
                matched = True
            case _:
                matched = False
        self.assertTrue(matched)

    def test_trivial_residuals_are_not_repeated(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"', POLICIES, _doc("d1", "active"), SCHEMA
        )
        self.assertEqual(result.residual_policies, {})


class TestIsAuthorizedPartialIsUnaffected(unittest.TestCase):
    def test_untouched(self):
        result = is_authorized_partial(
            {"principal": 'User::"alice"', "action": 'Action::"view"'}, POLICIES, "[]"
        )
        self.assertEqual(result.decision, Decision.NoDecision)
        self.assertIn("policy0", result.residuals)


class TestErrorHandling(unittest.TestCase):
    def test_missing_schema_raises(self):
        with self.assertRaises(ValueError):
            tpe_authorize('User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", "")

    def test_unparseable_principal_raises(self):
        with self.assertRaises(ValueError):
            tpe_authorize("not valid::", 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA)

    def test_bare_type_action_raises(self):
        with self.assertRaises(ValueError):
            tpe_authorize('User::"alice"', "Action", "Doc", POLICIES, "[]", SCHEMA)

    def test_unparseable_policies_raises(self):
        with self.assertRaises(ValueError):
            tpe_authorize('User::"alice"', 'Action::"view"', "Doc", "not cedar", "[]", SCHEMA)

    def test_unparseable_entities_raises(self):
        with self.assertRaises(ValueError):
            tpe_authorize('User::"alice"', 'Action::"view"', "Doc", POLICIES, "not json", SCHEMA)
