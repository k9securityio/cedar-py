"""Unit tests for policies_to_pst and cedarpy.pst."""
import dataclasses
import json
import unittest

from cedarpy import policies_to_pst
from cedarpy.pst import (
    ActionEq, ActionIn, BinaryOp, Char, EntityUid, GetAttr, HasAttr,
    IfThenElse, Is, Like, Literal, PolicySet, Record, ScopeEq, ScopeIs,
    ScopeIsIn, Set, Slot, Template, UnaryOp, Unless, Var, When, Wildcard,
)


def _clause(result, policy_id="policy0", index=0):
    return result.static_policies[policy_id].clauses[index]


def _expr(result, policy_id="policy0", index=0):
    return _clause(result, policy_id, index).expr


class TestScopeAndClauses(unittest.TestCase):
    def test_when_and_unless_clauses(self):
        result = policies_to_pst(
            'permit(principal, action, resource) '
            'when { resource.public == true } '
            'unless { resource.blocked };'
        )
        policy = result.static_policies["policy0"]
        self.assertEqual(policy.effect, "permit")
        self.assertEqual(len(policy.clauses), 2)
        self.assertIsInstance(policy.clauses[0], When)
        self.assertIsInstance(policy.clauses[1], Unless)

    def test_forbid_effect(self):
        result = policies_to_pst('forbid(principal, action, resource) when { resource.blocked };')
        self.assertEqual(result.static_policies["policy0"].effect, "forbid")

    def test_scope_constraints(self):
        result = policies_to_pst(
            'permit(principal == User::"alice", action in [Action::"view", Action::"edit"], '
            'resource is Photo in Album::"vacation");'
        )
        policy = result.static_policies["policy0"]
        self.assertEqual(policy.principal, ScopeEq(entity=EntityUid("User", "alice")))
        self.assertEqual(
            policy.action, ActionIn((EntityUid("Action", "view"), EntityUid("Action", "edit")))
        )
        self.assertEqual(
            policy.resource, ScopeIsIn("Photo", EntityUid("Album", "vacation"))
        )

    def test_annotations(self):
        result = policies_to_pst('@id("my-policy")\npermit(principal, action, resource);')
        self.assertEqual(result.static_policies["policy0"].annotations, {"id": "my-policy"})


class TestExprShapes(unittest.TestCase):
    def test_bool_literal(self):
        result = policies_to_pst('permit(principal, action, resource) when { true };')
        self.assertEqual(_expr(result), Literal(True))

    def test_long_literal(self):
        result = policies_to_pst('permit(principal, action, resource) when { 42 == 42 };')
        self.assertEqual(_expr(result).left, Literal(42))

    def test_entity_literal(self):
        result = policies_to_pst('permit(principal, action, resource) when { principal == User::"alice" };')
        self.assertEqual(_expr(result).right, Literal(EntityUid("User", "alice")))

    def test_set_and_record(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { [1, 2].contains(1) && {"a": 1}.a == 1 };'
        )
        top = _expr(result)
        self.assertEqual(top.left.left, Set((Literal(1), Literal(2))))
        self.assertEqual(top.right.left.base, Record({"a": Literal(1)}))

    def test_has(self):
        result = policies_to_pst('permit(principal, action, resource) when { resource has owner };')
        self.assertEqual(_expr(result), HasAttr(base=Var("resource"), attrs=("owner",)))

    def test_has_nested_path_lowers_to_two_clauses(self):
        # `resource has a.b` lowers to `resource has a && (resource.a) has b`,
        # not one HasAttr with two attrs, confirmed against real parser output.
        result = policies_to_pst('permit(principal, action, resource) when { resource has address.street };')
        top = _expr(result)
        self.assertEqual(top.left, HasAttr(base=Var("resource"), attrs=("address",)))
        self.assertEqual(top.right.attrs, ("street",))
        self.assertIsInstance(top.right.base, GetAttr)

    def test_like(self):
        result = policies_to_pst('permit(principal, action, resource) when { resource.name like "a*b" };')
        expr = _expr(result)
        self.assertIsInstance(expr, Like)
        self.assertEqual(expr.pattern, (Char("a"), Wildcard(), Char("b")))

    def test_is_without_in(self):
        result = policies_to_pst('permit(principal, action, resource) when { resource is Photo };')
        expr = _expr(result)
        self.assertEqual(expr, Is(base=Var("resource"), entity_type="Photo", in_expr=None))

    def test_is_with_in(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { resource is Photo in Album::"vacation" };'
        )
        expr = _expr(result)
        self.assertIsInstance(expr, Is)
        self.assertEqual(expr.in_expr, Literal(EntityUid("Album", "vacation")))

    def test_if_then_else(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { (if resource.flag then 1 else 2) == 1 };'
        )
        cond_expr = _expr(result).left
        self.assertIsInstance(cond_expr, IfThenElse)
        self.assertEqual(cond_expr.then_expr, Literal(1))
        self.assertEqual(cond_expr.else_expr, Literal(2))

    def test_unary_op(self):
        result = policies_to_pst('permit(principal, action, resource) when { !resource.blocked };')
        self.assertEqual(_expr(result), UnaryOp(op="not", arg=GetAttr(Var("resource"), "blocked")))

    def test_binary_op_names(self):
        cases = {"==": "eq", "!=": "not_eq", "<": "less", ">=": "greater_eq", "+": "add"}
        for symbol, expected in cases.items():
            result = policies_to_pst(f'permit(principal, action, resource) when {{ 1 {symbol} 1 }};')
            self.assertEqual(_expr(result).op, expected, msg=symbol)

    def test_slot_in_template(self):
        result = policies_to_pst('permit(principal == ?principal, action, resource);')
        self.assertNotIn("policy0", result.static_policies)
        self.assertEqual(result.templates["policy0"].principal, ScopeEq(entity=Slot("principal")))


class TestPatternMatching(unittest.TestCase):
    def test_nested_keyword_match(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { resource.status == "active" };'
        )
        match _expr(result):
            case BinaryOp(op="eq", left=GetAttr(base=Var(name="resource"), attr="status"), right=Literal(value="active")):
                matched = True
            case _:
                matched = False
        self.assertTrue(matched)

    def test_positional_match(self):
        result = policies_to_pst('permit(principal, action, resource) when { 1 == 1 };')
        match _expr(result):
            case BinaryOp(op, left, right):
                self.assertEqual((op, left, right), ("eq", Literal(1), Literal(1)))
            case _:
                self.fail("no match")


class TestImmutabilityAndSerialization(unittest.TestCase):
    def test_frozen(self):
        result = policies_to_pst('permit(principal, action, resource);')
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.static_policies = {}

    def test_asdict_and_json(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { resource.status == "active" };'
        )
        as_dict = dataclasses.asdict(result)
        self.assertEqual(
            as_dict["static_policies"]["policy0"]["clauses"][0]["expr"]["op"], "eq"
        )
        json.dumps(as_dict)  # must not raise


class TestErrorHandling(unittest.TestCase):
    def test_unparseable_policy_raises(self):
        with self.assertRaises(ValueError):
            policies_to_pst("this is not cedar")

    def test_empty_policy_set(self):
        result = policies_to_pst("")
        self.assertEqual(result, PolicySet(templates={}, static_policies={}, template_links=()))


class TestResidualsOutOfScope(unittest.TestCase):
    def test_is_authorized_partial_is_unaffected(self):
        from cedarpy import Decision, is_authorized_partial

        result = is_authorized_partial(
            {"principal": 'User::"alice"', "action": 'Action::"view"'},
            'permit(principal, action, resource) when { resource.status == "active" };',
            "[]",
        )
        self.assertEqual(result.decision, Decision.NoDecision)
        self.assertIn("policy0", result.residuals)
