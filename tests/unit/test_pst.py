"""Unit tests for policies_to_pst and cedarpy.pst."""
import dataclasses
import json
import typing
import unittest

from cedarpy import policies_to_pst
from cedarpy.pst import (
    ActionEq, ActionIn, BinaryOp, BoolLit, Char, EntityLit, EntityType,
    EntityUid, FrozenMap, GetAttr, HasAttr, IfThenElse, Is, Like, LongLit,
    PolicySet, Record, ScopeEq, ScopeIs, ScopeIsIn, Set, Slot, StringLit,
    Template, UnaryOp, Unless, Var, When, Wildcard,
)


def _uid(type_name, id_):
    *namespace, basename = type_name.split("::")
    return EntityUid(EntityType(basename, tuple(namespace)), id_)


def _etype(type_name):
    *namespace, basename = type_name.split("::")
    return EntityType(basename, tuple(namespace))


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
        self.assertEqual(policy.principal, ScopeEq(entity=_uid("User", "alice")))
        self.assertEqual(
            policy.action, ActionIn((_uid("Action", "view"), _uid("Action", "edit")))
        )
        self.assertEqual(
            policy.resource, ScopeIsIn(_etype("Photo"), _uid("Album", "vacation"))
        )

    def test_annotations(self):
        result = policies_to_pst('@id("my-policy")\npermit(principal, action, resource);')
        self.assertEqual(result.static_policies["policy0"].annotations, {"id": "my-policy"})


class TestExprShapes(unittest.TestCase):
    def test_bool_literal(self):
        result = policies_to_pst('permit(principal, action, resource) when { true };')
        self.assertEqual(_expr(result), BoolLit(True))

    def test_long_literal(self):
        result = policies_to_pst('permit(principal, action, resource) when { 42 == 42 };')
        self.assertEqual(_expr(result).left, LongLit(42))

    def test_entity_literal(self):
        result = policies_to_pst('permit(principal, action, resource) when { principal == User::"alice" };')
        self.assertEqual(_expr(result).right, EntityLit(_uid("User", "alice")))

    def test_set_and_record(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { [1, 2].contains(1) && {"a": 1}.a == 1 };'
        )
        top = _expr(result)
        self.assertEqual(top.left.left, Set((LongLit(1), LongLit(2))))
        self.assertEqual(top.right.left.base, Record(FrozenMap({"a": LongLit(1)})))

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
        self.assertEqual(expr, Is(base=Var("resource"), entity_type=_etype("Photo"), in_expr=None))

    def test_is_with_in(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { resource is Photo in Album::"vacation" };'
        )
        expr = _expr(result)
        self.assertIsInstance(expr, Is)
        self.assertEqual(expr.in_expr, EntityLit(_uid("Album", "vacation")))

    def test_if_then_else(self):
        result = policies_to_pst(
            'permit(principal, action, resource) when { (if resource.flag then 1 else 2) == 1 };'
        )
        cond_expr = _expr(result).left
        self.assertIsInstance(cond_expr, IfThenElse)
        self.assertEqual(cond_expr.then_expr, LongLit(1))
        self.assertEqual(cond_expr.else_expr, LongLit(2))

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
            case BinaryOp(op="eq", left=GetAttr(base=Var(name="resource"), attr="status"), right=StringLit(value="active")):
                matched = True
            case _:
                matched = False
        self.assertTrue(matched)

    def test_positional_match(self):
        result = policies_to_pst('permit(principal, action, resource) when { 1 == 1 };')
        match _expr(result):
            case BinaryOp(op, left, right):
                self.assertEqual((op, left, right), ("eq", LongLit(1), LongLit(1)))
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


class TestClosedSetsAndNamespaces(unittest.TestCase):
    def test_namespaced_entity_type_keeps_its_parts(self):
        result = policies_to_pst(
            'permit(principal == MyApp::Nested::User::"alice", action, resource);'
        )
        entity = result.static_policies["policy0"].principal.entity
        self.assertEqual(entity.type, EntityType("User", ("MyApp", "Nested")))
        self.assertEqual(str(entity.type), "MyApp::Nested::User")
        self.assertEqual(str(entity), 'MyApp::Nested::User::"alice"')

    def test_unqualified_entity_type_has_empty_namespace(self):
        result = policies_to_pst('permit(principal == User::"alice", action, resource);')
        self.assertEqual(
            result.static_policies["policy0"].principal.entity.type,
            EntityType("User", ()),
        )

    def test_bool_and_long_literals_are_distinct_nodes(self):
        # bool is a subclass of int in Python, so a single Literal(value) node
        # cannot tell Cedar's Bool from its Long.
        result = policies_to_pst(
            'permit(principal, action, resource) when { context.a == true && context.b == 1 };'
        )
        top = _expr(result)
        self.assertEqual(top.left.right, BoolLit(True))
        self.assertEqual(top.right.right, LongLit(1))
        self.assertNotEqual(top.left.right, top.right.right)

    def test_every_emitted_op_name_is_in_the_literal_alias(self):
        from cedarpy.pst import BinaryOpName, UnaryOpName

        cases = {
            "==": "eq", "!=": "not_eq", "<": "less", "<=": "less_eq",
            ">": "greater", ">=": "greater_eq", "&&": "and", "||": "or",
            "+": "add", "-": "sub", "*": "mul",
        }
        binary_names = set(typing.get_args(BinaryOpName))
        for symbol, expected in cases.items():
            result = policies_to_pst(
                f'permit(principal, action, resource) when {{ (1 {symbol} 1) == (1 {symbol} 1) }};'
                if symbol in ("&&", "||") else
                f'permit(principal, action, resource) when {{ 1 {symbol} 1 }};'
            )
            op = _expr(result).op if symbol not in ("&&", "||") else _expr(result).left.op
            self.assertEqual(op, expected, msg=symbol)
            self.assertIn(op, binary_names, msg=symbol)

        result = policies_to_pst('permit(principal, action, resource) when { !resource.blocked };')
        self.assertIn(_expr(result).op, set(typing.get_args(UnaryOpName)))

    def test_effect_and_var_names_are_in_their_literal_aliases(self):
        from cedarpy.pst import Effect, SlotName, VarName

        result = policies_to_pst(
            'permit(principal == ?principal, action, resource) when { context.x == principal };'
        )
        template = result.templates["policy0"]
        self.assertIn(template.effect, set(typing.get_args(Effect)))
        self.assertIn(template.principal.entity.name, set(typing.get_args(SlotName)))
        self.assertIn(template.clauses[0].expr.left.base.name, set(typing.get_args(VarName)))


class TestFrozenMapIsAValue(unittest.TestCase):
    def test_mapping_fields_reject_mutation(self):
        result = policies_to_pst('@id("x")\npermit(principal, action, resource) when { context.r == {"k": 1} };')
        policy = result.static_policies["policy0"]
        for mapping in (result.static_policies, policy.annotations, _expr(result).right.fields):
            self.assertIsInstance(mapping, FrozenMap)
            with self.assertRaises(TypeError):
                mapping["injected"] = None
            with self.assertRaises(TypeError):
                mapping.update({"injected": None})

    def test_nodes_are_hashable_and_usable_as_keys(self):
        result = policies_to_pst('permit(principal, action, resource) when { context.r == {"k": 1} };')
        again = policies_to_pst('permit(principal, action, resource) when { context.r == {"k": 1} };')
        record = _expr(result).right
        self.assertEqual({record: "seen"}[_expr(again).right], "seen")
        self.assertEqual(len({result, again}), 1)

    def test_mapping_still_compares_equal_to_a_plain_dict(self):
        result = policies_to_pst('@id("my-policy")\npermit(principal, action, resource);')
        self.assertEqual(result.static_policies["policy0"].annotations, {"id": "my-policy"})


class TestNonEmptyInvariants(unittest.TestCase):
    def test_has_attr_rejects_an_empty_path(self):
        # Rust models this field as NonEmpty<SmolStr>.
        with self.assertRaises(ValueError):
            HasAttr(base=Var("resource"), attrs=())
