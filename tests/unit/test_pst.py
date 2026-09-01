"""Unit tests for policies_to_pst and cedarpy.pst."""
import dataclasses
import json

import cedarpy
import typing
import unittest

from cedarpy import policies_to_pst
from cedarpy.pst import (
    ActionEq, ActionIn, BinaryOp, BoolLit, Char, EntityLit, EntityType,
    EntityUid, Expr, FrozenMap, GetAttr, HasAttr, IfThenElse, Is, Like,
    LongLit, PolicySet, Record, ScopeAny, ScopeEq, ScopeIs, ScopeIsIn, Set,
    Slot, StringLit, Template, TemplateLink, UnaryOp, Unless, Var, When,
    Wildcard, entity_uids,
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


class TestEntityUidsWalk(unittest.TestCase):
    def test_collects_uids_from_scope_and_conditions(self):
        result = policies_to_pst(
            'permit(principal == User::"alice", action in [Action::"view", Action::"edit"], '
            'resource is Photo in Album::"vacation") '
            'when { resource.owner == User::"bob" || principal in Group::"admins" };'
        )
        self.assertEqual(
            entity_uids(result.static_policies["policy0"]),
            frozenset({
                _uid("User", "alice"), _uid("Action", "view"), _uid("Action", "edit"),
                _uid("Album", "vacation"), _uid("User", "bob"), _uid("Group", "admins"),
            }),
        )

    def test_reaches_uids_nested_in_sets_and_records(self):
        result = policies_to_pst(
            'permit(principal, action, resource) '
            'when { [User::"a", User::"b"].contains(principal) && {"k": User::"c"}.k == principal };'
        )
        self.assertEqual(
            entity_uids(_expr(result)),
            frozenset({_uid("User", "a"), _uid("User", "b"), _uid("User", "c")}),
        )

    def test_a_policy_naming_no_entity_yields_nothing(self):
        result = policies_to_pst('permit(principal, action, resource) when { resource.public };')
        self.assertEqual(entity_uids(result), frozenset())

    def test_walks_a_whole_policy_set_including_template_links(self):
        result = policies_to_pst(
            'permit(principal == ?principal, action == Action::"view", resource);'
        )
        self.assertEqual(entity_uids(result), frozenset({_uid("Action", "view")}))


class TestUnrepresentableNodesAreAbsent(unittest.TestCase):
    """Neither node kind can occur, so neither is modelled.

    `pst::Template` validates each clause as it is added and rejects any
    holding an `Unknown`. `ResidualError` needs cedar's `tpe` feature.
    """

    def test_the_node_types_are_not_exported(self):
        import cedarpy.pst as pst_module

        for name in ("Unknown", "ResidualError"):
            with self.subTest(name=name):
                self.assertNotIn(name, pst_module.__all__)
                self.assertFalse(hasattr(pst_module, name))

    def test_a_policy_holding_an_unknown_is_rejected_by_cedar(self):
        with self.assertRaises(ValueError) as caught:
            policies_to_pst(
                'permit(principal, action, resource) when { unknown("x") };'
            )
        self.assertIn("Unknown", str(caught.exception))


class TestEntityUidsRejectsWhatItCannotWalk(unittest.TestCase):
    """An empty result must mean "names no entity", not "wrong argument"."""

    def test_the_engines_own_policy_set_handle_is_rejected(self):
        from cedarpy import PolicySet as EnginePolicySet

        handle = EnginePolicySet.from_str(
            'permit(principal == User::"alice", action, resource);'
        )
        with self.assertRaises(TypeError) as caught:
            entity_uids(handle)
        self.assertIn("cedarpy.pst", str(caught.exception))

    def test_non_nodes_are_rejected(self):
        for value in (None, 42, "User::\"alice\"", {"a": 1}, object()):
            with self.subTest(value=value), self.assertRaises(TypeError):
                entity_uids(value)

    def test_a_mapping_or_tuple_of_nodes_is_accepted(self):
        result = policies_to_pst(
            'permit(principal == User::"alice", action, resource);'
            'permit(principal == User::"bob", action, resource);'
        )
        expected = frozenset({_uid("User", "alice"), _uid("User", "bob")})
        self.assertEqual(entity_uids(result.static_policies), expected)
        self.assertEqual(entity_uids(tuple(result.static_policies.values())), expected)


class TestPolicySetRoundTrip(unittest.TestCase):
    """`PolicySet.from_pst` / `.to_pst` are inverses of each other."""

    POLICIES = (
        '@id("labelled")\n'
        'permit(principal == ?principal, action == Action::"view", '
        'resource is My::App::Doc in ?resource)\n'
        'when { resource.status like "a*c" && principal has a.b.c }\n'
        'unless { context.n < 3 };\n'
        'permit(principal, action in [Action::"a", Action::"b"], resource)\n'
        'when { if principal.x then true else [1, 2].containsAny([3]) };\n'
        'forbid(principal is User, action, resource)\n'
        'when { resource.owner == User::"bob" && {"k": 1}.k == 1 };\n'
    )

    def test_nodes_survive_a_round_trip_unchanged(self):
        from cedarpy import PolicySet as EnginePolicySet

        nodes = policies_to_pst(self.POLICIES)
        self.assertEqual(EnginePolicySet.from_pst(nodes).to_pst(), nodes)

    def test_policies_to_pst_matches_from_str_then_to_pst(self):
        from cedarpy import PolicySet as EnginePolicySet

        self.assertEqual(
            policies_to_pst(self.POLICIES),
            EnginePolicySet.from_str(self.POLICIES).to_pst(),
        )

    def test_a_rebuilt_set_authorizes_the_same_way(self):
        from cedarpy import Decision, PolicySet as EnginePolicySet, is_authorized

        policies = 'permit(principal, action, resource) when { resource.public };'
        rebuilt = EnginePolicySet.from_pst(policies_to_pst(policies))
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Doc::"d1"',
            "context": {},
        }
        entities = json.dumps([
            {"uid": {"type": "Doc", "id": "d1"}, "attrs": {"public": True}, "parents": []}
        ])
        self.assertEqual(is_authorized(request, rebuilt, entities).decision, Decision.Allow)

    def test_template_links_survive_a_round_trip(self):
        from cedarpy import PolicySet as EnginePolicySet

        linked = EnginePolicySet.from_str(self.POLICIES).with_linked(
            "policy0", "linked1",
            {"?principal": 'User::"alice"', "?resource": 'My::App::Folder::"f"'},
        )
        nodes = linked.to_pst()
        self.assertEqual(len(nodes.template_links), 1)
        self.assertEqual(nodes.template_links[0].new_id, "linked1")
        self.assertEqual(EnginePolicySet.from_pst(nodes).to_pst(), nodes)

    def test_an_edited_node_tree_rebuilds_into_a_working_set(self):
        """Change a node, get a policy set the engine will authorize against."""
        from cedarpy import Decision, PolicySet as EnginePolicySet, is_authorized

        nodes = policies_to_pst(
            'permit(principal == User::"alice", action, resource);'
        )
        original = nodes.static_policies["policy0"]
        retargeted = dataclasses.replace(
            original,
            principal=ScopeEq(_uid("User", "bob")),
        )
        edited = dataclasses.replace(
            nodes, static_policies={"policy0": retargeted},
        )
        rebuilt = EnginePolicySet.from_pst(edited)
        entities = "[]"
        for who, expected in (("bob", Decision.Allow), ("alice", Decision.Deny)):
            with self.subTest(principal=who):
                request = {
                    "principal": f'User::"{who}"',
                    "action": 'Action::"view"',
                    "resource": 'Doc::"d1"',
                    "context": {},
                }
                self.assertEqual(
                    is_authorized(request, rebuilt, entities).decision, expected
                )

    def test_from_pst_rejects_things_that_are_not_a_policy_set(self):
        from cedarpy import PolicySet as EnginePolicySet

        nodes = policies_to_pst('permit(principal, action, resource);')
        for value in (None, 42, nodes.static_policies["policy0"]):
            with self.subTest(value=value), self.assertRaises(TypeError):
                EnginePolicySet.from_pst(value)

    def test_from_pst_reports_a_link_to_a_missing_template(self):
        from cedarpy import PolicySet as EnginePolicySet

        nodes = policies_to_pst('permit(principal, action, resource);')
        broken = dataclasses.replace(nodes, template_links=(
            TemplateLink("no-such-template", "linked1",
                         {"principal": _uid("User", "alice")}),
        ))
        with self.assertRaises(ValueError):
            EnginePolicySet.from_pst(broken)


class TestExpressionDepthLimit(unittest.TestCase):
    """Expression nesting is capped at 100 levels in both directions.

    The limit is a behavioral contract: a later release may raise it, and
    lowering it would be a breaking change, so the boundary is pinned here.
    """

    @staticmethod
    def _nested_policy(n: int) -> str:
        return ("permit(principal, action, resource) when { "
                + "[" * n + "1" + "]" * n + " == 1 };")

    @staticmethod
    def _deep_nodes(n: int) -> PolicySet:
        expr: Expr = BoolLit(True)
        for _ in range(n):
            expr = UnaryOp("not", expr)
        template = Template(
            id="policy0", effect="permit",
            principal=ScopeAny(), action=ScopeAny(), resource=ScopeAny(),
            clauses=(When(expr),), annotations={},
        )
        return PolicySet(templates={}, static_policies={"policy0": template},
                         template_links=())

    def test_nesting_at_the_limit_converts(self):
        nodes = policies_to_pst(self._nested_policy(98))
        self.assertIn("policy0", nodes.static_policies)

    def test_nesting_past_the_limit_raises(self):
        with self.assertRaisesRegex(ValueError, "nesting exceeds the supported limit of 100"):
            policies_to_pst(self._nested_policy(99))

    def test_from_pst_accepts_nesting_under_the_limit(self):
        cedarpy.PolicySet.from_pst(self._deep_nodes(80))

    def test_from_pst_rejects_nesting_past_the_limit(self):
        with self.assertRaisesRegex(ValueError, "nesting exceeds the supported limit of 100"):
            cedarpy.PolicySet.from_pst(self._deep_nodes(150))

    def test_entity_uids_walks_trees_far_past_the_limit(self):
        # The walk is iterative, so hand-built trees deeper than the
        # conversion limit read fine rather than hitting RecursionError.
        self.assertEqual(entity_uids(self._deep_nodes(5000)), frozenset())
