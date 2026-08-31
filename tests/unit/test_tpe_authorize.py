"""Unit tests for tpe_authorize."""
import unittest

from cedarpy import (
    Decision, PartialEntities, PolicySet, TpeAuthzResult, TpeClassification,
    is_authorized, is_authorized_partial, tpe_authorize, tpe_reauthorize,
)
from cedarpy.pst import (
    BinaryOp, EntityType, EntityUid, GetAttr, Template, Var, entity_uids,
)

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


CONTEXT_SCHEMA = """
    entity User;
    entity Doc = { status: String };
    action "view" appliesTo {
        principal: [User],
        resource: [Doc],
        context: { mfa: Bool }
    };
"""

CONTEXT_POLICIES = """
    permit(principal, action == Action::"view", resource)
    when { context.mfa };
"""


class TestContextUnknownVersusEmpty(unittest.TestCase):
    """`context=None` means unknown, matching PartialRequest and
    is_authorized_partial. A known-empty context is `{}`."""

    def test_omitted_context_is_unknown_and_stays_residual(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"',
            CONTEXT_POLICIES, _doc("d1", "active"), CONTEXT_SCHEMA,
        )
        self.assertIsNone(result.decision)
        self.assertEqual(result.permits.residual_ids, ("policy0",))

    def test_explicit_context_resolves(self):
        allowed = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"',
            CONTEXT_POLICIES, _doc("d1", "active"), CONTEXT_SCHEMA, context={"mfa": True},
        )
        self.assertEqual(allowed.decision, Decision.Allow)

        denied = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"',
            CONTEXT_POLICIES, _doc("d1", "active"), CONTEXT_SCHEMA, context={"mfa": False},
        )
        self.assertEqual(denied.decision, Decision.Deny)

    def test_empty_context_is_not_the_same_as_unknown(self):
        # {} is a known context, so a policy reading a required attribute of it
        # is an error rather than a residual.
        with self.assertRaises(ValueError):
            tpe_authorize(
                'User::"alice"', 'Action::"view"', 'Doc::"d1"',
                CONTEXT_POLICIES, _doc("d1", "active"), CONTEXT_SCHEMA, context={},
            )


class TestEntityUidInputForms(unittest.TestCase):
    def test_dict_form_for_a_concrete_entity(self):
        result = tpe_authorize(
            {"type": "User", "id": "alice"},
            {"type": "Action", "id": "view"},
            {"type": "Doc", "id": "d1"},
            POLICIES, _doc("d1", "active"), SCHEMA,
        )
        self.assertEqual(result.decision, Decision.Allow)

    def test_dict_without_id_means_an_unknown_id(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', {"type": "Doc"}, POLICIES, "[]", SCHEMA
        )
        self.assertIsNone(result.decision)
        self.assertEqual(result.permits.residual_ids, ("policy0",))

    def test_pst_entity_type_means_an_unknown_id(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', EntityType("Doc"), POLICIES, "[]", SCHEMA
        )
        self.assertIsNone(result.decision)
        self.assertEqual(result.permits.residual_ids, ("policy0",))

    def test_id_cedar_surface_syntax_rejects_is_accepted_in_dict_form(self):
        result = tpe_authorize(
            {"type": "User", "id": "alice\nbob"},
            'Action::"view"', 'Doc::"d1"', POLICIES, _doc("d1", "active"), SCHEMA,
        )
        self.assertEqual(result.decision, Decision.Allow)

    def test_unusable_euid_input_type_raises(self):
        with self.assertRaises(TypeError):
            tpe_authorize(42, 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA)


class TestResidualPolicySetHandle(unittest.TestCase):
    def test_residuals_come_back_as_a_reusable_policy_set(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA
        )
        self.assertIsInstance(result.residual_policy_set, PolicySet)
        self.assertEqual(len(result.residual_policy_set), 1)

        # The handle drops straight into is_authorized once the unknowns are bound.
        decided = is_authorized(
            {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'},
            result.residual_policy_set, _doc("d1", "active"), SCHEMA,
        )
        self.assertEqual(decided.decision, Decision.Allow)


class TestReauthorize(unittest.TestCase):
    def test_binding_the_unknown_reaches_a_decision(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA
        )
        self.assertIsNone(result.decision)

        allowed = result.reauthorize(
            {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'},
            entities=_doc("d1", "active"),
        )
        self.assertEqual(allowed.decision, Decision.Allow)
        self.assertEqual(allowed.diagnostics.reasons, ["policy0"])

        denied = result.reauthorize(
            {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'},
            entities=_doc("d1", "inactive"),
        )
        self.assertEqual(denied.decision, Decision.Deny)

    def test_reauthorize_reuses_the_entities_tpe_ran_with(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", POLICIES, _doc("d1", "active"), SCHEMA
        )
        allowed = result.reauthorize(
            {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'}
        )
        self.assertEqual(allowed.decision, Decision.Allow)

    def test_a_request_contradicting_the_partial_request_raises(self):
        # TPE was told the principal is User::"alice"; reauthorizing as someone
        # else is not a decision the partial evaluation sanctioned.
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA
        )
        with self.assertRaises(ValueError):
            result.reauthorize(
                {"principal": 'User::"bob"', "action": 'Action::"view"', "resource": 'Doc::"d1"'},
                entities=_doc("d1", "active"),
            )

    def test_reauthorize_carries_the_correlation_id(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", POLICIES, "[]", SCHEMA
        )
        decided = result.reauthorize(
            {
                "principal": 'User::"alice"', "action": 'Action::"view"',
                "resource": 'Doc::"d1"', "correlation_id": "req-42",
            },
            entities=_doc("d1", "active"),
        )
        self.assertEqual(decided.correlation_id, "req-42")

    def test_free_function_takes_the_inputs_explicitly(self):
        decided = tpe_reauthorize(
            request={"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'},
            principal='User::"alice"', action='Action::"view"', resource="Doc",
            policies=POLICIES, entities=_doc("d1", "active"), schema=SCHEMA,
        )
        self.assertEqual(decided.decision, Decision.Allow)

    def test_a_hand_built_result_cannot_reauthorize(self):
        bare = TpeAuthzResult(
            decision=None, reason=(), permits=TpeClassification((), (), (), ()),
            forbids=TpeClassification((), (), (), ()), residual_policies={},
            residual_policy_set=PolicySet.from_str(""), metrics={},
        )
        with self.assertRaises(ValueError):
            bare.reauthorize({"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'})


PARTIAL_ENTITIES = [
    # status is unknown: the entity exists, its attributes do not yet.
    {"uid": {"type": "Doc", "id": "d1"}, "parents": []},
]


class TestPartialEntities(unittest.TestCase):
    def test_unknown_entity_attributes_stay_residual(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"',
            POLICIES, PartialEntities.from_json(PARTIAL_ENTITIES), SCHEMA,
        )
        self.assertIsNone(result.decision)
        self.assertEqual(result.permits.residual_ids, ("policy0",))

    def test_the_same_entities_fully_known_resolve(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"',
            POLICIES, PartialEntities.from_json(
                [{"uid": {"type": "Doc", "id": "d1"}, "attrs": {"status": "active"}, "parents": []}]
            ), SCHEMA,
        )
        self.assertEqual(result.decision, Decision.Allow)

    def test_reauthorizing_a_partial_document_requires_concrete_entities(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', 'Doc::"d1"',
            POLICIES, PartialEntities.from_json(PARTIAL_ENTITIES), SCHEMA,
        )
        request = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Doc::"d1"'}
        with self.assertRaises(ValueError):
            result.reauthorize(request)

        decided = result.reauthorize(request, entities=_doc("d1", "active"))
        self.assertEqual(decided.decision, Decision.Allow)

    def test_from_json_accepts_text_as_well_as_data(self):
        as_text = PartialEntities.from_json('[{"uid": {"type": "Doc", "id": "d1"}, "parents": []}]')
        self.assertEqual(as_text, PartialEntities.from_json(PARTIAL_ENTITIES))

    def test_malformed_partial_entities_raise(self):
        with self.assertRaises(ValueError):
            tpe_authorize(
                'User::"alice"', 'Action::"view"', 'Doc::"d1"',
                POLICIES, PartialEntities.from_json("not json"), SCHEMA,
            )


class TestEntityUidsOnResiduals(unittest.TestCase):
    """What a residual still needs loaded, which is why `entity_uids` exists.

    A residual from `is_authorized_partial` cannot become a PST at all, so this
    is the case the walk is for: a TPE residual is a `pst.Template`, and asking
    it which entities it names tells you what to fetch before finishing the
    evaluation.
    """

    SCHEMA = """
        entity Group;
        entity User in [Group];
        entity Doc = { status: String, owner: User };
        action "view" appliesTo { principal: [User], resource: [Doc] };
    """
    POLICIES = """
        permit(principal, action == Action::"view", resource)
        when { resource.owner == User::"bob" || principal in Group::"admins" };
    """

    def test_a_residual_names_the_entities_still_to_be_loaded(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", self.POLICIES, "[]", self.SCHEMA
        )
        self.assertIsNone(result.decision)
        self.assertEqual(
            entity_uids(result.residual_policies["policy0"]),
            frozenset({
                EntityUid(EntityType("User"), "bob"),
                EntityUid(EntityType("User"), "alice"),
                EntityUid(EntityType("Group"), "admins"),
            }),
        )

    def test_the_whole_residual_mapping_can_be_walked_at_once(self):
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", self.POLICIES, "[]", self.SCHEMA
        )
        self.assertEqual(
            entity_uids(result.residual_policies),
            entity_uids(result.residual_policies["policy0"]),
        )

    def test_the_residual_policy_set_handle_is_not_a_pst_node(self):
        """`residual_policy_set` is the engine's handle, not nodes.

        Walking it would silently find nothing, so it raises instead. Convert
        it with `to_pst()` first, or use `residual_policies`.
        """
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", self.POLICIES, "[]", self.SCHEMA
        )
        with self.assertRaises(TypeError):
            entity_uids(result.residual_policy_set)
        self.assertIsInstance(entity_uids(result.residual_policy_set.to_pst()), frozenset)

    def test_the_two_residual_views_are_not_interchangeable(self):
        """`residual_policies` is the reduced view; the handle is every residual.

        `residual_policy_set` carries all residuals, including the ones that
        came out concretely true, false or erroring, and keeps each policy's
        original scope. `residual_policies` carries only the ones still
        undecided, as the evaluator reduced them, with the concrete parts of
        the request already substituted in. So the entities they name differ,
        and which one to ask depends on the question.
        """
        result = tpe_authorize(
            'User::"alice"', 'Action::"view"', "Doc", self.POLICIES, "[]", self.SCHEMA
        )
        reduced = entity_uids(result.residual_policies)
        everything = entity_uids(result.residual_policy_set.to_pst())

        # The reduced residual has the concrete principal folded in.
        self.assertIn(EntityUid(EntityType("User"), "alice"), reduced)
        self.assertNotIn(EntityUid(EntityType("User"), "alice"), everything)
        # The full set keeps the action scope the reduced residual dropped.
        self.assertIn(EntityUid(EntityType("Action"), "view"), everything)
        self.assertNotIn(EntityUid(EntityType("Action"), "view"), reduced)
        # Both still name what the undecided condition depends on.
        for uid in (EntityUid(EntityType("User"), "bob"),
                    EntityUid(EntityType("Group"), "admins")):
            with self.subTest(uid=str(uid)):
                self.assertIn(uid, reduced)
                self.assertIn(uid, everything)
