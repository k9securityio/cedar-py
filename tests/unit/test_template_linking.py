"""Unit tests for Cedar template-linked policies on the PolicySet handle.

A Cedar *template* is a policy with `?principal` / `?resource` slots. It is
inert until linked: `with_linked` / `with_linked_batch` fill the slots with
concrete entities and return a NEW PolicySet handle (immutable, like
`with_added_str`) whose linked policies evaluate through `is_authorized` and
friends. `templates` (which lists each template's links) and `without_linked`
round out the lifecycle.

The `TemplateUpstreamSandboxCTestCase` cases reproduce the documented `link`
walkthrough from Cedar's own `sandbox_c` sample data (vendored under
`resources/sandbox_c/`), anchoring the binding to upstream behavior.

Feature from https://github.com/k9securityio/cedar-py/issues/29
"""
import unittest
from concurrent.futures import ThreadPoolExecutor

from cedarpy import (
    PolicySet,
    Decision,
    is_authorized,
    is_authorized_batch,
    is_authorized_partial,
)

from unit import load_file_as_str


def link_ids(ps: PolicySet) -> list:
    """All template-linked policy ids in the set, flattened from templates()."""
    return sorted(link["id"] for t in ps.templates() for link in t["links"])


# A single-slot (`?principal`) template carrying an @id annotation, plus a
# static policy alongside it so we also cover mixed sets.
PRINCIPAL_TEMPLATE = (
    '@id("grant-view")\n'
    'permit(principal == ?principal, action == Action::"view", resource);'
)

ENTITIES = "[]"

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
BOB_EDIT = {
    "principal": 'User::"bob"',
    "action": 'Action::"edit"',
    "resource": 'Photo::"vacation.jpg"',
}


def _link_alice(base: PolicySet) -> PolicySet:
    return base.with_linked(
        "grant-view", "grant-view-alice", {"?principal": 'User::"alice"'}
    )


class TemplateParsingTestCase(unittest.TestCase):
    """A template parses into the set but authorizes nothing until linked."""

    def test_template_not_counted_by_len(self) -> None:
        ps = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        # templates() is separate from policies(); __len__ counts policies only
        self.assertEqual(0, len(ps))

    def test_template_listed_by_templates(self) -> None:
        ps = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        templates = ps.templates()
        self.assertEqual(1, len(templates))
        t = templates[0]
        # the literal id is the parser-assigned policy0 (the @id is inert)
        self.assertEqual("policy0", t["id"])
        self.assertEqual("grant-view", t["id_annotation"])  # the @id value
        self.assertEqual(["?principal"], t["slots"])
        self.assertEqual([], t["links"])                    # nothing linked yet
        self.assertEqual([], link_ids(ps))

    def test_unlinked_template_authorizes_nothing(self) -> None:
        ps = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        self.assertEqual(Decision.Deny, is_authorized(ALICE_VIEW, ps, ENTITIES).decision)

    def test_str_renders_linked_policies_not_raw_templates(self) -> None:
        # Cedar's PolicySet Display renders policies() (static + linked), not the
        # templates themselves, so a template-only set stringifies to empty...
        ps = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        self.assertEqual("", str(ps).strip())
        # ...but once a slot is filled, the concrete linked policy renders.
        linked = _link_alice(ps)
        self.assertIn('User::"alice"', str(linked))

    def test_mixed_static_and_template_counts_only_static(self) -> None:
        mixed = (
            'permit(principal == User::"root", action == Action::"admin", resource);\n'
            + PRINCIPAL_TEMPLATE
        )
        ps = PolicySet.from_str(mixed)
        self.assertEqual(1, len(ps))               # only the static policy
        self.assertEqual(1, len(ps.templates()))   # one template


class TemplateLinkingTestCase(unittest.TestCase):
    """Linking fills a slot and the linked policy evaluates."""

    def test_link_returns_new_handle_leaving_base_unchanged(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        linked = _link_alice(base)
        self.assertIsNot(base, linked)
        self.assertEqual([], link_ids(base))                   # base untouched
        self.assertEqual(["grant-view-alice"], link_ids(linked))
        self.assertEqual(1, len(linked))                          # linked policy now counts

    def test_linked_policy_allows_matching_request(self) -> None:
        linked = _link_alice(PolicySet.from_str(PRINCIPAL_TEMPLATE))
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, linked, ENTITIES).decision)
        # a principal the slot was not filled with is still denied
        self.assertEqual(Decision.Deny, is_authorized(BOB_VIEW, linked, ENTITIES).decision)

    def test_link_by_literal_template_id(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        # policy0 is the literal id; linking by it works the same as by @id
        linked = base.with_linked("policy0", "by-literal", {"?principal": 'User::"alice"'})
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, linked, ENTITIES).decision)

    def test_linking_creates_new_policy_without_consuming_template(self) -> None:
        # new_id names a NEW policy; the template is not renamed or consumed and
        # can be linked again under a different new_id (one template, many grants)
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        once = base.with_linked("grant-view", "grant-for-alice", {"?principal": 'User::"alice"'})
        twice = once.with_linked("grant-view", "grant-for-bob", {"?principal": 'User::"bob"'})
        self.assertEqual(["grant-for-alice", "grant-for-bob"], link_ids(twice))
        # the template itself is still present (its @id unchanged), not renamed to a new_id
        self.assertEqual(["grant-view"], [t["id_annotation"] for t in twice.templates()])
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, twice, ENTITIES).decision)
        self.assertEqual(Decision.Allow, is_authorized(BOB_VIEW, twice, ENTITIES).decision)

    def test_link_matches_equivalent_static_policy(self) -> None:
        linked = _link_alice(PolicySet.from_str(PRINCIPAL_TEMPLATE))
        static = PolicySet.from_str(
            'permit(principal == User::"alice", action == Action::"view", resource);'
        )
        for req in (ALICE_VIEW, BOB_VIEW):
            self.assertEqual(
                is_authorized(req, static, ENTITIES).decision,
                is_authorized(req, linked, ENTITIES).decision,
            )


class TemplateBatchLinkingTestCase(unittest.TestCase):
    """with_linked_batch is the primary path; single linking is sugar over it."""

    def test_batch_links_many_across_different_templates(self) -> None:
        # one batch links several templates at once, including *different* ones —
        # here a view grant and an edit grant from two distinct templates
        base = PolicySet.from_str(
            '@id("grant-view")\n'
            'permit(principal == ?principal, action == Action::"view", resource);\n'
            '@id("grant-edit")\n'
            'permit(principal == ?principal, action == Action::"edit", resource);'
        )
        linked = base.with_linked_batch([
            {"template_id": "grant-view", "new_id": "alice-view",
             "values": {"?principal": 'User::"alice"'}},
            {"template_id": "grant-edit", "new_id": "bob-edit",
             "values": {"?principal": 'User::"bob"'}},
        ])
        self.assertEqual(["alice-view", "bob-edit"], link_ids(linked))
        # each link authorizes only its own template's action
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, linked, ENTITIES).decision)
        self.assertEqual(Decision.Allow, is_authorized(BOB_EDIT, linked, ENTITIES).decision)
        # cross action denied: bob holds an edit grant, not a view grant — proof
        # the two links came from genuinely different templates
        self.assertEqual(Decision.Deny, is_authorized(BOB_VIEW, linked, ENTITIES).decision)

    def test_single_and_batch_produce_identical_decisions(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        single = base.with_linked("grant-view", "alice", {"?principal": 'User::"alice"'})
        batch = base.with_linked_batch([
            {"template_id": "grant-view", "new_id": "alice",
             "values": {"?principal": 'User::"alice"'}},
        ])
        self.assertEqual(link_ids(single), link_ids(batch))
        self.assertEqual(
            is_authorized(ALICE_VIEW, single, ENTITIES).decision,
            is_authorized(ALICE_VIEW, batch, ENTITIES).decision,
        )

    def test_empty_batch_is_noop_returning_new_handle(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        same = base.with_linked_batch([])
        self.assertIsNot(base, same)
        self.assertEqual([], link_ids(same))

    def test_batch_is_all_or_nothing_on_failure(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        with self.assertRaises(ValueError):
            base.with_linked_batch([
                {"template_id": "grant-view", "new_id": "ok",
                 "values": {"?principal": 'User::"alice"'}},
                {"template_id": "no-such-template", "new_id": "boom",
                 "values": {"?principal": 'User::"bob"'}},
            ])
        # the base is borrowed immutably; a failed batch leaves it unchanged
        self.assertEqual([], link_ids(base))

    def test_batch_rejects_duplicate_new_id_within_the_batch(self) -> None:
        # two links in one batch claiming the same new_id is a collision; the
        # whole batch fails and the base is untouched (atomicity within a batch)
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        with self.assertRaises(ValueError):
            base.with_linked_batch([
                {"template_id": "grant-view", "new_id": "dup",
                 "values": {"?principal": 'User::"alice"'}},
                {"template_id": "grant-view", "new_id": "dup",
                 "values": {"?principal": 'User::"bob"'}},
            ])
        self.assertEqual([], link_ids(base))


class TemplateSlotValueFormsTestCase(unittest.TestCase):
    """Slot values accept a Cedar string or a {type, id} dict; ?resource works."""

    def test_principal_slot_accepts_type_id_dict(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        linked = base.with_linked(
            "grant-view", "alice", {"?principal": {"type": "User", "id": "alice"}}
        )
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, linked, ENTITIES).decision)

    def test_string_and_dict_forms_are_equivalent(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        as_str = base.with_linked("grant-view", "a", {"?principal": 'User::"alice"'})
        as_dict = base.with_linked("grant-view", "a", {"?principal": {"type": "User", "id": "alice"}})
        self.assertEqual(
            is_authorized(ALICE_VIEW, as_str, ENTITIES).decision,
            is_authorized(ALICE_VIEW, as_dict, ENTITIES).decision,
        )

    def test_resource_slot(self) -> None:
        template = (
            '@id("in-album")\n'
            'permit(principal == User::"alice", action == Action::"view", resource in ?resource);'
        )
        base = PolicySet.from_str(template)
        linked = base.with_linked("in-album", "alice-album", {"?resource": 'Album::"trip"'})
        entities = (
            '[{"uid": {"type": "Album", "id": "trip"}, "attrs": {}, "parents": []},'
            ' {"uid": {"type": "Photo", "id": "p1"}, "attrs": {}, "parents":'
            ' [{"type": "Album", "id": "trip"}]}]'
        )
        in_album = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p1"'}
        out_album = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"other"'}
        self.assertEqual(Decision.Allow, is_authorized(in_album, linked, entities).decision)
        self.assertEqual(Decision.Deny, is_authorized(out_album, linked, entities).decision)

    def test_both_slots(self) -> None:
        # multi-tenancy shape: a principal granted access within a resource group
        template = (
            '@id("member")\n'
            'permit(principal == ?principal, action == Action::"view", resource in ?resource);'
        )
        base = PolicySet.from_str(template)
        linked = base.with_linked(
            "member", "alice-trip",
            {"?principal": 'User::"alice"', "?resource": 'Album::"trip"'},
        )
        entities = (
            '[{"uid": {"type": "Album", "id": "trip"}, "attrs": {}, "parents": []},'
            ' {"uid": {"type": "Photo", "id": "p1"}, "attrs": {}, "parents":'
            ' [{"type": "Album", "id": "trip"}]}]'
        )
        req = {"principal": 'User::"alice"', "action": 'Action::"view"', "resource": 'Photo::"p1"'}
        self.assertEqual(Decision.Allow, is_authorized(req, linked, entities).decision)


class TemplateEvaluationPathsTestCase(unittest.TestCase):
    """A linked handle evaluates through every authorization entry point."""

    def setUp(self) -> None:
        self.linked = _link_alice(PolicySet.from_str(PRINCIPAL_TEMPLATE))

    def test_is_authorized(self) -> None:
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, self.linked, ENTITIES).decision)

    def test_is_authorized_batch(self) -> None:
        results = is_authorized_batch([ALICE_VIEW, BOB_VIEW], self.linked, ENTITIES)
        self.assertEqual([Decision.Allow, Decision.Deny], [r.decision for r in results])

    def test_is_authorized_partial(self) -> None:
        result = is_authorized_partial({**ALICE_VIEW, "context": {}}, self.linked, ENTITIES)
        self.assertEqual(Decision.Allow, result.decision)

    def test_linked_policy_id_annotation_surfaces_in_reasons(self) -> None:
        # The linked policy inherits the template's @id annotation; it should
        # resolve in id_annotations_by_reason for the matched linked policy.
        result = is_authorized(ALICE_VIEW, self.linked, ENTITIES)
        self.assertIn("grant-view", result.diagnostics.id_annotations_by_reason.values())


class TemplateIntrospectionTestCase(unittest.TestCase):
    """templates() reports each template and the links nested under it."""

    def test_templates_reports_definition_and_nested_links(self) -> None:
        base = PolicySet.from_str(PRINCIPAL_TEMPLATE)
        [t] = base.templates()
        self.assertEqual("policy0", t["id"])
        self.assertEqual("grant-view", t["id_annotation"])
        self.assertEqual(["?principal"], t["slots"])
        self.assertEqual([], t["links"])
        self.assertEqual([], link_ids(base))

        linked = base.with_linked_batch([
            {"template_id": "grant-view", "new_id": "alice",
             "values": {"?principal": 'User::"alice"'}},
            {"template_id": "grant-view", "new_id": "bob",
             "values": {"?principal": 'User::"bob"'}},
        ])
        # the template persists; each filling is nested under it with its values
        [t] = linked.templates()
        self.assertEqual("policy0", t["id"])
        links = sorted(t["links"], key=lambda link: link["id"])
        self.assertEqual(["alice", "bob"], [link["id"] for link in links])
        self.assertEqual({"?principal": 'User::"alice"'}, links[0]["values"])
        self.assertEqual({"?principal": 'User::"bob"'}, links[1]["values"])
        # link_ids() helper flattens the same ids out of templates()
        self.assertEqual(["alice", "bob"], link_ids(linked))

    def test_slots_is_a_set_returned_deterministically(self) -> None:
        # A template's slots are a set: each of ?principal / ?resource appears at
        # most once (a link's `values` is keyed by slot), so order is not part of
        # the contract. templates() returns them sorted, so the result is
        # deterministic (and the README example is reproducible).
        both = PolicySet.from_str(
            '@id("member")\n'
            'permit(principal == ?principal, action == Action::"view", resource in ?resource);'
        )
        [t] = both.templates()
        self.assertEqual({"?principal", "?resource"}, set(t["slots"]))  # the set contract
        self.assertEqual(len(t["slots"]), len(set(t["slots"])))         # no duplicates
        self.assertEqual(sorted(t["slots"]), t["slots"])                # deterministic, sorted

    def test_templates_id_annotation_none_when_absent(self) -> None:
        # a template with no @id reports id_annotation None (linkable by literal id)
        ps = PolicySet.from_str(
            'permit(principal == ?principal, action == Action::"view", resource);'
        )
        [t] = ps.templates()
        self.assertEqual("policy0", t["id"])
        self.assertIsNone(t["id_annotation"])

    def test_static_policies_excluded_from_links(self) -> None:
        mixed = (
            'permit(principal == User::"root", action == Action::"admin", resource);\n'
            + PRINCIPAL_TEMPLATE
        )
        linked = PolicySet.from_str(mixed).with_linked(
            "grant-view", "alice", {"?principal": 'User::"alice"'}
        )
        # only the template-linked policy appears under links, not the static one
        self.assertEqual(["alice"], link_ids(linked))


class TemplateUnlinkTestCase(unittest.TestCase):
    """without_linked removes a linked policy and returns a new handle."""

    def setUp(self) -> None:
        self.linked = PolicySet.from_str(PRINCIPAL_TEMPLATE).with_linked_batch([
            {"template_id": "grant-view", "new_id": "alice",
             "values": {"?principal": 'User::"alice"'}},
            {"template_id": "grant-view", "new_id": "bob",
             "values": {"?principal": 'User::"bob"'}},
        ])

    def test_unlink_removes_one_leaving_base_unchanged(self) -> None:
        fewer = self.linked.without_linked("bob")
        self.assertIsNot(self.linked, fewer)
        self.assertEqual(["alice", "bob"], link_ids(self.linked))  # original intact
        self.assertEqual(["alice"], link_ids(fewer))

    def test_unlinked_principal_is_denied(self) -> None:
        fewer = self.linked.without_linked("bob")
        self.assertEqual(Decision.Allow, is_authorized(ALICE_VIEW, fewer, ENTITIES).decision)
        self.assertEqual(Decision.Deny, is_authorized(BOB_VIEW, fewer, ENTITIES).decision)

    def test_relink_after_unlink(self) -> None:
        # the template is still present, so a removed link can be re-created
        fewer = self.linked.without_linked("bob")
        relinked = fewer.with_linked("grant-view", "bob", {"?principal": 'User::"bob"'})
        self.assertEqual(Decision.Allow, is_authorized(BOB_VIEW, relinked, ENTITIES).decision)


class TemplateErrorTestCase(unittest.TestCase):
    """Malformed link requests raise, and the base is never mutated."""

    def setUp(self) -> None:
        self.base = PolicySet.from_str(PRINCIPAL_TEMPLATE)

    def test_unknown_template_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.base.with_linked("nope", "x", {"?principal": 'User::"alice"'})

    def test_unknown_slot_key_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.base.with_linked("grant-view", "x", {"?nonsense": 'User::"alice"'})

    def test_wrong_slot_for_template_raises_value_error(self) -> None:
        # template declares ?principal; filling ?resource leaves it unfilled
        with self.assertRaises(ValueError):
            self.base.with_linked("grant-view", "x", {"?resource": 'Album::"a"'})

    def test_unparseable_slot_value_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.base.with_linked("grant-view", "x", {"?principal": "not valid cedar {{{"})

    def test_duplicate_new_id_raises_value_error(self) -> None:
        once = self.base.with_linked("grant-view", "dup", {"?principal": 'User::"alice"'})
        with self.assertRaises(ValueError):
            once.with_linked("grant-view", "dup", {"?principal": 'User::"bob"'})

    def test_missing_link_dict_keys_raise_key_error(self) -> None:
        for bad in (
            {"new_id": "x", "values": {"?principal": 'User::"alice"'}},      # no template_id
            {"template_id": "grant-view", "values": {"?principal": 'User::"alice"'}},  # no new_id
            {"template_id": "grant-view", "new_id": "x"},                    # no values
        ):
            with self.assertRaises(KeyError):
                self.base.with_linked_batch([bad])

    def test_ambiguous_id_annotation_raises_value_error(self) -> None:
        # two templates sharing one @id cannot be resolved by that @id
        two = PolicySet.from_str(
            '@id("dup")\npermit(principal == ?principal, action == Action::"view", resource);\n'
            '@id("dup")\npermit(principal == ?principal, action == Action::"edit", resource);'
        )
        with self.assertRaises(ValueError):
            two.with_linked("dup", "x", {"?principal": 'User::"alice"'})

    def test_unlink_unknown_id_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.base.without_linked("ghost")

    def test_unlink_static_policy_raises_value_error(self) -> None:
        static = PolicySet.from_str(
            'permit(principal == User::"root", action == Action::"admin", resource);'
        )
        # policy0 is a static policy, not a template-linked one
        with self.assertRaises(ValueError):
            static.without_linked("policy0")


class TemplateSchemaTestCase(unittest.TestCase):
    """A linked set composes with a schema the same way a static set does."""

    SCHEMA = """
        entity User;
        entity Photo;
        action "view" appliesTo { principal: [User], resource: [Photo] };
    """.strip()

    def test_linked_set_validates_against_schema(self) -> None:
        linked = _link_alice(PolicySet.from_str(PRINCIPAL_TEMPLATE))
        result = is_authorized(ALICE_VIEW, linked, ENTITIES, schema=self.SCHEMA)
        self.assertEqual(Decision.Allow, result.decision)


class TemplateConcurrencyTestCase(unittest.TestCase):
    """A single linked handle shared across threads stays correct."""

    def test_shared_linked_handle_across_threads(self) -> None:
        linked = PolicySet.from_str(PRINCIPAL_TEMPLATE).with_linked_batch([
            {"template_id": "grant-view", "new_id": "alice",
             "values": {"?principal": 'User::"alice"'}},
        ])
        cases = [(ALICE_VIEW, Decision.Allow), (BOB_VIEW, Decision.Deny)] * 60

        def run(case):
            request, expected = case
            return is_authorized(request, linked, ENTITIES).decision == expected

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, cases))
        self.assertTrue(all(results))
        self.assertEqual(len(cases), len(results))


class TemplateUpstreamSandboxCTestCase(unittest.TestCase):
    """Reproduce Cedar's own sandbox_c `link` walkthrough end to end.

    The fixture (vendored under resources/sandbox_c/) is the official Cedar
    sample: an `AccessVacation` template granting view on VacationPhoto94.jpg,
    linked per principal. The upstream README documents that linking `alice`
    then `bob` grants each of them access; we assert exactly that.
    """

    def setUp(self) -> None:
        # The upstream sandbox_c walkthrough authorizes without a schema (its
        # entities carry attributes the bundled schema does not declare), so we
        # reproduce it schema-free, matching the README's `authorize` commands.
        self.template = load_file_as_str("resources/sandbox_c/policies.cedar")
        self.entities = load_file_as_str("resources/sandbox_c/entities.json")
        self.view_vacation = {
            "action": 'Action::"view"',
            "resource": 'Photo::"VacationPhoto94.jpg"',
        }

    def _view(self, user: str) -> dict:
        return {"principal": f'User::"{user}"', **self.view_vacation}

    def test_unlinked_denies_everyone(self) -> None:
        base = PolicySet.from_str(self.template)
        self.assertEqual(
            Decision.Deny,
            is_authorized(self._view("alice"), base, self.entities).decision,
        )

    def test_link_alice_then_bob_grants_each_access(self) -> None:
        base = PolicySet.from_str(self.template)
        linked = base.with_linked_batch([
            {"template_id": "AccessVacation", "new_id": "AliceAccess",
             "values": {"?principal": 'User::"alice"'}},
            {"template_id": "AccessVacation", "new_id": "BobAccess",
             "values": {"?principal": 'User::"bob"'}},
        ])
        self.assertEqual(["AliceAccess", "BobAccess"], link_ids(linked))
        for user in ("alice", "bob"):
            self.assertEqual(
                Decision.Allow,
                is_authorized(self._view(user), linked, self.entities).decision,
                f"{user} should be granted access after linking",
            )
        # jane was never linked -> denied
        self.assertEqual(
            Decision.Deny,
            is_authorized(self._view("jane"), linked, self.entities).decision,
        )


if __name__ == "__main__":
    unittest.main()
