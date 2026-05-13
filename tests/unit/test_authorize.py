import json
import random
import string
import unittest
from datetime import timedelta
from typing import List, Union

from cedarpy import is_authorized, AuthzResult, Decision, is_authorized_batch

from unit import load_file_as_str, utc_now


def randomstr(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class AuthorizeTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        common_policies = """
                permit(
                    principal, 
                    action == Action::"edit", 
                    resource
                )
                when {
                   resource.account == principal
                };                
                permit(
                    principal,
                    action == Action::"delete",
                    resource
                )
                when {
                    context.authenticated == true
                    &&
                    resource has account && principal == resource.account.owner
                }
                ;

        """.strip()
        self.policies: dict[str, str] = {
            "common": common_policies,
            "alice": f"""
                permit(
                    principal == User::"alice",
                    action == Action::"view",
                    resource
                )
                ;
                {common_policies}""".strip(),
            "bob": f"""
                permit(
                    principal == User::"bob",
                    action == Action::"view",
                    resource
                )
                ;
                {common_policies}""".strip(),

        }
        self.entities: List[dict] = [
            {
                "uid" : {
                    "type" : "User",
                    "id" : "alice"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "type" : "User",
                    "id" : "bob"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "type" : "Photo",
                    "id" : "bobs-photo-1"
                },
                "attrs": {
                    "account": {"__entity": { "type" : "User", "id" : "bob"} }
                },
                "parents": []
            },
            {
                "uid": {
                    "type" : "Action",
                    "id" : "view"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "type" : "Action",
                    "id" : "edit"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "type" : "Action",
                    "id" : "delete"
                },
                "attrs": {},
                "parents": []
            }
        ]

        self.request_bob_view_own_photo = {
            "principal": "User::\"bob\"",
            "action": "Action::\"view\"",
            "resource": "Photo::\"1234-abcd\"",
            "context": {}
        }

    # noinspection PyMethodMayBeStatic
    def make_request(self):
        """Make a valid Cedar request"""
        username = random.choice(["alice", "bob", "does-not-exist"])
        action = random.choice(["view", "edit", "delete", "does-not-exist"])
        photo_resource = random.choice(["1234-abcd", "prototype_v0.jpg", "does-not-exist"])
        context = random.choice([None,
                                 {},
                                 '{}',
                                 {'key': 'value'},
                                 {'authenticated': True},
                                 ])
        request = {
            "principal": f'User::"{username}"',
            "action": f'Action::"{action}"',
            "resource": f'Photo::"{photo_resource}"',
            "context": context
        }

        if random.choice([True, False]):
            request["correlation_id"] = randomstr()

        return request

    def assert_authz_responses_equal(self,
                                     expect_authz_result: Union[AuthzResult, dict],
                                     actual_authz_result: AuthzResult,
                                     ignore_metric_values=False,
                                     msg: str = None):
        """Assert an AuthzResult matches an expected spec"""

        if isinstance(expect_authz_result, dict):
            expect_authz_result = AuthzResult(expect_authz_result)

        self.assertEqual(expect_authz_result.decision,
                         actual_authz_result.decision,
                         msg=msg)
        self.assertEqual(expect_authz_result.diagnostics.errors,
                         actual_authz_result.diagnostics.errors,
                         msg=msg)
        self.assertEqual(expect_authz_result.diagnostics.reasons,
                         actual_authz_result.diagnostics.reasons,
                         msg=msg)

        if expect_authz_result.metrics:
            # only assert equality of metrics if caller has included them.
            # in general, we can't check metrics because they rely on runtime / execution information
            if ignore_metric_values:
                self.assertIsNotNone(actual_authz_result.metrics)
            else:
                self.assertEqual(expect_authz_result['metrics'], actual_authz_result['metrics'])

    def test_authorize_basic_ALLOW(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"view\"",
            "resource": "Photo::\"1234-abcd\"",
            "context": {}
        }

        expect_authz_result = AuthzResult({
            "decision": "Allow",
            "diagnostics": {
                "reason": ["policy0"],
                "errors": []
            }
            # omit metrics
        })
        actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_authorize_basic_DENY(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"delete\"",
            "resource": "Photo::\"1234-abcd\"",
            "context": {}
        }

        expect_authz_result = AuthzResult({
            'decision': 'Deny',
            'diagnostics': {
                'errors': ['error while evaluating policy `policy2`: record does not have the '
                           'attribute `authenticated`'],
                'reason': []
            }
        })
        actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_authorize_basic_shape_of_response(self):
        for _ in range(1, 30):
            request = self.make_request()
            actual_authz_result: AuthzResult = is_authorized(request,
                                                             self.policies["bob"],
                                                             self.entities)
            self.assertEqual(request.get("correlation_id", None),
                             actual_authz_result.correlation_id)
            self.assertIsNotNone('decision', actual_authz_result.decision)

            self.assertIsNotNone('diagnostics', actual_authz_result)
            diagnostics = actual_authz_result['diagnostics']
            self.assertIsNotNone(diagnostics.errors)
            self.assertIsNotNone(diagnostics.reasons)

            self.assertIsNotNone('metrics', actual_authz_result)

            metrics = actual_authz_result['metrics']
            for metric_name in [
                'parse_policies_duration_micros',
                'parse_schema_duration_micros',
                'load_entities_duration_micros',
                'build_request_duration_micros',
                'authz_duration_micros',
            ]:
                self.assertIn(metric_name, metrics)
                if 'duration' in metric_name:
                    self.assertGreaterEqual(metrics[metric_name], 0)

    def test_authorize_basic_perf(self):
        import timeit

        num_exec = 100

        timer = timeit.timeit(lambda: self.test_authorize_basic_ALLOW(), number=num_exec)
        print(f'ALLOW ({num_exec}): {timer}')
        t_deadline_seconds = 0.500  # need ~290ms for aarch64 in GH Actions (because qemu?)
        self.assertLess(timer.real, t_deadline_seconds)

        timer = timeit.timeit(lambda: self.test_authorize_basic_DENY(), number=num_exec)
        print(f'DENY ({num_exec}): {timer}')
        self.assertLess(timer.real, t_deadline_seconds)

    def test_context_may_be_a_json_str_or_dict(self):
        for expect_context in [{}, {"key": "value"},
                               '{}', '{"key":"value"}']:
            request = {
                "principal": "User::\"bob\"",
                "action": "Action::\"view\"",
                "resource": "Photo::\"1234-abcd\"",
                "context": expect_context
            }
            expect_authz_result = AuthzResult({
                "decision": "Allow",
                "diagnostics": {
                    "reason": ["policy0"],
                    "errors": []
                }
            })
            actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
            self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_entities_may_be_a_json_str_or_list(self):
        for entities in [self.entities,
                         json.dumps(self.entities)]:
            actual_authz_result: AuthzResult = is_authorized(self.request_bob_view_own_photo,
                                                             self.policies["bob"],
                                                             entities)
            self.assertEqual(Decision.Allow, actual_authz_result["decision"])

    def test_schema_may_be_none_or_json_str_or_dict(self):
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema_src = load_file_as_str("resources/sandbox_b/schema.json")
        for schema in [
            None,
            schema_src,
            json.loads(schema_src)
        ]:
            request = {
                "principal": "User::\"alice\"",
                "action": "Action::\"delete\"",
                "resource": "Photo::\"alice_w2.jpg\"",
                "context": json.dumps({
                    "authenticated": False
                })
            }

            actual_authz_result: AuthzResult = is_authorized(request, policies, entities,
                                                             schema=schema)
            self.assertEqual(Decision.Deny, actual_authz_result.decision)
            self.assertEqual([], actual_authz_result.diagnostics.errors)

    def test_context_is_optional_in_authorize_request(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"edit\"",
            "resource": "Photo::\"bobs-photo-1\""
        }

        expect_authz_result: AuthzResult = AuthzResult({"decision": "Allow",
                                                        "diagnostics": {"reason": ["policy1"], "errors": []}})

        actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result,
                                          msg="expected omitted context to be allowed")

        # noinspection PyTypedDict
        request["context"] = None
        actual_authz_result = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result,
                                          msg="expected context with value None to be allowed")

        request["context"] = {}
        actual_authz_result = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result,
                                          msg="expected empty context to be allowed")

    def test_authorized_to_edit_own_photo_ALLOW(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"edit\"",
            "resource": "Photo::\"bobs-photo-1\"",
            "context": {}
        }

        expect_authz_result: AuthzResult = AuthzResult({"decision": "Allow",
                                                        "diagnostics": {"reason": ["policy1"], "errors": []}})
        actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_not_authorized_to_edit_other_users_photo(self):
        request = {
            "principal": "User::\"alice\"",
            "action": "Action::\"edit\"",
            "resource": "Photo::\"bobs-photo-1\"",
            "context": {}
        }

        expect_authz_result: AuthzResult = AuthzResult({"decision": "Deny", "diagnostics": {"reason": [], "errors": []}})
        actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_authorized_to_delete_own_photo_when_authenticated_in_context(self):
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema = load_file_as_str("resources/sandbox_b/schema.json")

        request = {
            "principal": "User::\"alice\"",
            "action": "Action::\"delete\"",
            "resource": "Photo::\"alice_w2.jpg\"",
            "context": json.dumps({
                "authenticated": False
            })
        }

        expect_authz_result: AuthzResult = AuthzResult({"decision": "Deny", "diagnostics": {"reason": [], "errors": []}})
        actual_authz_result: AuthzResult = is_authorized(request, policies, entities,
                                                         schema=schema)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

        request["context"] = json.dumps({
            "authenticated": True
        })

        expect_authz_result = AuthzResult({"decision": "Allow", "diagnostics": {"reason": ["policy2"], "errors": []}})
        actual_authz_result = is_authorized(request, policies, entities,
                                            schema=schema)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_authorized_batch_evaluates_authorization_and_returns_in_order(self):
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema = load_file_as_str("resources/sandbox_b/schema.json")

        requests = []
        expect_authz_results: List[AuthzResult] = []

        actions = [
            'Action::"view"',
            'Action::"edit"',
            'Action::"comment"',
            'Action::"delete"',
            'Action::"listAlbums"',
            'Action::"listPhotos"',
            # 'Action::"addPhoto"',
        ]

        random.shuffle(actions)

        for action in actions:
            request = {
                "principal": 'User::"alice"',
                "action": action,
                "resource": 'Photo::"alice_w2.jpg"',
                "context": json.dumps({
                    "authenticated": False
                })
            }
            requests.append(request)
            expect_authz_result: AuthzResult = is_authorized(request, policies, entities, schema=schema)
            expect_authz_results.append(expect_authz_result)

        actual_authz_results = is_authorized_batch(requests, policies, entities, schema)
        self.assertIsNotNone(actual_authz_results)
        self.assertEqual(len(expect_authz_results), len(actual_authz_results))

        # verify batch results matches single authz
        for expect_authz_result, actual_authz_result in zip(expect_authz_results, actual_authz_results):
            self.assert_authz_responses_equal(expect_authz_result, actual_authz_result,
                                              ignore_metric_values=True)

    def test_is_authorized_with_a_request_that_errors(self):
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema = load_file_as_str("resources/sandbox_b/schema.json")

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"addPhoto"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": json.dumps({
                "authenticated": False
            })
        }

        authz_result: AuthzResult = is_authorized(request, policies, entities, schema=schema)
        self.assertEqual(Decision.NoDecision, authz_result.decision)
        self.assertEqual(["failed to parse schema from request"],
                         authz_result.diagnostics.errors)


    def test_is_authorized_with_policies_that_errors(self):
        policies = "this is not a real policy"
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema = load_file_as_str("resources/sandbox_b/schema.json")

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": json.dumps({
                "authenticated": False
            })
        }

        authz_result: AuthzResult = is_authorized(request, policies, entities, schema=schema)
        self.assertEqual(Decision.NoDecision, authz_result.decision)
        self.assertEqual(1, len(authz_result.diagnostics.errors))
        self.assertIn('policy parse errors:\nunexpected token `is`', authz_result.diagnostics.errors[0])

    def test_is_authorized_with_invalid_cedar_schema_returns_no_decision(self):
        # Regression for https://github.com/k9securityio/cedar-py/issues/27
        # Invalid (non-empty) schemas previously returned a real decision while
        # silently dropping the schema. Now they must surface as NoDecision +
        # a diagnostic error.
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        invalid_schema = "this is definitely not a cedar schema"

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": json.dumps({"authenticated": False}),
        }

        authz_result: AuthzResult = is_authorized(request, policies, entities, schema=invalid_schema)
        self.assertEqual(Decision.NoDecision, authz_result.decision)
        self.assertEqual(1, len(authz_result.diagnostics.errors))
        self.assertIn("schema", authz_result.diagnostics.errors[0].lower())

    def test_is_authorized_with_invalid_json_schema_returns_no_decision(self):
        # Regression for https://github.com/k9securityio/cedar-py/issues/27
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        invalid_json_schema = '{"not a valid": "cedar json schema"}'

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": json.dumps({"authenticated": False}),
        }

        authz_result: AuthzResult = is_authorized(request, policies, entities, schema=invalid_json_schema)
        self.assertEqual(Decision.NoDecision, authz_result.decision)
        self.assertEqual(1, len(authz_result.diagnostics.errors))
        self.assertIn("schema", authz_result.diagnostics.errors[0].lower())

    def test_id_annotation_surfaces_in_id_annotations(self):
        # Feature from https://github.com/k9securityio/cedar-py/issues/29 (item 2),
        # revised per https://github.com/k9securityio/cedar-py/issues/77:
        # AuthzResult.diagnostics.reasons keeps the parser-generated policy id
        # (so duplicate @id values across tenants stay distinguishable), and
        # the human-readable @id value is exposed via id_annotations.
        policies = """
            @id("alice_can_view")
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
        """.strip()

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": {},
        }

        authz_result: AuthzResult = is_authorized(request, policies, self.entities)
        self.assertEqual(Decision.Allow, authz_result.decision)
        self.assertEqual(["policy0"], authz_result.diagnostics.reasons)
        self.assertEqual({"policy0": "alice_can_view"},
                         authz_result.diagnostics.id_annotations)

    def test_id_annotation_mixed_with_unannotated_policies(self):
        # Mix annotated + un-annotated policies. Both surface as parser
        # policy ids in reasons; only the annotated policy appears in
        # id_annotations.
        policies = """
            @id("alice_view")
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
            permit(
                principal == User::"bob",
                action == Action::"view",
                resource
            );
        """.strip()

        alice_request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": {},
        }
        bob_request = {
            "principal": 'User::"bob"',
            "action": 'Action::"view"',
            "resource": 'Photo::"bobs-photo-1"',
            "context": {},
        }

        alice_result: AuthzResult = is_authorized(alice_request, policies, self.entities)
        self.assertEqual(Decision.Allow, alice_result.decision)
        self.assertEqual(["policy0"], alice_result.diagnostics.reasons)
        self.assertEqual({"policy0": "alice_view"},
                         alice_result.diagnostics.id_annotations)

        bob_result: AuthzResult = is_authorized(bob_request, policies, self.entities)
        self.assertEqual(Decision.Allow, bob_result.decision)
        # un-annotated policy keeps cedar's parser id (some "policyN") and
        # contributes no entry to id_annotations.
        self.assertEqual(["policy1"], bob_result.diagnostics.reasons)
        self.assertEqual({}, bob_result.diagnostics.id_annotations)

    def test_id_annotation_duplicates_are_allowed(self):
        # Cedar treats annotations as inert during evaluation
        # (https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-annotations):
        # "an annotation has no impact on policy evaluation" and "@id is not
        # special in the Cedar language." cedar-py therefore accepts duplicate
        # @id values rather than rejecting them as a configuration error —
        # rejecting would be a cedar-py-specific behavior that diverges from
        # Cedar's documented semantics and from cedar-py 4.8.1 (which silently
        # ignored @id annotations entirely).
        policies = """
            @id("dup")
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
            @id("dup")
            permit(
                principal == User::"bob",
                action == Action::"view",
                resource
            );
        """.strip()

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": {},
        }

        authz_result: AuthzResult = is_authorized(request, policies, self.entities)
        self.assertEqual(Decision.Allow, authz_result.decision)
        self.assertEqual([], authz_result.diagnostics.errors)
        # Only the first policy matched alice's request; reasons carries its
        # unique parser id, and the duplicate @id label is exposed via the
        # annotations map (without collapsing identity).
        self.assertEqual(["policy0"], authz_result.diagnostics.reasons)
        self.assertEqual({"policy0": "dup"},
                         authz_result.diagnostics.id_annotations)

    def test_id_annotation_coexists_with_other_annotations(self):
        # Per the docs, "multiple annotations allowed per policy." Verify
        # @id resolution still works when the policy also carries unrelated
        # annotations like @advice and @shadow_mode. cedar-py doesn't surface
        # the non-@id annotations today; this test asserts they don't
        # interfere with @id labeling.
        policies = """
            @advice("be careful")
            @id("alice_view")
            @shadow_mode
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
        """.strip()

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": {},
        }

        authz_result: AuthzResult = is_authorized(request, policies, self.entities)
        self.assertEqual(Decision.Allow, authz_result.decision)
        self.assertEqual(["policy0"], authz_result.diagnostics.reasons)
        self.assertEqual({"policy0": "alice_view"},
                         authz_result.diagnostics.id_annotations)

    def test_id_annotation_empty_value_is_omitted_from_annotations_map(self):
        # Per the docs: "Values are optional; omitting a value means the
        # annotation implicitly equals "", making @annotationname equivalent
        # to @annotationname("")." Both `@id` and `@id("")` therefore carry an
        # empty annotation value.
        #
        # @id is a labeling convention for identifying policies. An empty
        # display id is unhelpful — callers can't log it or look up against
        # it — so cedar-py omits such policies from id_annotations
        # entirely. reasons still surfaces the parser-generated id.
        for policy_body in [
            # @id with no parentheses — implicitly @id("")
            '@id\npermit(principal == User::"alice", action == Action::"view", resource);',
            # @id with explicit empty string
            '@id("")\npermit(principal == User::"alice", action == Action::"view", resource);',
        ]:
            with self.subTest(policy_body=policy_body):
                request = {
                    "principal": 'User::"alice"',
                    "action": 'Action::"view"',
                    "resource": 'Photo::"alice_w2.jpg"',
                    "context": {},
                }

                authz_result: AuthzResult = is_authorized(request, policy_body, self.entities)
                self.assertEqual(Decision.Allow, authz_result.decision)
                self.assertEqual(["policy0"], authz_result.diagnostics.reasons)
                self.assertEqual({}, authz_result.diagnostics.id_annotations)

    def test_id_annotation_does_not_affect_evaluation(self):
        # Regression guard for the docs property "an annotation has no impact
        # on policy evaluation." Two policies with the SAME @id but DIFFERENT
        # principal == clauses must each still route correctly: alice's
        # request matches the first policy, bob's matches the second, and
        # neither bleeds into the other. Per issue #77, reasons surfaces the
        # parser-generated id so the matched policy is unambiguously
        # identified even though both policies share the same @id label.
        policies = """
            @id("shared")
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
            @id("shared")
            permit(
                principal == User::"bob",
                action == Action::"view",
                resource
            );
        """.strip()

        alice_request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": {},
        }
        bob_request = {
            "principal": 'User::"bob"',
            "action": 'Action::"view"',
            "resource": 'Photo::"bobs-photo-1"',
            "context": {},
        }
        carol_request = {
            "principal": 'User::"carol"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": {},
        }

        alice_result: AuthzResult = is_authorized(alice_request, policies, self.entities)
        self.assertEqual(Decision.Allow, alice_result.decision)
        self.assertEqual(["policy0"], alice_result.diagnostics.reasons)
        self.assertEqual({"policy0": "shared"},
                         alice_result.diagnostics.id_annotations)

        bob_result: AuthzResult = is_authorized(bob_request, policies, self.entities)
        self.assertEqual(Decision.Allow, bob_result.decision)
        self.assertEqual(["policy1"], bob_result.diagnostics.reasons)
        self.assertEqual({"policy1": "shared"},
                         bob_result.diagnostics.id_annotations)

        # carol is named in neither policy: no policy matches, decision Deny.
        carol_result: AuthzResult = is_authorized(carol_request, policies, self.entities)
        self.assertEqual(Decision.Deny, carol_result.decision)
        self.assertEqual([], carol_result.diagnostics.reasons)
        self.assertEqual({}, carol_result.diagnostics.id_annotations)

    def test_issue_77_multi_tenant_baseline_permit_disambiguates(self):
        # Regression test for https://github.com/k9securityio/cedar-py/issues/77.
        #
        # Multi-tenant scenario: each tenant authors their own copy of a
        # templated @id("baseline-permit-all") permit, scoped to a
        # tenant-owned resource. In 4.8.1 reasons returned the parser id
        # (e.g., "policy0") and the caller could map back to which tenant's
        # policy fired. In 4.8.2 reasons returned the @id value
        # ("baseline-permit-all"), which is identical across tenants and
        # collapses tenant identity. This test asserts the post-77 contract:
        # reasons returns the parser id, and the @id label is recoverable
        # via diagnostics.id_annotations.
        policies = """
            @id("baseline-permit-all")
            permit(principal, action, resource in App::"app-A");

            @id("baseline-permit-all")
            permit(principal, action, resource in App::"app-B");
        """.strip()

        app_a_request = {
            "principal": 'User::"alice"',
            "action": 'Action::"read"',
            "resource": 'App::"app-A"',
            "context": {},
        }
        app_b_request = {
            "principal": 'User::"alice"',
            "action": 'Action::"read"',
            "resource": 'App::"app-B"',
            "context": {},
        }

        app_a_result: AuthzResult = is_authorized(app_a_request, policies, self.entities)
        self.assertEqual(Decision.Allow, app_a_result.decision)
        self.assertEqual(["policy0"], app_a_result.diagnostics.reasons)
        self.assertEqual({"policy0": "baseline-permit-all"},
                         app_a_result.diagnostics.id_annotations)

        app_b_result: AuthzResult = is_authorized(app_b_request, policies, self.entities)
        self.assertEqual(Decision.Allow, app_b_result.decision)
        self.assertEqual(["policy1"], app_b_result.diagnostics.reasons)
        self.assertEqual({"policy1": "baseline-permit-all"},
                         app_b_result.diagnostics.id_annotations)

        # The two diagnostic identities are distinct, which is the property
        # issue #77 needs preserved.
        self.assertNotEqual(app_a_result.diagnostics.reasons,
                            app_b_result.diagnostics.reasons)

    def test_authorized_batch_perf(self):
        import platform

        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema = load_file_as_str("resources/sandbox_b/schema.json")

        requests = []
        expect_authz_results: List[AuthzResult] = []

        t_single_start = utc_now()
        photo_actions = [
            'Action::"view"',
            'Action::"edit"',
            'Action::"comment"',
            'Action::"delete"',
        ]
        photo_resources = [
            # defined in entities
            "alice_w2.jpg",
            "vacation.jpg",
            "sales_projections.jpg",
            "prototype_v0.jpg",
        ]
        for action in photo_actions:
            for resource in photo_resources:
                request = {
                    "principal": 'User::"alice"',
                    "action": action,
                    "resource": f'Photo::"{resource}"',
                    "context": json.dumps({
                        "authenticated": False
                    })
                }
                requests.append(request)
                expect_authz_result: AuthzResult = is_authorized(request, policies, entities, schema=schema)
                expect_authz_results.append(expect_authz_result)

        t_single_elapsed: timedelta = utc_now() - t_single_start

        t_batch_start = utc_now()
        actual_authz_results = is_authorized_batch(requests, policies, entities, schema)
        self.assertIsNotNone(actual_authz_results)
        self.assertEqual(len(expect_authz_results), len(actual_authz_results))

        t_batch_elapsed: timedelta = utc_now() - t_batch_start

        num_requests = len(requests)
        print(f'num_requests: {num_requests}')
        print(f't_single_elapsed:\t{t_single_elapsed.total_seconds()}')
        print(f't_batch_elapsed:\t{t_batch_elapsed.total_seconds()}')

        self.assertGreaterEqual(num_requests, 5,
                                msg=f"should eval batch perf with at least 5 requests")

        # Windows shows lower performance for batch req since adoption of cedar-policy 4.7 engine, relax requirement
        expected_speedup = 2.0 if platform.system() == 'Windows' else 3.0
        self.assertLessEqual(t_batch_elapsed, (t_single_elapsed / expected_speedup),
                             msg=f"expected batch eval to be +{expected_speedup}x faster; check for perf regression")

        # verify batch results match single authz
        for expect_authz_result, actual_authz_result in zip(expect_authz_results, actual_authz_results):
            print(f'actual_authz_result.metrics: {actual_authz_result. metrics}')
            self.assert_authz_responses_equal(expect_authz_result, actual_authz_result,
                                              ignore_metric_values=True)

    def test_cedar_43_isempty_operator_ALLOW(self):
        """Test Cedar 4.3+ isEmpty() operator allows when set is empty."""
        policies = """
            permit(
                principal,
                action == Action::"access",
                resource
            )
            when {
                principal.tags.isEmpty()
            };
        """

        entities = [
            {"uid": {"type": "User", "id": "alice"}, "attrs": {"tags": []}, "parents": []},
            {"uid": {"type": "Resource", "id": "file1"}, "attrs": {}, "parents": []}
        ]

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"access"',
            "resource": 'Resource::"file1"'
        }

        result = is_authorized(request, policies, entities)
        self.assertEqual(Decision.Allow, result.decision)

    def test_cedar_43_isempty_operator_DENY(self):
        """Test Cedar 4.3+ isEmpty() operator denies when set is not empty."""
        policies = """
            permit(
                principal,
                action == Action::"access",
                resource
            )
            when {
                principal.tags.isEmpty()
            };
        """

        entities = [
            {"uid": {"type": "User", "id": "bob"}, "attrs": {"tags": ["admin", "developer"]}, "parents": []},
            {"uid": {"type": "Resource", "id": "file1"}, "attrs": {}, "parents": []}
        ]

        request = {
            "principal": 'User::"bob"',
            "action": 'Action::"access"',
            "resource": 'Resource::"file1"'
        }

        result = is_authorized(request, policies, entities)
        self.assertEqual(Decision.Deny, result.decision)

    def test_cedar_45_trailing_commas_in_policies(self):
        """Test Cedar 4.5+ support for trailing commas in policy syntax."""
        # Trailing comma after 'resource,' should be accepted
        policies = """
            permit(
                principal == User::"alice",
                action == Action::"read",
                resource,
            )
            when {
                resource.public == true
            };
        """

        entities = [
            {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
            {"uid": {"type": "File", "id": "doc1"}, "attrs": {"public": True}, "parents": []}
        ]

        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"read"',
            "resource": 'File::"doc1"'
        }

        result = is_authorized(request, policies, entities)
        self.assertEqual(Decision.Allow, result.decision)

