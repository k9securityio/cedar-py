import json
import random
import unittest
from datetime import timedelta
from typing import List, Union

from cedarpy import is_authorized, AuthzResult, Decision, is_authorized_batch

from unit import load_file_as_str, utc_now


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
                "uid": {
                    "__expr": "User::\"alice\""
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "__expr": "User::\"bob\""
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "__expr": "Photo::\"bobs-photo-1\""
                },
                "attrs": {
                    "account": {"__expr": "User::\"bob\""}
                },
                "parents": []
            },
            {
                "uid": {
                    "__expr": "Action::\"view\""
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "__expr": "Action::\"edit\""
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "__expr": "Action::\"delete\""
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
            "principal": f"User::\"{username}\"",
            "action": f"Action::\"{action}\"",
            "resource": f"Photo::\"{photo_resource}\"",
            "context": context
        }
        return request

    def assert_authz_responses_equal(self,
                                     expect_authz_result: Union[AuthzResult, dict],
                                     actual_authz_result: AuthzResult,
                                     ignore_metric_values=False,
                                     msg: str = None):
        """Assert an AuthzResult matches an expected spec
        :param ignore_metric_values:
        """

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
                'errors': ['while evaluating policy policy2, encountered the '
                           'following error: record does not have the '
                           'required attribute: authenticated'],
                'reason': []
            }
        })
        actual_authz_result: AuthzResult = is_authorized(request, self.policies["bob"], self.entities)
        self.assert_authz_responses_equal(expect_authz_result, actual_authz_result)

    def test_authorize_basic_shape_of_response(self):
        for _ in range(1, 30):
            actual_authz_result: AuthzResult = is_authorized(self.make_request(),
                                                             self.policies["bob"],
                                                             self.entities)
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

    def test_authorized_batch_perf(self):
        policies = self.policies["alice"]
        entities = load_file_as_str("resources/sandbox_b/entities.json")
        schema = load_file_as_str("resources/sandbox_b/schema.json")

        requests = []
        expect_authz_results: List[AuthzResult] = []

        t_single_start = utc_now()
        actions = [
            'Action::"view"',
            'Action::"edit"',
            'Action::"comment"',
            'Action::"delete"',
            'Action::"listAlbums"',
            'Action::"listPhotos"',
            # 'Action::"addPhoto"',
        ]
        
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

        t_single_elapsed: timedelta = utc_now() - t_single_start

        t_batch_start = utc_now()
        actual_authz_results = is_authorized_batch(requests, policies, entities, schema)
        self.assertIsNotNone(actual_authz_results)
        self.assertEqual(len(expect_authz_results), len(actual_authz_results))

        t_batch_elapsed: timedelta = utc_now() - t_batch_start

        print(f'num_requests: {len(requests)}')
        print(f't_single_elapsed:\t{t_single_elapsed.total_seconds()}')
        print(f't_batch_elapsed:\t{t_batch_elapsed.total_seconds()}')

        self.assertLessEqual(t_batch_elapsed, t_single_elapsed)

        # verify batch results match single authz
        for expect_authz_result, actual_authz_result in zip(expect_authz_results, actual_authz_results):
            print(f'actual_authz_result.metrics: {actual_authz_result. metrics}')
            self.assert_authz_responses_equal(expect_authz_result, actual_authz_result,
                                              ignore_metric_values=True)

