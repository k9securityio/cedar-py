import json
import unittest

import cedarpolicy

from unit import load_file_as_str


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
        self.entities: str = json.dumps(
            [
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
        )

    def test_authorize_basic_ALLOW(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"view\"",
            "resource": "Photo::\"1234-abcd\"",
            "context": json.dumps({})
        }

        expect_authz_resp = {
            "decision": "Allow",
            "diagnostics": {
                "reason": ["policy0"],
                "errors": []
            }
        }
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp)

    def test_authorize_basic_DENY(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"delete\"",
            "resource": "Photo::\"1234-abcd\"",
            "context": json.dumps({})
        }

        expect_authz_resp = {
            'decision': 'Deny',
            'diagnostics': {
                'errors': ['while evaluating policy policy2, encountered the '
                           'following error: record does not have the '
                           'required attribute: authenticated'],
                'reason': []
            }
        }
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp)

    def test_authorize_basic_perf(self):
        import timeit

        num_exec = 100

        timer = timeit.timeit(lambda: self.test_authorize_basic_ALLOW(), number=num_exec)
        print(f'ALLOW ({num_exec}): {timer}')
        t_deadline_seconds = 0.250
        self.assertLess(timer.real, t_deadline_seconds)

        timer = timeit.timeit(lambda: self.test_authorize_basic_DENY(), number=num_exec)
        print(f'DENY ({num_exec}): {timer}')
        self.assertLess(timer.real, t_deadline_seconds)

    def test_context_is_optional_in_authorize_request(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"edit\"",
            "resource": "Photo::\"bobs-photo-1\""
        }

        expect_authz_resp: dict = {"decision": "Allow", "diagnostics": {"reason": ["policy1"], "errors": []}}

        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp,
                         "expected omitted context to be allowed")

        # noinspection PyTypedDict
        request["context"] = None
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp,
                         "expected context with value None to be allowed")

        request["context"] = json.dumps({})
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp,
                         "expected empty context to be allowed")

    def test_authorized_to_edit_own_photo_ALLOW(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"edit\"",
            "resource": "Photo::\"bobs-photo-1\"",
            "context": json.dumps({})
        }

        expect_authz_resp: dict = {"decision": "Allow", "diagnostics": {"reason": ["policy1"], "errors": []}}
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp)

    def test_not_authorized_to_edit_other_users_photo(self):
        request = {
            "principal": "User::\"alice\"",
            "action": "Action::\"edit\"",
            "resource": "Photo::\"bobs-photo-1\"",
            "context": json.dumps({})
        }

        expect_authz_resp: dict = {"decision": "Deny", "diagnostics": {"reason": [], "errors": []}}
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual(expect_authz_resp, actual_authz_resp)

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

        expect_authz_resp = {"decision": "Deny", "diagnostics": {"reason": [], "errors": []}}
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, policies, entities,
                                                            schema=schema)
        self.assertEqual(expect_authz_resp, actual_authz_resp)

        request["context"] = json.dumps({
            "authenticated": True
        })

        expect_authz_resp = {"decision": "Allow", "diagnostics": {"reason": ["policy2"], "errors": []}}
        actual_authz_resp: dict = cedarpolicy.is_authorized(request, policies, entities,
                                                            schema=schema)
        self.assertEqual(expect_authz_resp, actual_authz_resp)
