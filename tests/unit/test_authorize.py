import json
import unittest
import cedarpolicy


class AuthorizeTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        self.policies: dict[str, str] = {
            "bob": """
                permit(
                    principal == User::"bob",
                    action == Action::"view",
                    resource
                )
                ;
                permit(
                    principal, 
                    action == Action::"edit", 
                    resource
                )
                when {
                   resource.owner == principal
                };                
                permit(
                    principal,
                    action == Action::"delete",
                    resource
                )
                when {
                    resource.owner == principal
                    &&
                    context.authentication.usedMFA == true
                }
                ;
                    """.strip()

        }
        self.entities: str = json.dumps(
            [
              {
                "uid": {
                  "__expr": "User::\"bob\""
                },
                "attrs": {},
                "parents": []
              },
              {
                "uid": {
                  "__expr": "Photos::\"bobs-photo-1\""
                },
                "attrs": {
                    "owner": {"__expr": "User::\"bob\""}
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
            "resource": "Photos::\"1234-abcd\"",
            "context": {}
        }
        
        is_authorized: str = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual("ALLOW", is_authorized)

    def test_authorize_basic_DENY(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"delete\"",
            "resource": "Photos::\"1234-abcd\"",
            "context": {}
        }

        is_authorized: str = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual("DENY", is_authorized)

    def test_authorize_basic_perf(self):
        import timeit
        
        num_exec = 100

        timer = timeit.timeit(lambda: self.test_authorize_basic_ALLOW(), number=num_exec)
        print(f'ALLOW ({num_exec}): {timer}')
        t_deadline_seconds = 0.100
        self.assertLess(timer.real, t_deadline_seconds)

        timer = timeit.timeit(lambda: self.test_authorize_basic_DENY(), number=num_exec)
        print(f'DENY ({num_exec}): {timer}')
        self.assertLess(timer.real, t_deadline_seconds)

    def test_authorize_edit_own_photo(self):
        request = {
            "principal": "User::\"bob\"",
            "action": "Action::\"edit\"",
            "resource": "Photos::\"bobs-photo-1\"",
            "context": {}
        }

        is_authorized: str = cedarpolicy.is_authorized(request, self.policies["bob"], self.entities)
        self.assertEqual("ALLOW", is_authorized)
