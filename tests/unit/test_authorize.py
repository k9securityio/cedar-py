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
                    """.strip()

        }
        self.entities: str = """
        [
          {
            "uid": {
              "__expr": "User::\\"bob\\""
            },
            "attrs": {},
            "parents": []
          },
          {
            "uid": {
              "__expr": "Action::\\"view\\""
            },
            "attrs": {},
            "parents": []
          }
        ]        
                """.strip()

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
