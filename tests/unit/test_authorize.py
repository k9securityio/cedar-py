import unittest
import cedarpolicy


class AuthorizeTestCase(unittest.TestCase):

    def test_authorize(self):
        request = {"key": "value"}
        policies = """
    permit(
        principal == User::"bob",
        action == Action::"view",
        resource
    )
    ;
        """
        entities = """
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
      "__expr": "Action::\"view\""
    },
    "attrs": {},
    "parents": []
  }
]        
        """
        is_authorized: str = cedarpolicy.is_authorized(request, policies, entities)
        self.assertEqual("DENY", is_authorized)
