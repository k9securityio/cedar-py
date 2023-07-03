import json

from cedarpolicy import _cedarpolicy


def echo(s: str) -> str:
    return _cedarpolicy.echo(s)


def parse_test_policy() -> str:
    return _cedarpolicy.parse_test_policy()


def is_authorized(request: dict,
                  policies: str,
                  entities: str,
                  schema: str = None,
                  verbose: bool = False) -> dict:
    """Evaluate whether the request is authorized given the parameters.

    :returns a dictionary containing the decision and diagnostic details, e.g.:
    {
        "decision": "Allow|Deny",
        "diagnostics": {
            "reason": ["policy0"], # the policy that determined the decision
            "errors": []           # any errors
        }
    }

    """
    authz_response = _cedarpolicy.is_authorized(request, policies, entities, schema, verbose)
    return json.loads(authz_response)
