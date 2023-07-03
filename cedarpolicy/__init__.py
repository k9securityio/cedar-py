import json
from copy import copy

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

    :param request is a Cedar-style request object containing a principal, action, resource, and (optional) context;
    context may be a dict (preferred) or a string
    :param policies is a str containing all the policies in the Cedar PolicySet
    :param entities a json-formatted string containing the list of entities to include in the evaluation
    :param schema a json-formatted string containing the Cedar schema, required when context is populated
    :param verbose a boolean determining whether to enable verbose logging output within the library

    :returns a dictionary containing the decision and diagnostic details, e.g.:
    {
        "decision": "Allow|Deny",
        "diagnostics": {
            "reason": ["policy0"], # the policy that determined the decision
            "errors": []           # any errors
        }
    }

    """
    if "context" in request:
        context = request["context"]
        if isinstance(context, dict):
            # ok user provided context as a dictionary, lets flatten it for them
            context_json_str = json.dumps(context)
            request = copy(request)
            request["context"] = context_json_str

    authz_response = _cedarpolicy.is_authorized(request, policies, entities, schema, verbose)
    return json.loads(authz_response)
