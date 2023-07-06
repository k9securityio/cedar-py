import json
from copy import copy
from enum import Enum
from typing import Union, List, Any

from cedarpolicy import _cedarpolicy


def echo(s: str) -> str:
    return _cedarpolicy.echo(s)


def is_authorized(request: dict,
                  policies: str,
                  entities: Union[str, List[dict]],
                  schema: Union[str, dict, None] = None,
                  verbose: bool = False) -> dict:
    """Evaluate whether the request is authorized given the parameters.

    :param request is a Cedar-style request object containing a principal, action, resource, and (optional) context;
    context may be a dict (preferred) or a string
    :param policies is a str containing all the policies in the Cedar PolicySet
    :param entities a list of entities or a json-formatted string containing the list of entities to
    include in the evaluation
    :param schema (optional) dictionary or json-formatted string containing the Cedar schema
    :param verbose (optional) boolean determining whether to enable verbose logging output within the library

    :returns a dictionary containing the decision and diagnostic details, e.g.:
    {
        "decision": "Allow|Deny",
        "diagnostics": {
            "reason": ["policy0"], # the policy that determined the decision
            "errors": []           # any errors
        },
        "metrics": {
            "authz_duration_micros": 42
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

    if isinstance(entities, str):
        pass
    elif isinstance(entities, list):
        entities = json.dumps(entities)

    if schema is not None:
        if isinstance(schema, str):
            pass
        elif isinstance(schema, dict):
            schema = json.dumps(schema)

    authz_response = _cedarpolicy.is_authorized(request, policies, entities, schema, verbose)
    return json.loads(authz_response)


class Decision(Enum):
    Allow = 'Allow'
    Deny = 'Deny'
    NoDecision = 'NoDecision'


class AuthzResult:
    def __init__(self, authz_resp: dict) -> None:
        super().__init__()
        self._authz_resp = authz_resp

    @property
    def decision(self) -> Decision:
        return Decision[self._authz_resp['decision']]

    @property
    def allowed(self) -> bool:
        return Decision.Allow == self.decision

    def __getitem__(self, __name: str) -> Any:
        return getattr(self, __name)
