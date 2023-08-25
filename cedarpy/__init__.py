import json
from copy import copy
from enum import Enum
from typing import Union, List, Any

from cedarpy import _internal


def echo(s: str) -> str:
    return _internal.echo(s)


class Decision(Enum):
    Allow = 'Allow'
    Deny = 'Deny'
    NoDecision = 'NoDecision'


class Diagnostics:

    def __init__(self, diagnostics: dict) -> None:
        super().__init__()
        self._diagnostics: dict = diagnostics

    @property
    def errors(self) -> List[str]:
        return self._diagnostics.get('errors', list())

    @property
    def reasons(self) -> List[str]:
        # (intentionally) map 'reason' key in diagnostics dict to 'reasons' property (plural)
        return self._diagnostics.get('reason', list())


class AuthzResult:
    def __init__(self, authz_resp: dict) -> None:
        super().__init__()
        self._authz_resp = authz_resp
        self._diagnostics = Diagnostics(self._authz_resp.get('diagnostics', {}))

    @property
    def decision(self) -> Decision:
        return Decision[self._authz_resp['decision']]

    @property
    def allowed(self) -> bool:
        return Decision.Allow == self.decision

    @property
    def diagnostics(self) -> Diagnostics:
        return self._diagnostics

    @property
    def metrics(self) -> dict:
        return self._authz_resp.get('metrics', {})

    def __getitem__(self, __name: str) -> Any:
        return getattr(self, __name)


def is_authorized(request: dict,
                  policies: str,
                  entities: Union[str, List[dict]],
                  schema: Union[str, dict, None] = None,
                  verbose: bool = False) -> AuthzResult:
    """Evaluate whether the request is authorized given the parameters.

    :param request is a Cedar-style request object containing a principal, action, resource, and (optional) context;
    context may be a dict (preferred) or a string
    :param policies is a str containing all the policies in the Cedar PolicySet
    :param entities a list of entities or a json-formatted string containing the list of entities to
    include in the evaluation
    :param schema (optional) dictionary or json-formatted string containing the Cedar schema
    :param verbose (optional) boolean determining whether to enable verbose logging output within the library

    :returns an AuthzResult

    """
    return is_authorized_batch(requests=[request],
                               policies=policies,
                               entities=entities,
                               schema=schema,
                               verbose=verbose)[0]


def is_authorized_batch(requests: List[dict],
                        policies: str,
                        entities: Union[str, List[dict]],
                        schema: Union[str, dict, None] = None,
                        verbose: bool = False) -> List[AuthzResult]:
    """Evaluate whether a batch of requests are authorized given the other parameters.  Each request is evaluated
    independently and results in an AuthzResult per request.

    :param requests is list of Cedar-style request objects containing a principal, action, resource, and (optional) context;
    context may be a dict (preferred) or a string
    :param policies is a str containing all the policies in the Cedar PolicySet
    :param entities a list of entities or a json-formatted string containing the list of entities to
    include in the evaluation
    :param schema (optional) dictionary or json-formatted string containing the Cedar schema
    :param verbose (optional) boolean determining whether to enable verbose logging output within the library

    :returns a list of AuthzResults, in same order as the requests

    """
    requests_local = []
    for request in requests:
        if "context" in request:
            context = request["context"]
            if isinstance(context, dict):
                # ok user provided context as a dictionary, lets flatten it for them
                context_json_str = json.dumps(context)
                request = copy(request)
                request["context"] = context_json_str
            elif context is None:
                request = copy(request)
                del request["context"]

        requests_local.append(request)

    if isinstance(entities, str):
        pass
    elif isinstance(entities, list):
        entities = json.dumps(entities)

    if schema is not None:
        if isinstance(schema, str):
            pass
        elif isinstance(schema, dict):
            schema = json.dumps(schema)

    authz_result_strs: List[str] = _internal.is_authorized_batch(requests_local, policies, entities, schema, verbose)
    authz_result_objs: List[dict] = []

    for authz_result_str in authz_result_strs:
        authz_result_objs.append(json.loads(authz_result_str))
        
    authz_results: List[AuthzResult] = []
    for response_obj in authz_result_objs:
        authz_results.append(AuthzResult(response_obj))

    return authz_results


def format_policies(policies: str,
                    line_width: int = 80,
                    indent_width: int = 2) -> str:
    """Format the provided policies according to the Cedar conventions.

    :param policies is a str containing the policies to be formatted
    :param line_width (optional) is the desired maximum line length
    :param indent_width (optional) is the desired indentation width

    :returns the formatted policy
    :raises ValueError: if the input policies cannot be parsed
    """
    return _internal.format_policies(policies, line_width, indent_width)
