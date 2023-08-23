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

    authz_response = _internal.is_authorized(request, policies, entities, schema, verbose)
    return AuthzResult(json.loads(authz_response))


def is_batch_authorized(requests: List[dict],
                        policies: str,
                        entities: Union[str, List[dict]],
                        schema: Union[str, dict, None] = None,
                        verbose: bool = False) -> List[AuthzResult]:
    """Evaluate whether the batch of requests are authorized given the parameters.

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

    batch_authz_response_strs: List[str] = _internal.is_batch_authorized(requests_local, policies, entities, schema, verbose)
    print(f'batch_authz_response_strs: {batch_authz_response_strs}')
    batch_authz_response_objs: List[dict] = []

    for item in batch_authz_response_strs:
        try:
            batch_authz_response_objs.append(json.loads(item))
        except Exception as e:
            pass
        
    batch_authz_responses: List[AuthzResult] = []
    for response_obj in batch_authz_response_objs:
        print(f'response_obj: {response_obj}')
        batch_authz_responses.append(AuthzResult(response_obj))

    return batch_authz_responses


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
