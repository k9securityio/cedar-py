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
    authz_response = _cedarpolicy.is_authorized(request, policies, entities, schema, verbose)
    return json.loads(authz_response)