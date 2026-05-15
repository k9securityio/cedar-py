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

    @property
    def id_annotations_by_reason(self) -> dict:
        """Map from each parser-generated policy id in ``reasons`` to the
        literal value of its ``@id`` annotation, when the matched policy
        declares one. ``@id("foo")`` contributes ``"foo"``; ``@id("")`` /
        bare ``@id`` (which the Cedar docs define as equivalent to
        ``@id("")``) contributes ``""``. Policies with no ``@id`` annotation
        are omitted from the map.
        """
        return self._diagnostics.get('id_annotations_by_reason', dict())


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
    def correlation_id(self) -> Decision:
        return self._authz_resp.get('correlation_id', None)

    @property
    def diagnostics(self) -> Diagnostics:
        return self._diagnostics

    @property
    def metrics(self) -> dict:
        return self._authz_resp.get('metrics', {})

    def __getitem__(self, __name: str) -> Any:
        return getattr(self, __name)


class ValidationError:
    """Represents a single validation error found when validating policies against a schema."""

    def __init__(self, error_dict: dict) -> None:
        self._error = error_dict

    @property
    def policy_id(self) -> str:
        """The policy ID where the error occurred (may be empty for parse errors)."""
        return self._error.get('policy_id', '')

    @property
    def error(self) -> str:
        """Human-readable error message."""
        return self._error.get('error', '')

    def __str__(self) -> str:
        if self.policy_id:
            return f"[{self.policy_id}] {self.error}"
        return self.error

    def __repr__(self) -> str:
        return f"ValidationError(policy_id={self.policy_id!r}, error={self.error!r})"


class ValidationResult:
    """Result of validating Cedar policies against a schema."""

    def __init__(self, result_dict: dict) -> None:
        self._result = result_dict
        self._errors = [ValidationError(e) for e in result_dict.get('errors', [])]

    @property
    def validation_passed(self) -> bool:
        """True if all policies passed validation."""
        return self._result.get('validation_passed', False)

    @property
    def errors(self) -> List['ValidationError']:
        """List of validation errors (empty if validation passed)."""
        return self._errors

    @property
    def id_annotations_by_policy_id(self) -> dict:
        """Map from each parser-generated policy id appearing in ``errors``
        to the literal value of its ``@id`` annotation, when the source
        policy declares one. ``@id("foo")`` contributes ``"foo"``;
        ``@id("")`` / bare ``@id`` (which the Cedar docs define as equivalent
        to ``@id("")``) contributes ``""``. Policies with no ``@id``
        annotation are omitted from the map.
        """
        return self._result.get('id_annotations_by_policy_id', dict())

    def __bool__(self) -> bool:
        """Allows `if validation_result:` syntax."""
        return self.validation_passed

    def __repr__(self) -> str:
        return f"ValidationResult(validation_passed={self.validation_passed}, num_errors={len(self._errors)})"


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


def policies_to_json_str(policies: str) -> str:
    """Convert a cedar policy file to a json cedar policy file.

    :param policies is a str containing the policies to be converted

    :returns the json formatted policy
    :raises ValueError: if the input policies cannot be parsed
    """
    return _internal.policies_to_json_str(policies)

def policies_from_json_str(policies: str) -> str:
    """Convert a json cedar policy file to a cedar policy file.

    :param policies is a str containing the policies to be converted

    :returns the cedar formatted policy
    :raises ValueError: if the input policies cannot be parsed
    """
    return _internal.policies_from_json_str(policies)


class ShadowedFinding:
    """A finding where one policy is shadowed or overridden by another."""

    def __init__(self, finding_dict: dict) -> None:
        self._finding = finding_dict

    @property
    def policy_id(self) -> str:
        """The policy that is shadowed/overridden."""
        return self._finding.get('policy_id', '')

    @property
    def by_policy_id(self) -> str:
        """The policy that does the shadowing/overriding."""
        return self._finding.get('by_policy_id', '')

    def __repr__(self) -> str:
        return f"ShadowedFinding(policy_id={self.policy_id!r}, by_policy_id={self.by_policy_id!r})"


class RequestTypeFindings:
    """Analysis findings for a specific request type (action) in the schema."""

    def __init__(self, findings_dict: dict) -> None:
        self._findings = findings_dict

    @property
    def action(self) -> str:
        """The action this analysis applies to."""
        return self._findings.get('action', '')

    @property
    def redundant_groups(self) -> List[List[str]]:
        """Groups of policies that are equivalent to each other."""
        return self._findings.get('redundant_groups', [])

    @property
    def permit_shadowed_by_permit(self) -> List['ShadowedFinding']:
        """Permit policies fully covered by another permit policy."""
        return [ShadowedFinding(f) for f in self._findings.get('permit_shadowed_by_permit', [])]

    @property
    def permit_overridden_by_forbid(self) -> List['ShadowedFinding']:
        """Permit policies fully overridden by a forbid policy."""
        return [ShadowedFinding(f) for f in self._findings.get('permit_overridden_by_forbid', [])]

    @property
    def forbid_shadowed_by_forbid(self) -> List['ShadowedFinding']:
        """Forbid policies fully covered by another forbid policy."""
        return [ShadowedFinding(f) for f in self._findings.get('forbid_shadowed_by_forbid', [])]

    def __repr__(self) -> str:
        return f"RequestTypeFindings(action={self.action!r})"


class PolicyFinding:
    """Per-policy vacuousness and error findings."""

    def __init__(self, finding_dict: dict) -> None:
        self._finding = finding_dict

    @property
    def policy_id(self) -> str:
        return self._finding.get('policy_id', '')

    @property
    def effect(self) -> str:
        """'permit' or 'forbid'."""
        return self._finding.get('effect', '')

    @property
    def vacuous_never_matches(self) -> bool:
        """True if this policy can never match any request."""
        return self._finding.get('vacuous_never_matches', False)

    @property
    def vacuous_always_matches(self) -> bool:
        """True if this policy matches all requests."""
        return self._finding.get('vacuous_always_matches', False)

    @property
    def never_errors(self) -> bool:
        """True if this policy never produces evaluation errors."""
        return self._finding.get('never_errors', False)

    def __repr__(self) -> str:
        return f"PolicyFinding(policy_id={self.policy_id!r}, effect={self.effect!r}, vacuous_never_matches={self.vacuous_never_matches}, vacuous_always_matches={self.vacuous_always_matches})"


class VacuousPolicy:
    """A policy that is vacuous (matches all or no requests)."""

    def __init__(self, result_dict: dict) -> None:
        self._result = result_dict

    @property
    def policy_id(self) -> str:
        return self._result.get('policy_id', '')

    @property
    def effect(self) -> str:
        """'permit' or 'forbid'."""
        return self._result.get('effect', '')

    @property
    def vacuity(self) -> str:
        """'matches_all' or 'matches_none'."""
        return self._result.get('vacuity', '')

    def __repr__(self) -> str:
        return f"VacuousPolicy(policy_id={self.policy_id!r}, effect={self.effect!r}, vacuity={self.vacuity!r})"


class AnalysisResult:
    """Result of analyzing a Cedar policy set for logical issues.

    Matches the findings from cedar-lean-cli's ``analyze policies`` command:
    policyset vacuity, vacuous policies, redundant groups, permit-shadowed-by-permit,
    permit-overridden-by-forbid, forbid-shadowed-by-forbid.
    """

    def __init__(self, result_dict: dict) -> None:
        self._result = result_dict
        self._per_request_type_findings = [RequestTypeFindings(f) for f in result_dict.get('per_request_type_findings', [])]
        self._vacuous_policies = [VacuousPolicy(p) for p in result_dict.get('vacuous_policies', [])]

    @property
    def policyset_vacuity(self) -> str:
        """Policyset-level vacuity: 'matches_all', 'matches_some', or 'matches_none'."""
        return self._result.get('policyset_vacuity', 'matches_some')

    @property
    def vacuous_policies(self) -> List['VacuousPolicy']:
        """Policies that are vacuous (only non-matches_some included)."""
        return self._vacuous_policies

    @property
    def per_request_type_findings(self) -> List['RequestTypeFindings']:
        """Findings per request type (action): redundancy, shadowing, overriding. Only includes request types with findings."""
        return self._per_request_type_findings

    def __repr__(self) -> str:
        return f"AnalysisResult(policyset_vacuity={self.policyset_vacuity!r}, vacuous_policies={len(self._vacuous_policies)}, per_request_type_findings={len(self._per_request_type_findings)})"


class RequestTypeComparison:
    """Comparison result for a specific request type (action)."""

    def __init__(self, comparison_dict: dict) -> None:
        self._comparison = comparison_dict

    @property
    def action(self) -> str:
        """The action this comparison applies to."""
        return self._comparison.get('action', '')

    @property
    def result(self) -> str:
        """One of: 'equivalent', 'less_permissive', 'more_permissive', 'incomparable'."""
        return self._comparison.get('result', '')

    @property
    def more_permissive_example(self) -> Union[str, None]:
        """Counterexample where pset1 allows but pset2 denies."""
        return self._comparison.get('more_permissive_example')

    @property
    def less_permissive_example(self) -> Union[str, None]:
        """Counterexample where pset1 denies but pset2 allows."""
        return self._comparison.get('less_permissive_example')

    def __repr__(self) -> str:
        return f"RequestTypeComparison(action={self.action!r}, result={self.result!r})"


class CompareResult:
    """Result of comparing two Cedar policy sets, per request type."""

    def __init__(self, result_dict: dict) -> None:
        self._result = result_dict
        self._comparisons = [RequestTypeComparison(c) for c in result_dict.get('request_type_comparisons', [])]

    @property
    def request_type_comparisons(self) -> List['RequestTypeComparison']:
        """Per request type comparison results."""
        return self._comparisons

    @property
    def all_equivalent(self) -> bool:
        """True if all request types are equivalent."""
        return all(c.result == 'equivalent' for c in self._comparisons)

    def __repr__(self) -> str:
        return f"CompareResult(comparisons={len(self._comparisons)}, all_equivalent={self.all_equivalent})"


def analyze_policies(policies: str,
                     schema: Union[str, dict]) -> AnalysisResult:
    """Analyze a Cedar policy set for logical issues.

    Uses the CVC5 SMT solver to check for shadowed permits, impossible conditions,
    and whether the policy set always allows or always denies all requests.

    :param policies: Cedar policies as a string
    :param schema: Cedar schema (JSON dict, JSON string, or Cedar schema string)

    :returns: AnalysisResult with always_allows, always_denies, and per-policy diagnostics
    :raises RuntimeError: if CVC5 is not installed or analysis fails
    :raises ValueError: if policies or schema cannot be parsed
    """
    if isinstance(schema, dict):
        schema = json.dumps(schema)

    result_str = _internal.analyze_policies(policies, schema)
    result_dict = json.loads(result_str)
    return AnalysisResult(result_dict)


def compare_policy_sets(baseline_policies: str,
                        new_policies: str,
                        schema: Union[str, dict]) -> CompareResult:
    """Compare two Cedar policy sets and determine if they are equivalent.

    Uses the CVC5 SMT solver to check whether the two policy sets produce
    identical authorization decisions for all possible requests. If they differ,
    returns a concrete counterexample request.

    :param baseline_policies: the current/old Cedar policies as a string
    :param new_policies: the proposed/new Cedar policies as a string
    :param schema: Cedar schema (JSON dict, JSON string, or Cedar schema string)

    :returns: CompareResult with equivalent boolean and optional counterexample
    :raises RuntimeError: if CVC5 is not installed or analysis fails
    :raises ValueError: if policies or schema cannot be parsed
    """
    if isinstance(schema, dict):
        schema = json.dumps(schema)

    result_str = _internal.compare_policy_sets(baseline_policies, new_policies, schema)
    result_dict = json.loads(result_str)
    return CompareResult(result_dict)


def validate_policies(policies: str,
                      schema: Union[str, dict]) -> ValidationResult:
    """Validate Cedar policies against a schema.

    This function checks that policies are valid according to the provided schema,
    including entity type checking, action validation, and type checking of
    expressions in policy conditions.

    :param policies: Cedar policies as a string
    :param schema: Cedar schema (JSON dict, JSON string, or Cedar schema string)

    :returns: ValidationResult with validation_passed boolean and list of errors

    Example:
        >>> result = validate_policies(policies, schema)
        >>> if result.validation_passed:
        ...     print("Policies are valid!")
        ... else:
        ...     for error in result.errors:
        ...         print(f"Error: {error}")
    """
    if isinstance(schema, dict):
        schema = json.dumps(schema)

    result_str = _internal.validate_policies(policies, schema)
    result_dict = json.loads(result_str)
    return ValidationResult(result_dict)
