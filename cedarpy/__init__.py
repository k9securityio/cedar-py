import json
from copy import copy
from enum import Enum
from typing import Union, List, Optional, Any

from cedarpy import _internal

# Re-export the Rust-implemented PolicySet handle (see help(PolicySet) for usage).
PolicySet = _internal.PolicySet


class Entities:
    """An opaque, reusable handle wrapping a parsed Cedar entity set.

    Parse a stable entity graph once with ``Entities.from_json_str(...)`` and
    pass the handle anywhere an entities string/list is accepted
    (``is_authorized``, ``is_authorized_batch``, ``is_authorized_partial``),
    reusing it across calls to avoid re-parsing (JSON deserialization plus
    transitive-closure computation). For the "stable base plus a per-request
    delta" pattern, ``with_added_json_str(delta)`` parses only the delta and
    returns a NEW handle — the base is immutable and reused.

    The optional ``schema`` (a Cedar schema as a JSON/Cedar string, or a dict)
    validates the entities at construction; it is not re-applied when the handle
    is later reused in an ``is_authorized(..., schema=...)`` call (same
    pre-parsed-handle contract as ``PolicySet``).

    This thin wrapper normalizes a dict ``schema`` to JSON (matching the rest of
    the package) and delegates to the Rust-backed handle; ``len()`` is the entity
    count and ``str()`` renders the entities back to Cedar JSON.
    """

    def __init__(self, _inner: "_internal.Entities") -> None:
        # Handles are created via from_json_str / with_added_json_str, never
        # constructed directly; mirror the Rust handle's no-bare-constructor rule.
        if not isinstance(_inner, _internal.Entities):
            raise TypeError(
                "Entities cannot be constructed directly; use Entities.from_json_str(...)")
        self._inner = _inner

    @staticmethod
    def from_json_str(s: str, schema: Union[str, dict, None] = None) -> "Entities":
        """Parse an ``Entities`` handle from a Cedar JSON entities document.

        :param schema: (optional) a Cedar schema as a JSON/Cedar string or a
            dict; when supplied, the entities are validated against it.
        :raises ValueError: if the entities (or schema) cannot be parsed, or the
            entities do not conform to ``schema``.
        """
        if isinstance(schema, dict):
            schema = json.dumps(schema)
        return Entities(_internal.Entities.from_json_str(s, schema))

    def with_added_json_str(self, delta: str, schema: Union[str, dict, None] = None) -> "Entities":
        """Return a NEW ``Entities`` handle: this base plus the entities parsed
        from ``delta``. The base is cloned, not re-parsed — only ``delta`` is
        parsed. The merge is a disjoint union: a ``delta`` entity whose uid
        duplicates a non-identical base uid raises ``ValueError``.

        :param schema: (optional) a Cedar schema as a JSON/Cedar string or a
            dict; when supplied, validates the combined set.
        :raises ValueError: if ``delta`` (or ``schema``) cannot be parsed, a
            ``delta`` uid duplicates a non-identical base uid, or the result
            violates ``schema``.
        """
        if isinstance(schema, dict):
            schema = json.dumps(schema)
        return Entities(self._inner.with_added_json_str(delta, schema))

    def __len__(self) -> int:
        return len(self._inner)

    def __str__(self) -> str:
        return str(self._inner)

    def __repr__(self) -> str:
        return repr(self._inner)


def echo(s: str) -> str:
    return _internal.echo(s)


class Decision(Enum):
    Allow = 'Allow'
    Deny = 'Deny'
    NoDecision = 'NoDecision'


class _DiagnosticsBase:
    """Shared backing for the public diagnostics types. Not part of the
    public API — type-annotate against ``Diagnostics`` or
    ``PartialDiagnostics`` directly. Exists to share dict-accessor
    implementation without committing the two public types to a
    subclass relationship.
    """

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


class Diagnostics(_DiagnosticsBase):
    """Diagnostics for a fully-evaluated authorization decision."""
    pass


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
                  policies: Union[str, PolicySet],
                  entities: Union[str, List[dict], Entities],
                  schema: Union[str, dict, None] = None,
                  verbose: bool = False) -> AuthzResult:
    """Evaluate whether the request is authorized given the parameters.

    :param request is a Cedar-style request object containing a principal, action, resource, and (optional) context.
    Each of ``principal``, ``action``, ``resource`` may be either a Cedar surface-syntax string
    (e.g. ``'User::"alice"'``) or a structured dict with ``type`` and ``id`` keys
    (e.g. ``{"type": "User", "id": "alice"}``). The dict form sidesteps Cedar's surface-syntax
    constraints and is required for entity ids containing characters Cedar's parser rejects as
    "needs to be normalized" (e.g. embedded newlines). It mirrors cedar-java's ``JsonEUID`` form.
    ``context`` may be a dict (preferred) or a string.
    :param policies the Cedar policies, as either a str containing all the policies in the PolicySet
    or a pre-parsed ``PolicySet`` handle (``PolicySet.from_str(...)``). Reusing a handle across calls
    avoids re-parsing the policies on every call; see the ``PolicySet`` class for details.
    :param entities a list of entities, a json-formatted string containing the list of entities, or a
    pre-parsed ``Entities`` handle (``Entities.from_json_str(...)``). Reusing a handle across calls
    avoids re-parsing the entity graph on every call; see the ``Entities`` class for details.
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
                        policies: Union[str, PolicySet],
                        entities: Union[str, List[dict], Entities],
                        schema: Union[str, dict, None] = None,
                        verbose: bool = False) -> List[AuthzResult]:
    """Evaluate whether a batch of requests are authorized given the other parameters.  Each request is evaluated
    independently and results in an AuthzResult per request.

    :param requests is list of Cedar-style request objects containing a principal, action, resource, and (optional) context.
    Each of ``principal``, ``action``, ``resource`` may be either a Cedar surface-syntax string
    (e.g. ``'User::"alice"'``) or a structured dict with ``type`` and ``id`` keys
    (e.g. ``{"type": "User", "id": "alice"}``). See ``is_authorized`` for details. ``context`` may
    be a dict (preferred) or a string.
    :param policies the Cedar policies, as either a str containing all the policies in the PolicySet
    or a pre-parsed ``PolicySet`` handle (``PolicySet.from_str(...)``). Reusing a handle across calls
    avoids re-parsing the policies on every call; see the ``PolicySet`` class for details.
    :param entities a list of entities, a json-formatted string containing the list of entities, or a
    pre-parsed ``Entities`` handle (``Entities.from_json_str(...)``). Reusing a handle across calls
    avoids re-parsing the entity graph on every call; see the ``Entities`` class for details.
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

    # Normalize entities to what the extension accepts: a JSON string, or the
    # Rust-backed _internal.Entities unwrapped from the public handle.
    internal_entities = entities
    if isinstance(internal_entities, list):
        internal_entities = json.dumps(internal_entities)
    elif isinstance(internal_entities, Entities):
        internal_entities = internal_entities._inner

    if schema is not None:
        if isinstance(schema, str):
            pass
        elif isinstance(schema, dict):
            schema = json.dumps(schema)

    authz_result_strs: List[str] = _internal.is_authorized_batch(requests_local, policies, internal_entities, schema, verbose)
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


class PartialDiagnostics(_DiagnosticsBase):
    """Diagnostics for a partial-evaluation authorization decision.

    Carries the same ``errors`` / ``reasons`` / ``id_annotations_by_reason``
    surface as ``Diagnostics``, plus partial-eval-specific fields. Note that
    semantics differ slightly: in partial eval, ``reasons`` lists the
    definitely-satisfied policies, and ``id_annotations_by_reason`` covers
    annotations for definitely-satisfied, all-residual, and
    definitely-errored policies.
    """

    @property
    def may_be_determining(self) -> List[str]:
        return self._diagnostics.get('may_be_determining', [])

    @property
    def must_be_determining(self) -> List[str]:
        return self._diagnostics.get('must_be_determining', [])

    @property
    def nontrivial_residuals(self) -> List[str]:
        return self._diagnostics.get('nontrivial_residuals', [])

    @property
    def unknown_entities(self) -> List[str]:
        return self._diagnostics.get('unknown_entities', [])


class PartialAuthzResult:
    """Result of a partial authorization evaluation.

    When the authorizer can reach a definitive decision despite unknowns,
    ``decision`` is ``Allow`` or ``Deny``. When unknowns prevent a decision,
    ``decision`` is ``NoDecision`` and ``residuals`` contains simplified
    policy ASTs awaiting further evaluation. When input errors occur,
    ``decision`` is ``NoDecision`` and ``residuals`` is empty.
    """

    def __init__(self, authz_resp: dict) -> None:
        self._authz_resp = authz_resp
        self._diagnostics = PartialDiagnostics(authz_resp.get('diagnostics', {}))

    @property
    def decision(self) -> Decision:
        d = self._authz_resp.get('decision')
        if d is None or d == 'NoDecision':
            return Decision.NoDecision
        return Decision[d]

    @property
    def allowed(self) -> bool:
        """allowed is ``True`` iff ``decision == Decision.Allow``. Both ``Deny`` and
        ``NoDecision`` return ``False``; check ``decision`` directly to
        distinguish a denial from an unknown-blocked partial result.
        """
        return Decision.Allow == self.decision

    @property
    def correlation_id(self) -> Optional[str]:
        return self._authz_resp.get('correlation_id')

    @property
    def diagnostics(self) -> PartialDiagnostics:
        return self._diagnostics

    @property
    def residuals(self) -> dict:
        return self._authz_resp.get('residuals', {})

    @property
    def metrics(self) -> dict:
        return self._authz_resp.get('metrics', {})

    def __getitem__(self, __name: str) -> Any:
        return getattr(self, __name)


def is_authorized_partial(request: dict,
                          policies: Union[str, PolicySet],
                          entities: Union[str, List[dict], Entities],
                          schema: Union[str, dict, None] = None,
                          verbose: bool = False) -> PartialAuthzResult:
    """Partially evaluate an authorization request with unknowns.

    Fields in the request dict that are None or absent are treated as
    unknown. The evaluator simplifies policies as far as possible and
    returns residual expressions for policies that cannot be fully resolved.

    .. warning::

        **Partial-eval results MUST NOT be used as a final authorization
        decision.** Treat ``decision == Decision.Allow`` from
        ``is_authorized_partial`` as a *preview* that holds only for the
        unknowns supplied. Once all unknowns are bound, re-run
        ``is_authorized`` with the complete request; that call performs
        full schema validation (including action-typed context shapes)
        which partial evaluation deliberately skips for fields that are
        still unknown.

        In particular, when a schema is provided but ``action`` is
        unknown, request-context type-checking against the schema's
        action-specific context shape is silently skipped — there is no
        bound action to look up. A residual that depends on context
        values is not a guarantee that those values are well-typed.

    :param request is a Cedar-style request object containing a principal, action, resource, and (optional) context;
    context may be a dict (preferred) or a string.
    Unlike is_authorized (which defaults an absent context to empty),
    an absent or None context here is treated as unknown and will residualize;
    pass context={} for an explicitly empty context.
    :param policies the Cedar policies, as either a str containing all the policies in the PolicySet
    or a pre-parsed ``PolicySet`` handle (``PolicySet.from_str(...)``). Reusing a handle across calls
    avoids re-parsing the policies on every call; see the ``PolicySet`` class for details.
    :param entities a list of entities, a json-formatted string containing the list of entities, or a
    pre-parsed ``Entities`` handle (``Entities.from_json_str(...)``). Reusing a handle across calls
    avoids re-parsing the entity graph on every call; see the ``Entities`` class for details.
    :param schema (optional) dictionary or json-formatted string containing the Cedar schema
    :param verbose (optional) boolean determining whether to enable verbose logging output within the library

    :returns a PartialAuthzResult
    """
    request_local: dict = {}
    for key in ('principal', 'action', 'resource', 'correlation_id'):
        if key in request:
            request_local[key] = request[key]

    if 'context' in request:
        context = request['context']
        if isinstance(context, dict):
            request_local['context'] = json.dumps(context)
        elif context is None:
            request_local['context'] = None
        else:
            request_local['context'] = context

    internal_entities = entities
    if isinstance(internal_entities, list):
        internal_entities = json.dumps(internal_entities)
    elif isinstance(internal_entities, Entities):
        internal_entities = internal_entities._inner

    if schema is not None and isinstance(schema, dict):
        schema = json.dumps(schema)

    result_str = _internal.is_authorized_partial(
        request_local, policies, internal_entities, schema, verbose)
    result_dict = json.loads(result_str)
    return PartialAuthzResult(result_dict)


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
