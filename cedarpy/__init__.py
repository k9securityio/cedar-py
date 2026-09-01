from __future__ import annotations

import json
from copy import copy
from enum import Enum
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from cedarpy import _internal
from cedarpy import pst

# Re-export the Rust-implemented PolicySet and Schema handles.
PolicySet = _internal.PolicySet
Schema = _internal.Schema

__all__ = [
    "AuthzResult", "Decision", "Diagnostics", "Entities", "PartialAuthzResult",
    "PartialDiagnostics", "PartialEntities", "PolicySet", "Schema",
    "TpeAuthzResult", "TpeClassification", "ValidationError",
    "ValidationResult", "echo", "format_policies", "is_authorized",
    "is_authorized_batch", "is_authorized_partial", "policies_from_json_str",
    "policies_to_json_str", "policies_to_pst", "pst", "tpe_authorize",
    "tpe_reauthorize", "validate_policies",
]


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
    def from_json_str(s: str, schema: str | dict | Schema | None = None) -> Entities:
        """Parse an ``Entities`` handle from a Cedar JSON entities document.

        :param schema: (optional) a Cedar schema as a JSON/Cedar string, a
            dict, or a pre-parsed ``Schema`` handle; when supplied, the entities
            are validated against it.
        :raises ValueError: if the entities (or schema) cannot be parsed, or the
            entities do not conform to ``schema``.
        """
        if isinstance(schema, dict):
            schema = json.dumps(schema)
        return Entities(_internal.Entities.from_json_str(s, schema))

    def with_added_json_str(self, delta: str, schema: str | dict | Schema | None = None) -> Entities:
        """Return a NEW ``Entities`` handle: this base plus the entities parsed
        from ``delta``. The base is cloned, not re-parsed — only ``delta`` is
        parsed. The merge is a disjoint union: a ``delta`` entity whose uid
        duplicates a non-identical base uid raises ``ValueError``.

        :param schema: (optional) a Cedar schema as a JSON/Cedar string, a
            dict, or a pre-parsed ``Schema`` handle; when supplied, validates
            the combined set.
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


@dataclass(frozen=True)
class PartialEntities:
    """An entity document in which some entity data is unknown.

    A concrete entity set says every entity's attributes, parents, and tags are
    known. TPE also accepts a document where an entity exists but one of those
    is absent, meaning unknown, so policies reading it stay residual. Each of
    ``attrs``, ``parents``, and ``tags`` must be wholly present or wholly
    absent per entity, and a parent entity cannot itself have unknown parents.

    Pass the result as ``tpe_authorize(..., entities=PartialEntities.from_json(...))``.
    """
    _partial_entities_json: str

    @staticmethod
    def from_json(entities: str | list[dict] | dict) -> PartialEntities:
        """Build from a partial entity document, as JSON text or Python data."""
        if isinstance(entities, str):
            return PartialEntities(entities)
        return PartialEntities(json.dumps(entities))


@dataclass(frozen=True)
class _TpeInputs:
    """The inputs one ``tpe_authorize`` call ran with, so its result can
    reauthorize without the caller repeating them."""
    principal: str | dict | pst.EntityType
    action: str | dict
    resource: str | dict | pst.EntityType
    policies: str | PolicySet
    entities: str | list[dict] | Entities | PartialEntities
    schema: str | dict | Schema
    context: dict | None


@dataclass(frozen=True)
class TpeClassification:
    """Policy ids TPE could not resolve, and the ones it did, for one effect."""
    residual_ids: tuple[str, ...]
    true_ids: tuple[str, ...]
    false_ids: tuple[str, ...]
    error_ids: tuple[str, ...]


@dataclass(frozen=True)
class TpeAuthzResult:
    """The outcome of one ``tpe_authorize`` call.

    ``decision`` is ``Decision.Allow`` or ``Decision.Deny`` when the unknowns
    cannot change the outcome, and ``None`` when they can. ``permits`` and
    ``forbids`` classify the policy ids of each effect separately.
    """
    decision: Decision | None
    reason: tuple[str, ...]
    permits: TpeClassification
    forbids: TpeClassification
    residual_policies: Mapping[str, pst.Template]
    """The undecided policies, as typed ``cedarpy.pst`` nodes.

    Each is reduced by the evaluator, with the concrete parts of the request
    already substituted in. ``pst.entity_uids`` on this mapping reports the
    entities still needed to finish the evaluation. This is a different view
    from ``residual_policy_set``, and the two name different entities."""
    residual_policy_set: PolicySet
    """Every residual as a reusable ``PolicySet`` handle.

    Includes the residuals that came out concretely true, false or erroring,
    each keeping its original scope. Pass it to ``is_authorized`` once the
    unknowns are bound, or use ``reauthorize``, which also checks the concrete
    request against the partial one."""
    metrics: Mapping[str, int]
    _request_inputs: _TpeInputs | None = field(default=None, repr=False, compare=False)

    def reauthorize(self,
                    request: dict,
                    entities: str | list[dict] | Entities | None = None,
                    verbose: bool = False) -> AuthzResult:
        """Bind the unknowns and reach a concrete decision from the residuals.

        ``request`` is a fully concrete request, in the same form
        ``is_authorized`` accepts. ``entities`` defaults to the entities the
        ``tpe_authorize`` call ran against, and is required when that call ran
        against a ``PartialEntities`` document. The engine checks the concrete
        request and entities for consistency with the partial ones, so a
        request that contradicts them raises rather than returning a decision
        Cedar never sanctioned.

        :returns an AuthzResult, the same type ``is_authorized`` returns.
        """
        if self._request_inputs is None:
            raise ValueError(
                "this TpeAuthzResult was not produced by tpe_authorize, so it does not "
                "carry the inputs to reauthorize against; call tpe_reauthorize(...) with "
                "them explicitly"
            )
        i = self._request_inputs
        return tpe_reauthorize(
            request=request,
            principal=i.principal,
            action=i.action,
            resource=i.resource,
            policies=i.policies,
            entities=i.entities,
            schema=i.schema,
            context=i.context,
            concrete_entities=entities,
            verbose=verbose,
        )


class _DiagnosticsBase:
    """Shared backing for the public diagnostics types. Not part of the
    public API — type-annotate against ``Diagnostics`` or
    ``PartialDiagnostics`` directly. Exists to share dict-accessor
    implementation without committing the two public types to a
    subclass relationship.
    """

    def __init__(self, diagnostics: Mapping[str, Any]) -> None:
        super().__init__()
        self._diagnostics: Mapping[str, Any] = diagnostics

    @property
    def errors(self) -> list[str]:
        return self._diagnostics.get('errors', list())

    @property
    def reasons(self) -> list[str]:
        # (intentionally) map 'reason' key in diagnostics dict to 'reasons' property (plural)
        return self._diagnostics.get('reason', list())

    @property
    def id_annotations_by_reason(self) -> Mapping[str, str]:
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
    def __init__(self, authz_resp: Mapping[str, Any]) -> None:
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
    def correlation_id(self) -> str | None:
        return self._authz_resp.get('correlation_id', None)

    @property
    def diagnostics(self) -> Diagnostics:
        return self._diagnostics

    @property
    def metrics(self) -> Mapping[str, int]:
        return self._authz_resp.get('metrics', {})

    def __getitem__(self, __name: str) -> Any:
        return getattr(self, __name)


class ValidationError:
    """Represents a single validation error found when validating policies against a schema."""

    def __init__(self, error_dict: Mapping[str, Any]) -> None:
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

    def __init__(self, result_dict: Mapping[str, Any]) -> None:
        self._result = result_dict
        self._errors = [ValidationError(e) for e in result_dict.get('errors', [])]

    @property
    def validation_passed(self) -> bool:
        """True if all policies passed validation."""
        return self._result.get('validation_passed', False)

    @property
    def errors(self) -> list[ValidationError]:
        """List of validation errors (empty if validation passed)."""
        return self._errors

    @property
    def id_annotations_by_policy_id(self) -> Mapping[str, str]:
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
                  policies: str | PolicySet,
                  entities: str | list[dict] | Entities,
                  schema: str | dict | Schema | None = None,
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
    :param schema (optional) a Cedar schema as a JSON dict, JSON string, Cedar schema string, or a
    pre-parsed ``Schema`` handle (``Schema.from_str(...)``). Reusing a handle across calls avoids
    re-parsing the schema on every call; see the ``Schema`` class for details.
    :param verbose (optional) boolean determining whether to enable verbose logging output within the library

    :returns an AuthzResult

    """
    return is_authorized_batch(requests=[request],
                               policies=policies,
                               entities=entities,
                               schema=schema,
                               verbose=verbose)[0]


def is_authorized_batch(requests: list[dict],
                        policies: str | PolicySet,
                        entities: str | list[dict] | Entities,
                        schema: str | dict | Schema | None = None,
                        verbose: bool = False) -> list[AuthzResult]:
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
    :param schema (optional) a Cedar schema as a JSON dict, JSON string, Cedar schema string, or a
    pre-parsed ``Schema`` handle (``Schema.from_str(...)``). Reusing a handle across calls avoids
    re-parsing the schema on every call; see the ``Schema`` class for details.
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

    authz_result_strs: list[str] = _internal.is_authorized_batch(
        requests_local, policies, _internal_entities(entities), _internal_schema(schema), verbose)
    authz_result_objs: list[Mapping[str, Any]] = []

    for authz_result_str in authz_result_strs:
        authz_result_objs.append(json.loads(authz_result_str))
        
    authz_results: list[AuthzResult] = []
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


def policies_to_pst(policies: str) -> "pst.PolicySet":
    """Parse Cedar policy text into typed PST nodes from cedarpy.pst.

    The node set tracks the Cedar engine (see the ``cedarpy.pst`` module
    docs): syntax newer than the modelled node types raises ``ValueError``
    until a cedarpy release models it.
    """
    return _internal.policies_to_pst(policies)


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
    def may_be_determining(self) -> list[str]:
        return self._diagnostics.get('may_be_determining', [])

    @property
    def must_be_determining(self) -> list[str]:
        return self._diagnostics.get('must_be_determining', [])

    @property
    def nontrivial_residuals(self) -> list[str]:
        return self._diagnostics.get('nontrivial_residuals', [])

    @property
    def unknown_entities(self) -> list[str]:
        return self._diagnostics.get('unknown_entities', [])


class PartialAuthzResult:
    """Result of a partial authorization evaluation.

    When the authorizer can reach a definitive decision despite unknowns,
    ``decision`` is ``Allow`` or ``Deny``. When unknowns prevent a decision,
    ``decision`` is ``NoDecision`` and ``residuals`` contains simplified
    policy ASTs awaiting further evaluation. When input errors occur,
    ``decision`` is ``NoDecision`` and ``residuals`` is empty.
    """

    def __init__(self, authz_resp: Mapping[str, Any]) -> None:
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
    def correlation_id(self) -> str | None:
        return self._authz_resp.get('correlation_id')

    @property
    def diagnostics(self) -> PartialDiagnostics:
        return self._diagnostics

    @property
    def residuals(self) -> Mapping[str, Any]:
        return self._authz_resp.get('residuals', {})

    @property
    def metrics(self) -> Mapping[str, int]:
        return self._authz_resp.get('metrics', {})

    def __getitem__(self, __name: str) -> Any:
        return getattr(self, __name)


def is_authorized_partial(request: dict,
                          policies: str | PolicySet,
                          entities: str | list[dict] | Entities,
                          schema: str | dict | Schema | None = None,
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
    :param schema (optional) a Cedar schema as a JSON dict, JSON string, Cedar schema string, or a
    pre-parsed ``Schema`` handle (``Schema.from_str(...)``). Reusing a handle across calls avoids
    re-parsing the schema on every call; see the ``Schema`` class for details.
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

    result_str = _internal.is_authorized_partial(
        request_local, policies, _internal_entities(entities), _internal_schema(schema), verbose)
    result_dict = json.loads(result_str)
    return PartialAuthzResult(result_dict)


_TpeEntities = str | list[dict] | Entities | PartialEntities
_TpePartialEuid = str | dict | pst.EntityType


def _normalize_tpe_euid(value: str | dict | pst.EntityType) -> str | dict:
    """A `pst.EntityType` names a type whose id is unknown. Pass it on in the
    dict form Rust reads, which carries `type` and an optional `id`."""
    if isinstance(value, pst.EntityType):
        return {"type": str(value)}
    return value


def _internal_entities(entities: str | list[dict] | Entities) -> str | _internal.Entities:
    """Narrow the public entities forms to what the extension accepts: JSON
    text, or the Rust-backed handle unwrapped from the public one."""
    if isinstance(entities, list):
        return json.dumps(entities)
    if isinstance(entities, Entities):
        return entities._inner
    return entities


def _internal_schema(schema: str | dict | Schema | None) -> str | Schema | None:
    """Narrow a schema to what Rust's SchemaArg reads: text or a handle."""
    if isinstance(schema, dict):
        return json.dumps(schema)
    return schema


def _internal_schema_required(schema: str | dict | Schema) -> str | Schema:
    """The TPE path requires a schema, so its narrowing cannot yield None."""
    if isinstance(schema, dict):
        return json.dumps(schema)
    return schema


def _normalize_tpe_entities(entities: _TpeEntities) -> Any:
    if isinstance(entities, PartialEntities):
        return entities
    return _internal_entities(entities)


def tpe_authorize(principal: _TpePartialEuid,
                  action: str | dict,
                  resource: _TpePartialEuid,
                  policies: str | PolicySet,
                  entities: _TpeEntities,
                  schema: str | dict | Schema,
                  context: dict | None = None,
                  verbose: bool = False) -> TpeAuthzResult:
    """Evaluate a request whose principal or resource is known only by type.

    Returns residual policies, as typed ``cedarpy.pst`` nodes, for the parts
    the unknowns leave undecided. This is a separate feature from
    ``is_authorized_partial``, which it neither calls nor changes.

    ``principal`` / ``resource`` accept a concrete entity, as a Cedar
    surface-syntax string (``'User::"alice"'``) or a ``{"type": ..., "id": ...}``
    dict, or a known type with an unknown id, as a bare type string (``"User"``),
    a ``pst.EntityType``, or a dict carrying only ``type``. ``action`` must be
    concrete and takes either of the two concrete forms.

    ``context`` follows ``is_authorized_partial``: ``None`` (the default) means
    the context is unknown, so policies reading it stay residual, and ``{}``
    means a known-empty context.

    ``entities`` must be fully concrete unless wrapped in ``PartialEntities``,
    which additionally allows an entity's attributes, parents, or tags to be
    unknown. ``schema`` is required.

    :raises ValueError: on input Cedar cannot resolve.
    :returns a TpeAuthzResult, whose ``reauthorize`` binds the unknowns later.
    """
    result = _internal.tpe_authorize(
        _normalize_tpe_euid(principal),
        _normalize_tpe_euid(action),
        _normalize_tpe_euid(resource),
        policies,
        _normalize_tpe_entities(entities),
        _internal_schema_required(schema),
        None if context is None else json.dumps(context),
        verbose,
    )
    return replace(result, _request_inputs=_TpeInputs(
        principal=principal, action=action, resource=resource, policies=policies,
        entities=entities, schema=schema, context=context,
    ))


def tpe_reauthorize(request: dict,
                    principal: _TpePartialEuid,
                    action: str | dict,
                    resource: _TpePartialEuid,
                    policies: str | PolicySet,
                    entities: _TpeEntities,
                    schema: str | dict | Schema,
                    context: dict | None = None,
                    concrete_entities: str | list[dict] | Entities | None = None,
                    verbose: bool = False) -> AuthzResult:
    """Bind the unknowns a TPE call left open and decide by evaluating only
    its residuals.

    Every parameter after ``request`` is the corresponding ``tpe_authorize``
    input; ``TpeAuthzResult.reauthorize`` calls this with the ones its own call
    used. ``request`` is a fully concrete request in the form ``is_authorized``
    accepts. ``concrete_entities`` overrides the entities to evaluate against,
    and is required when ``entities`` was a ``PartialEntities`` document.

    Cedar checks the concrete request and entities against the partial ones
    before evaluating, so a request contradicting them raises rather than
    returning a decision the partial evaluation never sanctioned.

    :raises ValueError: on inconsistent or unresolvable input.
    :returns an AuthzResult, the same type ``is_authorized`` returns.
    """
    request_local = request
    if "context" in request_local:
        context_value = request_local["context"]
        request_local = copy(request_local)
        if isinstance(context_value, dict):
            request_local["context"] = json.dumps(context_value)
        elif context_value is None:
            del request_local["context"]

    result_str = _internal.tpe_reauthorize(
        request_local,
        _normalize_tpe_euid(principal),
        _normalize_tpe_euid(action),
        _normalize_tpe_euid(resource),
        policies,
        _normalize_tpe_entities(entities),
        _internal_schema_required(schema),
        None if context is None else json.dumps(context),
        None if concrete_entities is None else _normalize_tpe_entities(concrete_entities),
        verbose,
    )
    return AuthzResult(json.loads(result_str))


def validate_policies(policies: str,
                      schema: str | dict | Schema) -> ValidationResult:
    """Validate Cedar policies against a schema.

    This function checks that policies are valid according to the provided schema,
    including entity type checking, action validation, and type checking of
    expressions in policy conditions.

    :param policies: Cedar policies as a string
    :param schema: Cedar schema (JSON dict, JSON string, Cedar schema string,
        or a pre-parsed ``Schema`` handle)

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
    # str and Schema handles pass through directly to Rust's SchemaArg

    result_str = _internal.validate_policies(policies, schema)
    result_dict = json.loads(result_str)
    return ValidationResult(result_dict)
