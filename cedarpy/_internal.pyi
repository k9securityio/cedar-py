"""Type stubs for cedarpy's Rust extension. Prefer the public wrappers in
``cedarpy`` (e.g. ``cedarpy.is_authorized``); do not import ``_internal`` directly.
"""
from typing import Any, Dict, List, Optional, Union


class PolicySet:
    """An opaque, reusable handle wrapping a parsed Cedar policy set.

    Parsing policies is the dominant per-call cost in ``is_authorized``. Callers
    whose policies are static can parse them once into a ``PolicySet`` and reuse
    the handle across many authorization calls, avoiding the re-parse each time::

        ps = PolicySet.from_str(policies)        # parse once
        for req in requests:
            is_authorized(req, ps, entities)     # reuse — no re-parse

    A ``PolicySet`` is accepted anywhere a policies string is accepted:
    ``is_authorized``, ``is_authorized_batch``, and ``is_authorized_partial``.

    Construct with ``PolicySet.from_str(cedar_text)`` or
    ``PolicySet.from_json_str(cedar_json)``; both raise ``ValueError`` on parse
    errors. The handle is immutable, and its memory is released automatically
    when the last Python reference is dropped.
    """

    @staticmethod
    def from_str(s: str) -> "PolicySet":
        """Parse a ``PolicySet`` from Cedar policy text. Raises ``ValueError`` on parse errors."""
        ...

    @staticmethod
    def from_json_str(s: str) -> "PolicySet":
        """Parse a ``PolicySet`` from the Cedar JSON (EST) policy format. Raises ``ValueError`` on parse errors."""
        ...

    def with_added_str(self, fragment: str) -> "PolicySet":
        """Return a NEW ``PolicySet`` handle: this set plus the policies parsed
        from ``fragment``. The base is cloned, not re-parsed — only ``fragment``
        is parsed — so a caller with a static base and small dynamic fragments
        avoids re-parsing the base each call.

        The result is equivalent (same authorization decisions) to parsing the
        concatenated base-plus-fragment text. Cedar assigns surface-syntax
        policies a positional ``PolicyId`` (``policy0``, ``policy1``, …) per
        parse, so the fragment's ids that would collide with the base are
        renumbered to follow it, exactly as concatenation would. ``@id``
        annotations are preserved. Raises ``ValueError`` if ``fragment`` cannot
        be parsed.
        """
        ...

    def __len__(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...


class Entities:
    """An opaque, reusable handle wrapping a parsed Cedar entity set.

    Parsing entities (deserializing the JSON and computing the transitive
    closure of the ``parents`` graph) is a per-call cost in ``is_authorized``.
    Callers who authorize many requests against a large, stable base graph can
    parse it once into an ``Entities`` handle and reuse it, avoiding the
    re-parse each time::

        base = Entities.from_json_str(entities_json)   # parse once
        for req in requests:
            is_authorized(req, policy_set, base)        # reuse — no re-parse

    For the common "stable base plus a tiny per-request delta" pattern, build
    the base once and add the delta per call with ``add_from_json_str``, which
    parses only the delta::

        per_request = base.add_from_json_str(delta_json)
        is_authorized(req, policy_set, per_request)

    An ``Entities`` is accepted anywhere an entities string/list is accepted:
    ``is_authorized``, ``is_authorized_batch``, and ``is_authorized_partial``.

    The handle is immutable — ``add_from_json_str`` returns a NEW handle and
    leaves the base unchanged — and its memory is released automatically when
    the last Python reference is dropped. An optional ``schema`` is applied when
    the handle is built; it is not re-applied when the handle is later reused in
    an ``is_authorized(..., schema=...)`` call (same pre-parsed-handle contract
    as ``PolicySet``).
    """

    @staticmethod
    def from_json_str(s: str, schema: Optional[str] = ...) -> "Entities":
        """Parse an ``Entities`` handle from a Cedar JSON entities document.

        ``schema`` (optional) is Cedar schema text or JSON; when supplied, the
        entities are validated against it. Raises ``ValueError`` if the entities
        (or schema) cannot be parsed, or the entities violate ``schema``.
        """
        ...

    def add_from_json_str(self, delta: str, schema: Optional[str] = ...) -> "Entities":
        """Return a NEW ``Entities`` handle: this base set plus the entities
        parsed from ``delta``. The base is cloned, not re-parsed — only ``delta``
        is parsed. The merge is a disjoint union: a ``delta`` entity whose uid
        already exists in the base (and is not identical) is an error.

        ``schema`` (optional), when supplied, validates the combined set. Raises
        ``ValueError`` if ``delta`` (or ``schema``) cannot be parsed, if a
        ``delta`` uid duplicates a non-identical base uid, or the result
        violates ``schema``.
        """
        ...

    def __len__(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...


def echo(s: str) -> str: ...


def is_authorized(
    request: Dict[str, Any],
    policies: Union[str, PolicySet],
    entities: Union[str, Entities],
    schema: Optional[str] = ...,
    verbose: Optional[bool] = ...,
) -> str: ...


def is_authorized_batch(
    requests: List[Dict[str, Any]],
    policies: Union[str, PolicySet],
    entities: Union[str, Entities],
    schema: Optional[str] = ...,
    verbose: Optional[bool] = ...,
) -> List[str]: ...


def is_authorized_partial(
    request: Dict[str, Optional[str]],
    policies: Union[str, PolicySet],
    entities: Union[str, Entities],
    schema: Optional[str] = ...,
    verbose: Optional[bool] = ...,
) -> str: ...


def format_policies(s: str, line_width: int, indent_width: int) -> str: ...


def policies_to_json_str(s: str) -> str: ...


def policies_from_json_str(s: str) -> str: ...


def validate_policies(policies: str, schema: str) -> str: ...
