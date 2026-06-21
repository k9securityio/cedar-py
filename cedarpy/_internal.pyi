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

    def __len__(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...


def echo(s: str) -> str: ...


def is_authorized(
    request: Dict[str, Any],
    policies: Union[str, PolicySet],
    entities: str,
    schema: Optional[str] = ...,
    verbose: Optional[bool] = ...,
) -> str: ...


def is_authorized_batch(
    requests: List[Dict[str, Any]],
    policies: Union[str, PolicySet],
    entities: str,
    schema: Optional[str] = ...,
    verbose: Optional[bool] = ...,
) -> List[str]: ...


def is_authorized_partial(
    request: Dict[str, Optional[str]],
    policies: Union[str, PolicySet],
    entities: str,
    schema: Optional[str] = ...,
    verbose: Optional[bool] = ...,
) -> str: ...


def format_policies(s: str, line_width: int, indent_width: int) -> str: ...


def policies_to_json_str(s: str) -> str: ...


def policies_from_json_str(s: str) -> str: ...


def validate_policies(policies: str, schema: str) -> str: ...
