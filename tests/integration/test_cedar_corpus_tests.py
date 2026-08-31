"""Runs the auto-generated cedar fuzzer corpus tests.

These tests live in ``cedar-integration-tests/corpus-tests.tar.gz`` and
exercise edge cases that hand-written tests don't. The upstream cedar
Rust runner (cedar-testing/tests/cedar-policy/corpus_tests.rs) and the
cedar-java runner (CedarJava/.../SharedIntegrationTests.java) both apply
these leniencies versus the strict comparison used for hand-written
tests:

* ``reason`` is compared as a set (decision is the contract; ordering is
  not).
* ``errors`` is compared by **count only** — the integration-test format
  records erroring policy ids, but cedar-py surfaces the full error
  message, so we can't compare strings directly. Cedar-java does the
  same.
* Policy parse failures: cedarpy returns ``decision=NoDecision``. The
  upstream contract is "if parse fails, expected decision is Deny" —
  treat ``NoDecision`` as a soft-pass when the fixture expected ``Deny``.
* ``validateRequest=false`` requests skip schema-based request
  validation. cedar-py achieves this by omitting the ``schema`` argument
  to ``is_authorized`` for those cases.
* The fixture's ``principal``/``action``/``resource`` fields are already
  ``{type, id}`` dicts — passed through to ``is_authorized`` unchanged so
  cedar-py's structured-EUID path handles fuzzer-generated entity ids
  that aren't expressible in Cedar surface syntax.

Not run as part of ``make integration-tests`` — invoke explicitly via
``make corpus-tests`` because the suite is large (7K+ files).
"""

import atexit
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

import pytest

import cedarpy


CORPUS_TARBALL = Path(__file__).parent / "resources" / "cedar-integration-tests" / "corpus-tests.tar.gz"


def _extract_corpus_once() -> Optional[Path]:
    """Extract the corpus tarball to a process-lifetime tmp dir.

    pytest collection happens at import time, before any fixture has
    run, so we need a place that exists as soon as the test module is
    imported. We register an ``atexit`` cleanup so the dir is removed
    when the test process exits.

    Lives in this module (not the shared ``conftest.py``) so the
    extraction cost is only paid when the corpus suite is actually
    collected — ``make integration-tests`` never imports this module.
    """
    if not CORPUS_TARBALL.exists():
        return None
    tmp_root = tempfile.mkdtemp(prefix="cedar-corpus-tests-")
    atexit.register(shutil.rmtree, tmp_root, ignore_errors=True)
    with tarfile.open(CORPUS_TARBALL, "r:gz") as tf:
        tf.extractall(tmp_root)
    return Path(tmp_root) / "corpus-tests"


CORPUS_DIR = _extract_corpus_once()


def _list_corpus_test_params() -> list:
    """Build ``(stem, request_index)`` pairs for parameterization.

    Reads each test's ``requests`` array length from the extracted tree,
    then yields one param tuple per request. Result is sorted for
    deterministic test IDs.
    """
    if CORPUS_DIR is None:
        return []
    out = []
    for json_path in sorted(CORPUS_DIR.glob("*.json")):
        if json_path.name.endswith(".entities.json"):
            continue
        with json_path.open() as f:
            data = json.load(f)
        stem = json_path.stem
        for i in range(len(data.get("requests", []))):
            out.append((stem, i))
    return out


CORPUS_PARAMS = _list_corpus_test_params()


@pytest.fixture(scope="session")
def corpus_dir() -> Path:
    """Path to the directory containing extracted corpus test files."""
    if CORPUS_DIR is None:
        pytest.skip("corpus-tests.tar.gz not present (run `make submodules` first)")
    return CORPUS_DIR


def _load_test(corpus_dir: Path, stem: str) -> dict:
    """Load and resolve all artifacts for a single corpus test file."""
    with (corpus_dir / f"{stem}.json").open() as f:
        test_def = json.load(f)
    # The corpus JSONs reference resources by path relative to the
    # cedar-integration-tests root (e.g. "corpus-tests/<stem>.cedar").
    # Strip the directory and resolve from `corpus_dir` directly.
    policies_path = corpus_dir / Path(test_def["policies"]).name
    entities_path = corpus_dir / Path(test_def["entities"]).name
    schema_path = corpus_dir / Path(test_def["schema"]).name
    return {
        "policies": policies_path.read_text(),
        "entities": json.loads(entities_path.read_text()),
        "schema": schema_path.read_text(),
        "requests": test_def["requests"],
    }


@pytest.mark.parametrize(
    ("stem", "request_index"),
    CORPUS_PARAMS,
    ids=[f"{stem}_r{i}" for stem, i in CORPUS_PARAMS],
)
def test_corpus(corpus_dir: Path, stem: str, request_index: int) -> None:
    test = _load_test(corpus_dir, stem)
    request_model = test["requests"][request_index]

    # Honor the per-request `validateRequest` flag the way cedar-java does:
    # when false, omit the schema so cedar-py won't enforce request validation.
    validate_request = request_model.get("validateRequest", True)
    schema_arg = test["schema"] if validate_request else None

    # The fixture's principal/action/resource are already in
    # `{type, id}` shape — pass them through to is_authorized as-is and
    # let cedarpy's structured-EUID path (EntityUid::from_json) handle
    # them. This sidesteps Cedar's surface-syntax restrictions on entity
    # ids (e.g. embedded newlines), which the fuzzer corpus exercises.
    request = {
        "principal": request_model["principal"],
        "action": request_model["action"],
        "resource": request_model["resource"],
        "context": request_model.get("context", {}),
    }

    result = cedarpy.is_authorized(
        request=request,
        policies=test["policies"],
        entities=test["entities"],
        schema=schema_arg,
        verbose=False,
    )

    expected_decision = request_model["decision"].lower()
    actual_decision = result.decision.value.lower()

    # Soft-pass for parse-error path: cedarpy returns NoDecision when the
    # policy or schema fails to parse. The upstream-runner contract is
    # "expected decision must be Deny" in that case.
    if actual_decision == "nodecision":
        assert expected_decision == "deny", (
            f"{stem}#{request_index}: cedarpy returned NoDecision (parse failure) "
            f"but fixture expected decision={expected_decision!r}. "
            f"errors={result.diagnostics.errors}"
        )
        return

    assert expected_decision == actual_decision, (
        f"{stem}#{request_index} ({request_model.get('description', '')}): "
        f"unexpected decision"
    )
    assert set(request_model["reason"]) == set(result.diagnostics.reasons), (
        f"{stem}#{request_index}: unexpected reasons"
    )
    # cedar-java semantics: count-only error comparison.
    assert len(request_model["errors"]) == len(result.diagnostics.errors), (
        f"{stem}#{request_index}: expected {len(request_model['errors'])} errors, "
        f"got {len(result.diagnostics.errors)}: {result.diagnostics.errors}"
    )


def test_corpus_policies_convert_to_pst(corpus_dir: Path) -> None:
    """Every corpus policy either converts to PST nodes or is rejected by cedar.

    ``policies_to_pst`` and ``PolicySet.from_pst`` mirror cedar's pst enums by
    hand, and those enums are ``#[non_exhaustive]``, so nothing at compile time
    says the mirror is complete. This runs the whole fuzzer corpus through the
    conversion and back.

    What it asserts is not "everything converts": cedar's own PST construction
    rejects some fuzzer output, and those failures are cedar's to make — but
    only one shape of them is known and expected, extension functions called
    with the wrong number of arguments (arity is unchecked at parse time and
    checked at PST construction). Every cedar-side rejection must match that
    shape; the first rejection of any other kind fails the test, named. No
    failure may be *cedarpy's*, i.e. the "unrepresentable variant" error
    raised when a node kind is not modelled, and everything which does
    convert must survive the round trip unchanged.
    """
    policy_files = sorted(corpus_dir.glob("*.cedar"))
    # Guards against the corpus silently shrinking (7,600 files as of the
    # v4.12.0 corpus), which the per-failure assertions below cannot see.
    assert len(policy_files) > 7000, f"only {len(policy_files)} .cedar files under {corpus_dir}"

    expected_rejection = re.compile(r"expects \d+ argument\(s\), got \d+")
    unrepresentable: list[str] = []
    unexpected_rejections: list[str] = []
    not_identity: list[str] = []
    for path in policy_files:
        source = path.read_text()
        try:
            nodes = cedarpy.policies_to_pst(source)
        except ValueError as e:
            if "unrepresentable" in str(e):
                unrepresentable.append(f"{path.name}: {e}")
            elif not expected_rejection.search(str(e)):
                unexpected_rejections.append(f"{path.name}: {e}")
            continue
        if cedarpy.PolicySet.from_pst(nodes).to_pst() != nodes:
            not_identity.append(path.name)

    assert not unrepresentable, (
        "policies_to_pst met node kinds cedarpy does not model:\n"
        + "\n".join(unrepresentable[:20])
    )
    assert not unexpected_rejections, (
        "cedar rejected corpus policies for a reason other than extension\n"
        "function arity; decide whether the new rejection shape is cedar's\n"
        "or cedarpy's, then extend expected_rejection if it is cedar's:\n"
        + "\n".join(unexpected_rejections[:20])
    )
    assert not not_identity, (
        "policy sets changed when round-tripped through from_pst/to_pst:\n"
        + "\n".join(not_identity[:20])
    )
