"""Pytest fixtures for the integration test suite.

Specifically, supports the corpus-tests runner by extracting
``cedar-integration-tests/corpus-tests.tar.gz`` once per session into a
temp directory.
"""

import atexit
import json
import shutil
import tarfile
import tempfile
from pathlib import Path

import pytest


CORPUS_TARBALL = Path(__file__).parent / "resources" / "cedar-integration-tests" / "corpus-tests.tar.gz"


def _extract_corpus_once() -> Path:
    """Extract the corpus tarball to a process-lifetime tmp dir.

    pytest collection happens at import time, before any fixture has
    run, so we need a place that exists as soon as the test module is
    imported. We register an ``atexit`` cleanup so the dir is removed
    when the test process exits.
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
