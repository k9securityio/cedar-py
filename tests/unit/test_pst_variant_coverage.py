"""Audits cedar_policy::pst's enum variants against a snapshot in this repo.

Those enums are all `#[non_exhaustive]`, so an exhaustive `match` is impossible
from outside the crate and the compiler cannot report a variant `cedarpy.pst`
does not model. This reads the variant names out of the cedar-policy-core
source that `Cargo.lock` resolves to and compares them against
`pst_variants.json`, so a cedar-policy bump that adds, removes or renames one
fails here and names it.

Regenerate the snapshot with `python tests/unit/test_pst_variant_coverage.py`
after deciding what to do about the change.
"""
import json
import re
import subprocess
import typing
import unittest
from pathlib import Path

from cedarpy import pst

SNAPSHOT = Path(__file__).parent / "pst_variants.json"

# `PstConstructionError` is cedar's own error type, not a node kind cedarpy
# mirrors, so it is deliberately outside the audit.
IGNORED_ENUMS = frozenset({"PstConstructionError"})


def _core_source_dir() -> Path | None:
    """The cedar-policy-core source tree Cargo.lock resolves to, if available."""
    try:
        out = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            capture_output=True, check=True,
            cwd=Path(__file__).parents[2],
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    if not out:
        return None
    # Decoded here rather than with `text=True`, which would use the locale
    # codec: cargo's metadata is UTF-8 and is not ASCII-only, so on a Windows
    # runner the default cp1252 decode fails partway through.
    for package in json.loads(out.decode("utf-8"))["packages"]:
        if package["name"] == "cedar-policy-core":
            return Path(package["manifest_path"]).parent
    return None


def _enabled_cedar_features() -> frozenset[str]:
    """The cargo features Cargo.toml turns on for cedar-policy."""
    manifest = (Path(__file__).parents[2] / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^cedar-policy\s*=\s*\{([^}]*)\}', manifest, re.M)
    if match is None:
        return frozenset()
    features = re.search(r'features\s*=\s*\[([^\]]*)\]', match.group(1))
    if features is None:
        return frozenset()
    return frozenset(re.findall(r'"([^"]+)"', features.group(1)))


def _scrape_variants(source_dir: Path) -> dict[str, dict[str, str | None]]:
    """Map each pst enum to its variants and the cargo feature each needs.

    Reads the source, not the compiled crate, because a feature-gated variant
    does not exist in our build at all.
    """
    enums: dict[str, dict[str, str | None]] = {}
    for path in sorted((source_dir / "src" / "pst").glob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        name = None
        depth = 0
        gate = None
        for line in lines:
            if name is None:
                match = re.match(r"pub enum (\w+)", line)
                if match and match.group(1) not in IGNORED_ENUMS:
                    name = match.group(1)
                    enums[name] = {}
                    depth = 1
                    gate = None
                continue
            if depth == 1:
                feature = re.match(r'\s*#\[cfg\(feature = "([^"]+)"\)\]', line)
                if feature:
                    gate = feature.group(1)
                    continue
                variant = re.match(r"    ([A-Z]\w*)", line)
                if variant:
                    enums[name][variant.group(1)] = gate
                    gate = None
            depth += line.count("{") - line.count("}")
            if depth == 0:
                name = None
    return enums


class TestPstVariantCoverage(unittest.TestCase):
    def test_snapshot_matches_the_cedar_policy_core_source(self):
        source_dir = _core_source_dir()
        if source_dir is None:
            self.skipTest("cargo is unavailable, so the crate source cannot be read")
        scraped = _scrape_variants(source_dir)
        self.assertTrue(scraped, f"found no pst enums under {source_dir}")
        expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.assertEqual(
            expected, scraped,
            "cedar_policy::pst's variants no longer match "
            f"{SNAPSHOT.name}. Update cedarpy/pst.py and src/lib.rs for any new "
            "variant, then regenerate with "
            "`python tests/unit/test_pst_variant_coverage.py`.",
        )

    def test_every_enabled_expr_variant_is_modelled(self):
        """Which Expr variants can occur here, against the ones we model.

        A variant behind a cargo feature `Cargo.toml` does not enable cannot
        occur, so the enabled features are read from there. `Unknown` is
        excluded because `pst::Template` rejects any clause holding one. The
        modelled side is read off `cedarpy.pst.Expr`, so a node type added to
        the union without a matching Rust variant fails too.
        """
        source_dir = _core_source_dir()
        if source_dir is None:
            self.skipTest("cargo is unavailable, so the crate source cannot be read")
        enabled = _enabled_cedar_features()
        expr = _scrape_variants(source_dir)["Expr"]
        available = {
            variant for variant, gate in expr.items()
            if gate is None or gate in enabled
        } - {"Unknown"}
        # Cedar's single `Literal` variant fans out into four node types here,
        # because `bool` is a subclass of `int` and one node could not tell a
        # Bool from a Long.
        literals = {"BoolLit", "LongLit", "StringLit", "EntityLit"}
        modelled = set()
        for node in typing.get_args(pst.Expr):
            name = node.__name__
            modelled.add("Literal" if name in literals else name)
        self.assertEqual(available, modelled)


if __name__ == "__main__":
    source_dir = _core_source_dir()
    if source_dir is None:
        raise SystemExit("cargo is unavailable, cannot regenerate the snapshot")
    SNAPSHOT.write_text(
        json.dumps(_scrape_variants(source_dir), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {SNAPSHOT}")
