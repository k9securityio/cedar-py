#!/usr/bin/env python3
"""Aggregate cedarpy benchmark history.

Two phases:

  Phase A: read native pytest-benchmark JSONs from
    tests/benchmark/results/Darwin-CPython-3.11-64bit/
  produced by capture_history.sh, group by save-prefix (everything before
  '-runN'), compute per-benchmark median/max/min/stdev across runs, and write
  one summary JSON per commit to:
    tests/benchmark/results/history/<filename>.json

  Phase B: read all tests/benchmark/results/history/*.json (excluding
  manifest), order by commit author date, render
    tests/benchmark/results/HISTORY.md
  with one section per benchmark and Δ vs the earliest state (typically
  v4.8.0).

State discovery is filename-driven. Adding a new state means appending it to
capture_history.sh's STATES list and re-running; aggregate.py picks it up
automatically.

Usage:
  python tests/benchmark/aggregate.py             # both phases
  python tests/benchmark/aggregate.py --phase a   # raw → per-commit JSON only
  python tests/benchmark/aggregate.py --phase b   # per-commit JSON → markdown only
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "tests" / "benchmark" / "results"
NATIVE_DIR = RESULTS_DIR / "Darwin-CPython-3.11-64bit"
HISTORY_DIR = RESULTS_DIR / "history"
HISTORY_MD = RESULTS_DIR / "HISTORY.md"
MANIFEST_PATH = HISTORY_DIR / "states-manifest.json"


def median_baseline_path(save_prefix: str) -> Path:
    """Default output path for build_baseline_from_state, per save_prefix."""
    return RESULTS_DIR / f"baseline-{save_prefix}-median.json"

# Native pytest-benchmark filename formats produced by --benchmark-save:
#   <NNNN>_<save-name>.json                                   (5.x default)
#   <NNNN>_<save-name>.<vcs-id>.<YYYYMMDD_HHMMSS>.json        (legacy autosave)
# where save-name = "<save-prefix>-run<N>".
NATIVE_FILE_RE = re.compile(
    r"^\d{4}_(?P<save_name>.+?)(?:\.(?P<vcs>[0-9a-f]+)\.(?P<ts>\d{8}_\d{6}))?\.json$"
)
SAVE_NAME_RE = re.compile(r"^(?P<prefix>.+)-run(?P<n>\d+)$")


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=REPO_ROOT, text=True
    ).strip()


def discover_native_runs() -> dict[str, list[Path]]:
    """Map save_prefix -> list of native JSON file paths."""
    by_prefix: dict[str, list[Path]] = {}
    if not NATIVE_DIR.is_dir():
        return by_prefix
    for path in sorted(NATIVE_DIR.iterdir()):
        m = NATIVE_FILE_RE.match(path.name)
        if not m:
            continue
        save_name = m.group("save_name")
        sm = SAVE_NAME_RE.match(save_name)
        if not sm:
            # save without a -runN suffix (e.g., legacy single-run saves)
            continue
        by_prefix.setdefault(sm.group("prefix"), []).append(path)
    return by_prefix


def commit_metadata(sha: str) -> dict:
    """Return {sha, short_sha, date, subject, body_first_line, tag} for a commit.

    body_first_line is the first non-empty line of the commit body, used to
    pull the PR title out of GitHub merge commits (whose subject is the
    boilerplate "Merge pull request #N from ...").
    """
    info = git(
        "log", "-1",
        "--pretty=format:%H%x1f%h%x1f%aI%x1f%s%x1f%b",
        sha,
    ).split("\x1f")
    long_sha, short_sha, iso_date, subject, body = info
    # Author date as YYYY-MM-DD
    date = iso_date.split("T", 1)[0]
    # First non-empty line of the body (PR title for GitHub merges)
    body_first_line = next(
        (line.strip() for line in body.splitlines() if line.strip()),
        "",
    )
    # Tag pointing exactly at this commit (if any)
    try:
        tag = git("tag", "--points-at", long_sha).split("\n", 1)[0] or None
    except subprocess.CalledProcessError:
        tag = None
    if tag == "":
        tag = None
    return {
        "sha": long_sha,
        "short_sha": short_sha,
        "date": date,
        "subject": subject,
        "body_first_line": body_first_line,
        "tag": tag,
    }


def load_state_manifest() -> dict[str, dict]:
    """Load states-manifest.json (written by capture_history.sh) keyed by save_prefix."""
    if not MANIFEST_PATH.exists():
        return {}
    data = json.loads(MANIFEST_PATH.read_text())
    return {entry["save_prefix"]: entry for entry in data}


def label_for(meta: dict, save_prefix: str, description: str | None) -> tuple[str, str | None]:
    """Return (label, note) for the markdown row.

    The label is the curated description from states-manifest.json. If the
    description is missing (manifest absent or save_prefix not listed), fall
    back to the prior auto-derivation: tag if any; else short SHA + concise
    note from the merge-commit body.
    """
    if description:
        return description, description

    tag = meta["tag"]
    body_first_line = meta.get("body_first_line", "")
    note: str | None = None
    m = re.search(r"Merge pull request #(\d+)", meta["subject"])
    if m:
        if body_first_line:
            note = f"PR #{m.group(1)}: {body_first_line}"
        else:
            note = f"PR #{m.group(1)} merge"
    elif tag:
        note = "tagged release"
    if tag:
        return tag, note
    if note:
        return f"{meta['short_sha']} ({note})", note
    return meta["short_sha"], None


def filename_for(meta: dict) -> str:
    """Return the per-commit history JSON filename: tag.json or short_sha.json."""
    if meta["tag"]:
        return f"{meta['tag']}.json"
    return f"{meta['short_sha']}.json"


def per_benchmark_stats(runs: list[Path]) -> dict[str, dict]:
    """For each benchmark name, compute median/max/min/stdev of the per-run mean."""
    means_by_name: dict[str, list[float]] = {}
    for path in runs:
        data = json.loads(path.read_text())
        for b in data["benchmarks"]:
            means_by_name.setdefault(b["name"], []).append(b["stats"]["mean"])
    out: dict[str, dict] = {}
    for name, means in sorted(means_by_name.items()):
        if not means:
            continue
        # All times stored in microseconds for legibility.
        means_us = [m * 1_000_000 for m in means]
        rec = {
            "median_us": round(statistics.median(means_us), 2),
            "max_us":    round(max(means_us), 2),
            "min_us":    round(min(means_us), 2),
            "n_runs":    len(means_us),
        }
        if len(means_us) >= 2:
            rec["stdev_us"] = round(statistics.stdev(means_us), 2)
        out[name] = rec
    return out


def phase_a() -> list[Path]:
    """Build per-commit summary JSONs from native run JSONs.

    Returns the list of summary JSON files written.
    """
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    manifest = load_state_manifest()
    by_prefix = discover_native_runs()
    if not by_prefix:
        print(f"warning: no matching native JSONs found in {NATIVE_DIR}")
        return []

    written: list[Path] = []
    for prefix, runs in sorted(by_prefix.items()):
        # All runs in a group should share a vcs id; use the first.
        first = json.loads(runs[0].read_text())
        sha = first.get("commit_info", {}).get("id") or "HEAD"

        meta = commit_metadata(sha)
        manifest_entry = manifest.get(prefix)
        description = manifest_entry.get("description") if manifest_entry else None
        label, note = label_for(meta, prefix, description)
        machine = first.get("machine_info", {})

        summary = {
            "commit": {
                "sha":       meta["sha"],
                "short_sha": meta["short_sha"],
                "tag":       meta["tag"],
                "label":     label,
                "date":      meta["date"],
                "subject":   meta["subject"],
                "note":      note,
            },
            "build": {
                "mode":                 "release",
                "python_implementation": machine.get("python_implementation"),
                "python_version":        machine.get("python_version"),
                "platform":              "Darwin-CPython-3.11-64bit",
            },
            "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "save_prefix": prefix,
            "source_runs": [p.name for p in runs],
            "benchmarks":  per_benchmark_stats(runs),
        }

        out_path = HISTORY_DIR / filename_for(meta)
        out_path.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"phase A: wrote {out_path.relative_to(REPO_ROOT)} ({len(runs)} runs)")
        written.append(out_path)
    return written


def fmt_us(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.0f}"


def fmt_pct(now: float | None, base: float | None) -> str:
    if now is None or base is None or base <= 0:
        return "—"
    delta = (now - base) / base * 100
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.1f}%"


def phase_b() -> Path:
    """Render HISTORY.md from history/*.json."""
    if not HISTORY_DIR.is_dir():
        print(f"error: {HISTORY_DIR} does not exist; run phase A first", file=sys.stderr)
        sys.exit(1)

    summaries = []
    for path in sorted(HISTORY_DIR.glob("*.json")):
        if path == MANIFEST_PATH:
            continue
        data = json.loads(path.read_text())
        # Skip anything that isn't a per-commit summary (e.g., other configs).
        if not isinstance(data, dict) or "commit" not in data:
            continue
        summaries.append(data)

    if not summaries:
        print(f"error: no per-commit summaries in {HISTORY_DIR}", file=sys.stderr)
        sys.exit(1)

    summaries.sort(key=lambda s: s["commit"]["date"])
    baseline = summaries[0]
    baseline_label = baseline["commit"]["label"]

    all_benchmarks = sorted({b for s in summaries for b in s["benchmarks"]})

    # Run counts may vary across states (e.g., if BENCHMARK_RUNS was changed
    # between captures). Surface a single N when uniform; otherwise say so.
    n_runs_set = {
        stats["n_runs"]
        for s in summaries for stats in s["benchmarks"].values()
        if "n_runs" in stats
    }
    if len(n_runs_set) == 1:
        n_runs_phrase = f"N={next(iter(n_runs_set))}"
    elif n_runs_set:
        n_runs_phrase = f"N varies ({min(n_runs_set)}–{max(n_runs_set)}; see per-commit JSON)"
    else:
        n_runs_phrase = "N runs per commit"

    lines: list[str] = []
    lines.append("# cedarpy benchmark history\n")
    lines.append(
        f"Median and max of pytest-benchmark per-run mean across {n_runs_phrase} "
        "release-mode runs per commit. Times in microseconds. Δ columns are vs "
        f"`{baseline_label}` (the earliest state in the record).\n"
    )
    lines.append(
        "Generated by `tests/benchmark/aggregate.py`. Source per-commit summaries "
        "live in `tests/benchmark/results/history/`. Native run JSONs live in "
        "`tests/benchmark/results/Darwin-CPython-3.11-64bit/`.\n"
    )

    for bench in all_benchmarks:
        lines.append(f"\n## `{bench}`\n")
        lines.append("| Commit | Date | Median (μs) | Δ median | Max (μs) | Δ max |")
        lines.append("|---|---|---|---|---|---|")

        ref_median = baseline["benchmarks"].get(bench, {}).get("median_us")
        ref_max    = baseline["benchmarks"].get(bench, {}).get("max_us")
        for s in summaries:
            stats = s["benchmarks"].get(bench)
            commit = s["commit"]
            label = commit["label"]
            date = commit["date"]
            if not stats:
                lines.append(f"| {label} | {date} | — | — | — | — |")
                continue
            med = stats.get("median_us")
            mx  = stats.get("max_us")
            delta_median = "—" if s is baseline else fmt_pct(med, ref_median)
            delta_max    = "—" if s is baseline else fmt_pct(mx,  ref_max)
            lines.append(
                f"| {label} | {date} | {fmt_us(med)} | {delta_median} | {fmt_us(mx)} | {delta_max} |"
            )

    HISTORY_MD.write_text("\n".join(lines) + "\n")
    print(f"phase B: wrote {HISTORY_MD.relative_to(REPO_ROOT)}")
    return HISTORY_MD


def build_baseline_from_state(save_prefix: str, output_path: Path | None = None) -> Path:
    """Synthesize a baseline JSON from the median of N runs for a given save_prefix.

    Writes to `tests/benchmark/results/baseline-<save_prefix>-median.json` by
    default; override with output_path. Does NOT touch the existing
    tests/benchmark/results/baseline.json — that file is preserved for the
    maintainer to swap in deliberately if desired.

    Produces a pytest-benchmark-shaped JSON whose per-benchmark numeric stats
    are the median across all available native runs of save_prefix. The first
    run is used as a structural template (machine_info, commit_info, etc.);
    only the per-benchmark stats fields are replaced with cross-run medians.

    The result represents the central tendency of save_prefix's perf rather
    than the noise of any single run, and is suitable as a stable reference
    for `make benchmark-compare`.
    """
    if output_path is None:
        output_path = median_baseline_path(save_prefix)
    by_prefix = discover_native_runs()
    if save_prefix not in by_prefix:
        sys.exit(
            f"error: no runs found for save_prefix {save_prefix!r}; "
            f"available: {sorted(by_prefix.keys())}"
        )
    run_paths = by_prefix[save_prefix]
    runs = [json.loads(p.read_text()) for p in run_paths]
    n = len(runs)

    # Use the first run as a structural template.
    baseline = json.loads(run_paths[0].read_text())

    # Index per-benchmark stats by name across runs.
    by_name: dict[str, list[dict]] = {}
    for run in runs:
        for b in run["benchmarks"]:
            by_name.setdefault(b["name"], []).append(b)

    # For each benchmark in the template, replace each numeric stats field
    # with the cross-run median.
    for bench in baseline["benchmarks"]:
        same_name = by_name.get(bench["name"], [])
        if not same_name:
            continue
        for field in list(bench["stats"]):
            if not isinstance(bench["stats"][field], (int, float)):
                continue
            values = [b["stats"][field] for b in same_name
                      if isinstance(b["stats"].get(field), (int, float))]
            if values:
                bench["stats"][field] = statistics.median(values)
        # ops is 1/mean by convention; recompute for consistency.
        if bench["stats"].get("mean", 0) > 0:
            bench["stats"]["ops"] = 1.0 / bench["stats"]["mean"]

    # Provenance marker so future readers know this isn't a raw single-run capture.
    baseline["_synthesized"] = {
        "from_save_prefix": save_prefix,
        "n_runs":           n,
        "method":           "per-stats-field median across runs",
        "generated_at":     dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "source_runs":      [p.name for p in run_paths],
    }

    output_path.write_text(json.dumps(baseline, indent=2) + "\n")
    print(f"wrote {output_path.relative_to(REPO_ROOT)} from {n} runs of {save_prefix!r}")
    return output_path


DEFAULT_CURRENT_DIR = RESULTS_DIR / "current"
BASELINE_PATH = RESULTS_DIR / "baseline.json"
DEFAULT_THRESHOLD_PCT = 5.0


def _rel(path: Path) -> str:
    """Path relative to REPO_ROOT if possible, else absolute. For display only."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _load_current_runs(current_dir: Path) -> dict[str, list[float]]:
    """Return per-benchmark list of per-run mean times (μs) from current_dir/run*.json."""
    run_files = sorted(current_dir.glob("run*.json"))
    if not run_files:
        sys.exit(
            f"error: no run*.json files in {_rel(current_dir)}. "
            f"Run `bash tests/benchmark/run_current.sh` first."
        )
    means_by_name: dict[str, list[float]] = {}
    for path in run_files:
        data = json.loads(path.read_text())
        for b in data["benchmarks"]:
            means_by_name.setdefault(b["name"], []).append(b["stats"]["mean"] * 1_000_000)
    return means_by_name


def _load_baseline_medians(baseline_path: Path) -> dict[str, float]:
    """Return per-benchmark baseline median time (μs) from baseline.json's stats.median field."""
    if not baseline_path.exists():
        sys.exit(
            f"error: baseline not found at {_rel(baseline_path)}. "
            f"Symlink baseline.json to a baseline-<state>-median.json first."
        )
    data = json.loads(baseline_path.read_text())
    return {b["name"]: b["stats"]["median"] * 1_000_000 for b in data["benchmarks"]}


def compare_current_to_baseline(
    current_dir: Path = DEFAULT_CURRENT_DIR,
    baseline_path: Path = BASELINE_PATH,
    threshold_pct: float = DEFAULT_THRESHOLD_PCT,
) -> int:
    """Compare median across N current runs against baseline median per benchmark.

    Gates on median Δ only (no mean threshold, per #69 goal 3). Faster-than-
    baseline never fails. Prints a per-benchmark PASS/FAIL summary table for
    both passing and failing outcomes. Returns 0 if all benchmarks pass, 1 if
    any benchmark's median Δ exceeds threshold_pct.
    """
    current_means = _load_current_runs(current_dir)
    baseline_medians = _load_baseline_medians(baseline_path)

    n_runs = max((len(v) for v in current_means.values()), default=0)
    all_names = sorted(set(current_means) | set(baseline_medians))

    rows: list[tuple[str, float | None, float | None, float | None, str]] = []
    any_fail = False
    skipped_warnings: list[str] = []

    for name in all_names:
        means = current_means.get(name)
        baseline_med = baseline_medians.get(name)
        if means is None:
            skipped_warnings.append(f"  {name}: present in baseline but no current runs — skipped")
            continue
        if baseline_med is None or baseline_med <= 0:
            skipped_warnings.append(f"  {name}: present in current runs but no baseline — skipped")
            continue
        cur_med = statistics.median(means)
        delta_pct = (cur_med - baseline_med) / baseline_med * 100
        status = "FAIL" if delta_pct > threshold_pct else "PASS"
        if status == "FAIL":
            any_fail = True
        rows.append((name, baseline_med, cur_med, delta_pct, status))

    name_w = max((len(r[0]) for r in rows), default=10)
    name_w = max(name_w, len("Benchmark"))
    print()
    print(f"{'Benchmark':<{name_w}}  {'Baseline (μs)':>13}  {'Median (μs)':>11}  {'Δ median':>9}  Status")
    print(f"{'-' * name_w}  {'-' * 13}  {'-' * 11}  {'-' * 9}  ------")
    for name, base, cur, delta, status in rows:
        print(
            f"{name:<{name_w}}  {fmt_us(base):>13}  {fmt_us(cur):>11}  "
            f"{fmt_pct(cur, base):>9}  {status}"
        )

    if skipped_warnings:
        print("\nwarnings:")
        for w in skipped_warnings:
            print(w)

    print(
        f"\nN={n_runs} current runs vs {_rel(baseline_path)}; "
        f"threshold: median Δ > {threshold_pct:g}% fails"
    )
    if any_fail:
        print("RESULT: FAIL — one or more benchmarks regressed beyond threshold")
        return 1
    print("RESULT: PASS")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=["a", "b", "ab"], default="ab",
                   help="run phase A (raw → per-commit JSON), phase B (per-commit JSON → markdown), or both (default)")
    p.add_argument("--build-baseline-from", metavar="SAVE_PREFIX",
                   help="alternative mode: synthesize baseline.json from the median of <SAVE_PREFIX>'s runs (skips phases A/B)")
    p.add_argument("--compare-current", nargs="?", const=str(DEFAULT_CURRENT_DIR),
                   metavar="DIR",
                   help=f"alternative mode: compare run*.json in DIR (default {DEFAULT_CURRENT_DIR.relative_to(REPO_ROOT)}) "
                        f"against baseline.json on median Δ; exits non-zero on regression")
    p.add_argument("--threshold-pct", type=float, default=DEFAULT_THRESHOLD_PCT,
                   help=f"median Δ regression threshold percent (default {DEFAULT_THRESHOLD_PCT}); used with --compare-current")
    args = p.parse_args()

    if args.compare_current:
        return compare_current_to_baseline(
            current_dir=Path(args.compare_current),
            threshold_pct=args.threshold_pct,
        )

    if args.build_baseline_from:
        build_baseline_from_state(args.build_baseline_from)
        return 0

    if "a" in args.phase:
        phase_a()
    if "b" in args.phase:
        phase_b()
    return 0


if __name__ == "__main__":
    sys.exit(main())
