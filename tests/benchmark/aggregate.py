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


def label_for(meta: dict, save_prefix: str) -> tuple[str, str | None]:
    """Return (label, note) for the markdown row.

    label is human-readable: tag if any; else short SHA + concise note.
    For GitHub merge commits, the note is "PR #N: <body first line>" so the
    label carries the PR title rather than the boilerplate "Merge pull request
    #N" subject. Falls back to "PR #N merge" if the body is empty.
    """
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
        label, note = label_for(meta, prefix)
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
        if path.name == "manifest.json":
            continue
        summaries.append(json.loads(path.read_text()))

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


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=["a", "b", "ab"], default="ab",
                   help="run phase A (raw → per-commit JSON), phase B (per-commit JSON → markdown), or both (default)")
    args = p.parse_args()

    if "a" in args.phase:
        phase_a()
    if "b" in args.phase:
        phase_b()
    return 0


if __name__ == "__main__":
    sys.exit(main())
