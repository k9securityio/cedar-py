"""Unit tests for tests/benchmark/aggregate.py's --compare-current mode."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
AGGREGATE_PATH = REPO_ROOT / "tests" / "benchmark" / "aggregate.py"


def _load_aggregate():
    spec = importlib.util.spec_from_file_location("benchmark_aggregate", AGGREGATE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


aggregate = _load_aggregate()


def _write_run(path: Path, means_by_name: dict[str, float]) -> None:
    """Write a minimal pytest-benchmark-shaped JSON with given per-benchmark mean (seconds)."""
    path.write_text(json.dumps({
        "benchmarks": [
            {"name": name, "stats": {"mean": mean}}
            for name, mean in means_by_name.items()
        ]
    }))


def _write_baseline(path: Path, medians_by_name: dict[str, float]) -> None:
    """Write a minimal baseline JSON with per-benchmark stats.median (seconds)."""
    path.write_text(json.dumps({
        "benchmarks": [
            {"name": name, "stats": {"median": median}}
            for name, median in medians_by_name.items()
        ]
    }))


def test_compare_passes_when_within_threshold(tmp_path, capsys):
    current = tmp_path / "current"
    current.mkdir()
    # Baseline median 100μs (= 0.0001s). Current runs: 100, 101, 102 μs → median 101μs → +1% Δ.
    _write_run(current / "run1.json", {"bench_a": 0.000100})
    _write_run(current / "run2.json", {"bench_a": 0.000101})
    _write_run(current / "run3.json", {"bench_a": 0.000102})

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100})

    rc = aggregate.compare_current_to_baseline(current, baseline, threshold_pct=5.0)
    out = capsys.readouterr().out
    assert rc == 0
    assert "PASS" in out
    assert "FAIL" not in out
    assert "RESULT: PASS" in out


def test_compare_fails_when_median_exceeds_threshold(tmp_path, capsys):
    current = tmp_path / "current"
    current.mkdir()
    # Baseline 100μs. Current medians: 120μs → +20% Δ → FAIL at 5% threshold.
    _write_run(current / "run1.json", {"bench_a": 0.000118})
    _write_run(current / "run2.json", {"bench_a": 0.000120})
    _write_run(current / "run3.json", {"bench_a": 0.000122})

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100})

    rc = aggregate.compare_current_to_baseline(current, baseline, threshold_pct=5.0)
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAIL" in out
    assert "RESULT: FAIL" in out


def test_compare_passes_when_faster_than_baseline(tmp_path, capsys):
    current = tmp_path / "current"
    current.mkdir()
    # Baseline 100μs. Current median 50μs → -50% Δ → must PASS (faster never fails).
    _write_run(current / "run1.json", {"bench_a": 0.000050})
    _write_run(current / "run2.json", {"bench_a": 0.000050})

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100})

    rc = aggregate.compare_current_to_baseline(current, baseline, threshold_pct=5.0)
    out = capsys.readouterr().out
    assert rc == 0
    assert "RESULT: PASS" in out
    # Negative Δ should appear in output
    assert "-50" in out


def test_compare_skips_benchmark_missing_from_baseline(tmp_path, capsys):
    current = tmp_path / "current"
    current.mkdir()
    _write_run(current / "run1.json", {"bench_a": 0.000100, "bench_new": 0.000100})

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100})

    rc = aggregate.compare_current_to_baseline(current, baseline, threshold_pct=5.0)
    out = capsys.readouterr().out
    assert rc == 0
    assert "bench_new" in out
    assert "no baseline" in out


def test_compare_skips_benchmark_missing_from_current(tmp_path, capsys):
    current = tmp_path / "current"
    current.mkdir()
    _write_run(current / "run1.json", {"bench_a": 0.000100})

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100, "bench_gone": 0.000200})

    rc = aggregate.compare_current_to_baseline(current, baseline, threshold_pct=5.0)
    out = capsys.readouterr().out
    assert rc == 0
    assert "bench_gone" in out
    assert "no current runs" in out


def test_compare_works_with_single_run(tmp_path, capsys):
    current = tmp_path / "current"
    current.mkdir()
    _write_run(current / "run1.json", {"bench_a": 0.000101})

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100})

    rc = aggregate.compare_current_to_baseline(current, baseline, threshold_pct=5.0)
    out = capsys.readouterr().out
    assert rc == 0
    assert "N=1" in out


def test_compare_exits_when_no_run_files(tmp_path):
    current = tmp_path / "current"
    current.mkdir()

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, {"bench_a": 0.000100})

    try:
        aggregate.compare_current_to_baseline(current, baseline)
    except SystemExit as e:
        assert e.code and "no run*.json" in str(e.code)
    else:
        raise AssertionError("expected SystemExit when no run files present")


def test_compare_exits_when_baseline_missing(tmp_path):
    current = tmp_path / "current"
    current.mkdir()
    _write_run(current / "run1.json", {"bench_a": 0.000100})

    missing_baseline = tmp_path / "does_not_exist.json"

    try:
        aggregate.compare_current_to_baseline(current, missing_baseline)
    except SystemExit as e:
        assert e.code and "baseline not found" in str(e.code)
    else:
        raise AssertionError("expected SystemExit when baseline missing")
