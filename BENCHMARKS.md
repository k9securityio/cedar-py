# Performance Benchmarks

This document describes how to run and interpret the cedarpy performance regression test suite.

## Overview

The benchmark suite uses [pytest-benchmark](https://pytest-benchmark.readthedocs.io/) to measure
the performance of cedarpy's authorization functions:

- `is_authorized` - Single authorization request
- `is_authorized_batch` - Batch authorization requests

The benchmarks test various scenarios:
- **Policy complexity**: Simple (1 rule), medium (~4 rules), and complex (~10 rules) policies
- **Entity set sizes**: Small (~10), medium (~50), and large (~200) entities
- **Batch sizes**: 1, 5, 10, 25, 50, and 100 requests per batch
- **Input formats**: Python objects vs JSON strings
- **Realistic scenarios**: Using the sandbox_b test fixtures with schema validation

## Quick Start

```bash
# Install dev dependencies (includes pytest-benchmark)
make venv-dev
source venv-dev/bin/activate

# Run benchmarks
make benchmark

# Save results (tagged with git commit and timestamp)
make benchmark-save

# Compare against baseline (fails on significant regressions)
make benchmark-compare
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make benchmark` | Run all benchmarks with verbose output |
| `make benchmark-save` | Run benchmarks and save results to `results/out/` |
| `make benchmark-compare` | Compare against baseline, fail on regressions |

## Results Directory Structure

```
tests/benchmark/results/
├── baseline.json          # Sym-link to current baseline (you create this)
├── baseline_cedar_4.7.json # Example: committed baseline for Cedar 4.7
└── out/                   # Ephemeral results (gitignored)
    └── results.<commit>.<timestamp>.json
```

- **`results/out/`**: Ephemeral benchmark results, gitignored
- **`results/baseline.json`**: Sym-link to the baseline for comparisons (you manage this)
- **Named baselines**: Can be committed to track performance across versions

## Regression Detection

The `make benchmark-compare` target fails if performance regresses beyond thresholds:

| Metric | Threshold | Notes |
|--------|-----------|-------|
| Median | 5% | Primary measure, most stable |
| Mean | 15% | Secondary measure, more sensitive to outliers |

These thresholds were chosen because:
- **Median** is stable and reliable for detecting true regressions
- **Mean** catches regressions but allows more variance due to outlier sensitivity
- **Max/StdDev** were found too noisy for reliable CI assertions

## Regression Testing Workflow

### Creating a Baseline

1. Run benchmarks and save results:
   ```bash
   make benchmark-save
   ```

2. Review the results in `tests/benchmark/results/out/`

3. Create a named baseline (recommended for version tracking):
   ```bash
   cp tests/benchmark/results/out/results.<commit>.<timestamp>.json \
      tests/benchmark/results/<machine-and-python-details>/<results_num>_cedarpy-<cedarpy_version>.<commit>.<timestamp>.json
   ```

4. Create the baseline sym-link:
   ```bash
   cd tests/benchmark/results
   ln -sf <named-baseline> baseline.json
   ```

### Before a Cedar Engine Upgrade

1. Ensure you have a baseline for the current version:
   ```bash
   make benchmark-save
   # Copy and name the baseline appropriately
   ```

2. Record the Cedar Policy engine version:
   ```bash
   grep "cedar-policy" Cargo.toml
   ```

### After Upgrading

1. Run comparison benchmarks:
   ```bash
   make benchmark-compare
   ```

2. The command will fail if:
   - Median time increases by more than 5%
   - Mean time increases by more than 15%

3. If comparisons pass, save results for the new version:
   ```bash
   make benchmark-save
   ```

4. Update the baseline sym-link if this becomes the new baseline:
   ```bash
   cd tests/benchmark/results
   ln -sf baseline_cedar_4.8.json baseline.json
   ```

### Pre-Release Checklist

1. Verify no regressions from baseline:
   ```bash
   make benchmark-compare
   ```

2. Save results for the release:
   ```bash
   make benchmark-save
   ```

3. Document any expected performance changes in release notes

## Running Benchmarks Directly

For most use cases, prefer the Makefile targets. Direct pytest invocation is useful
for debugging or running specific tests.

### Run Specific Test Classes

```bash
# Only is_authorized benchmarks
pytest tests/benchmark -k "TestIsAuthorizedBenchmarks" --benchmark-only

# Only is_authorized_batch benchmarks
pytest tests/benchmark -k "TestIsAuthorizedBatchBenchmarks" --benchmark-only

# Single vs Batch comparison
pytest tests/benchmark -k "TestSingleVsBatchBenchmarks" --benchmark-only
```

### Run Specific Tests

```bash
# Test a specific batch size
pytest tests/benchmark -k "test_batch_size_scaling[25]" --benchmark-only
```

## Interpreting Results

### Console Output

The benchmark output shows statistics for each test (sorted by median time):

```
Name                                    Min    Median     Max     Mean   StdDev   Rounds  Iterations
----------------------------------------------------------------------------------------------------
test_simple_policy_allow            0.0001   0.0002   0.0003   0.0002   0.0001       20           1
test_complex_policy                 0.0005   0.0006   0.0012   0.0007   0.0002       20           1
```

- **Min/Median/Max/Mean**: Timing statistics in seconds
- **Median**: Most reliable measure (used for 5% regression threshold)
- **Mean**: Secondary measure (used for 15% regression threshold)
- **StdDev**: Standard deviation (lower = more consistent)
- **Rounds**: Number of benchmark iterations (minimum 20)

### Comparison Output

When comparing against a baseline:

```
Name                                   Now      Baseline    Delta    %
----------------------------------------------------------------------
test_simple_policy_allow            0.0002      0.0002   +0.0000   +2%
test_complex_policy                 0.0007      0.0008   -0.0001   -12%
```

With `--benchmark-compare-fail`, the test run fails if thresholds are exceeded.

## Benchmark Categories

### Policy Complexity Tests

| Test | Policy | Description |
|------|--------|-------------|
| `test_simple_policy_allow` | 1 permit | Basic principal/action/resource match |
| `test_simple_policy_deny` | 1 permit | Request that doesn't match |
| `test_medium_policy` | 4 rules | Multiple conditions, forbid rules |
| `test_complex_policy` | 10 rules | Complex conditions, context checks |

### Entity Set Size Tests

| Test | Entities | Description |
|------|----------|-------------|
| `test_small_entity_set` | ~10 | Minimal entity graph |
| `test_medium_entity_set` | ~50 | Typical application |
| `test_large_entity_set` | ~200 | Large entity graph |

### Batch Size Tests

| Test | Batch Size | Description |
|------|------------|-------------|
| `test_batch_size_scaling[1]` | 1 | Baseline (same as single call) |
| `test_batch_size_scaling[5]` | 5 | Small batch |
| `test_batch_size_scaling[10]` | 10 | Medium batch |
| `test_batch_size_scaling[25]` | 25 | Larger batch |
| `test_batch_size_scaling[50]` | 50 | Large batch |
| `test_batch_size_scaling[100]` | 100 | Very large batch |

### Realistic Scenario Tests

Tests using `sandbox_b` fixtures with schema validation:

| Test | Scenario |
|------|----------|
| `test_sandbox_b_view_own_photo` | User viewing their own photo |
| `test_sandbox_b_view_public_photo` | User viewing public photo |
| `test_sandbox_b_delete_with_auth` | Authenticated delete operation |
| `test_sandbox_b_batch_mixed_actions` | Batch with view/edit/comment/delete |
| `test_sandbox_b_batch_multiple_users` | Multiple users accessing resources |

## Hardware Considerations

Benchmark results vary by hardware. For consistent comparisons:

1. **Use the same machine** for baseline and comparison runs
2. **Close other applications** to reduce noise
3. **Run multiple times** and look for consistent patterns
4. **Note your hardware** when sharing results:
   - CPU model and speed
   - RAM amount
   - OS and version
   - Python version

### CI Considerations

Due to noisy neighbors and variable hardware in CI environments:

- Max and StdDev metrics are too noisy for reliable CI assertions
- Median (5%) and Mean (15%) thresholds balance sensitivity with stability
- For precise measurements, run benchmarks on dedicated developer machines

## Adding New Benchmarks

Add benchmarks to `tests/benchmark/test_benchmark_authorize.py`:

```python
class TestMyBenchmarks:
    def test_my_scenario(self, benchmark, medium_policy, medium_entities):
        """Description of what this benchmarks."""
        request = {...}

        result = benchmark(
            is_authorized, request, medium_policy, medium_entities
        )

        assert result.decision in [Decision.Allow, Decision.Deny]
```

Guidelines:
- Use descriptive test names
- Include assertions to verify correctness
- Use appropriate fixtures for your scenario
- Document what the benchmark measures
