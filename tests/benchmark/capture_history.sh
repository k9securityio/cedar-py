#!/usr/bin/env bash
# Capture release-mode pytest-benchmark data at a list of historical cedarpy
# commits. Used to maintain tests/benchmark/results/history/ — the committed
# historical perf record.
#
# Each STATES entry is "<save_prefix>:<git-ref>:<description>". All three
# fields are required. The description is used as the row label in HISTORY.md.
#
# For each state: git checkout, maturin develop --release, then RUNS× pytest
# --benchmark-save. Native pytest-benchmark JSONs land in
# tests/benchmark/results/Darwin-CPython-3.11-64bit/.
#
# Restores the starting branch on exit (success or failure).
#
# Adding a new state: append "<save_prefix>:<git-ref>:<description>" to STATES
# below and re-run. The aggregator (aggregate.py) reads descriptions from
# tests/benchmark/results/history/states-manifest.json, which this script
# writes before the capture loop.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! git diff-index --quiet HEAD --; then
  echo "ERROR: working tree has uncommitted changes; aborting" >&2
  exit 1
fi

if [ ! -d "venv-dev" ]; then
  echo "ERROR: venv-dev not found. Run 'make venv-dev' first." >&2
  exit 1
fi
# shellcheck disable=SC1091
source venv-dev/bin/activate

START_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse HEAD)"
echo "Starting on: $START_BRANCH"

STORAGE="$REPO_ROOT/tests/benchmark/results"
RUNS="${BENCHMARK_RUNS:-5}"

# save_prefix : git-ref : description  (chronological order)
# - save_prefix: pytest-benchmark save-name prefix; for tagged states use the
#   sanitized tag (dots -> underscores); for untagged commits use
#   "<descriptor>_<short-sha>"
# - git-ref: any git ref (tag, short SHA, branch tip)
# - description: row label in HISTORY.md (REQUIRED, non-empty)
STATES=(
  "v4_8_0:v4.8.0:v4.8.0"
  "v4_8_1:v4.8.1:v4.8.1"
  "pr65_6f601df:6f601df:PR65 surface invalid schema"
  "pr66_500a8d0:500a8d0:PR66 honor id annotation"
  "main_ca5d83c:ca5d83c:main_ca5d83c docs update"
  "pr75_faf92a4:faf92a4:PR75 @id via post-process"
  "v4_8_2:v4.8.2:v4.8.2"
)

# Write states-manifest.json for the aggregator to consume.
HISTORY_DIR="$STORAGE/history"
MANIFEST="$HISTORY_DIR/states-manifest.json"
mkdir -p "$HISTORY_DIR"
printf '%s\n' "${STATES[@]}" | python3 -c '
import json, sys
states = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    parts = line.split(":", 2)
    if len(parts) != 3 or not parts[2]:
        sys.exit(f"ERROR: state {line!r} is missing required description (3rd field)")
    states.append({"save_prefix": parts[0], "ref": parts[1], "description": parts[2]})
print(json.dumps(states, indent=2))
' > "$MANIFEST"
echo "wrote manifest: $MANIFEST"

restore_branch() {
  echo
  echo "===== Restoring on $START_BRANCH ====="
  git reset --hard >/dev/null 2>&1 || true
  git checkout "$START_BRANCH" >/dev/null 2>&1 || true
  echo "now on: $(git log --oneline -1 2>/dev/null || true)"
}
trap restore_branch EXIT

for state in "${STATES[@]}"; do
  IFS=':' read -r prefix ref description <<< "$state"
  echo
  echo "==================================================================="
  echo "===== STATE: $prefix (ref=$ref, desc=$description) at $(date +%H:%M:%S) ====="
  echo "==================================================================="

  git reset --hard >/dev/null
  git checkout "$ref" >/dev/null 2>&1
  echo "checked out: $(git log --oneline -1)"

  echo "---- building (release) at $(date +%H:%M:%S) ----"
  maturin develop --release 2>&1 | tail -3

  for n in $(seq 1 "$RUNS"); do
    save_name="$prefix-run$n"
    echo "  [$(date +%H:%M:%S)] run $n -> $save_name"
    pytest tests/benchmark --benchmark-only \
      --benchmark-save="$save_name" \
      --benchmark-storage="$STORAGE" \
      -q 2>&1 | tail -3
  done
done

echo
echo "===== DONE at $(date +%H:%M:%S) ====="
