"""Measure how `release_gil` changes cedarpy calls beside a busy Python thread.

Produces the Measurements table in docs/guides/threads-and-asyncio-guide.md.
For each call and each `release_gil` setting, it reports:

- Alone: the median per-call duration, calling repeatedly for `--seconds` with
  no other Python thread running.
- Beside a CPU-bound thread: the median per-call duration, calling repeatedly
  for `--seconds` while another Python thread runs a CPU-bound loop.
- The busy thread's share of its solo rate: that thread's loop iterations per
  second during the run, divided by its rate when it runs alone. The solo rate
  is measured right before each call's runs, so drift between calls does not
  skew it.

Run it with a release build:

    maturin develop --release
    python tests/benchmark/gil_contention.py            # all calls, 2 s each
    python tests/benchmark/gil_contention.py --only PolicySet --seconds 3

The output is a Markdown table, preceded by the environment it ran in.
This is not a pytest module: the file name does not start with `test_`, so
`pytest tests/benchmark` does not collect it.
"""
import argparse
import importlib.metadata
import json
import platform
import statistics
import subprocess
import sys
import sysconfig
import threading
import time
from typing import Callable, List, Tuple

from cedarpy import Entities, PolicySet, Schema, validate_policies


# =============================================================================
# Inputs
# =============================================================================

def template_schema_json() -> str:
    """A small schema shaped like a multi-tenant service's: 150 actions, each
    for 7 principal types that belong to groups and a workspace, and for one of
    20 resource types; 8 actions apply to every resource type. 2,114 action ×
    principal type × resource type combinations. Same as the validation schema
    in tests/unit/test_gil_release.py."""
    principals = [f"P{i}" for i in range(7)]
    resources = [f"R{i}" for i in range(20)]
    entity_types = {"Workspace": {}, "Group": {"memberOfTypes": ["Workspace"]}}
    entity_types |= {name: {"memberOfTypes": ["Group", "Workspace"]} for name in principals}
    entity_types |= {name: {"memberOfTypes": ["Workspace"]} for name in resources}
    actions = {
        f"a{i}": {"appliesTo": {"principalTypes": principals,
                                "resourceTypes": resources if i < 8 else [resources[i % 20]]}}
        for i in range(150)
    }
    return json.dumps({"": {"entityTypes": entity_types, "actions": actions}})


TWO_SLOT_TEMPLATE = 'permit(principal in ?principal, action in [Action::"a0", Action::"a1"], resource in ?resource);'


def small_schema_json() -> str:
    """Two entity types and one action."""
    return json.dumps({"": {
        "entityTypes": {"User": {}, "Photo": {"shape": {"type": "Record", "attributes": {
            "owner": {"type": "Entity", "name": "User"}}}}},
        "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Photo"]}}},
    }})


def large_schema_json(type_count: int = 30) -> str:
    """300 actions that each apply to every pair of `type_count` entity types.
    About 140 KB at the default 30 types."""
    names = [f"T{i}" for i in range(type_count)]
    return json.dumps({"": {
        "entityTypes": {name: {"memberOfTypes": []} for name in names},
        "actions": {
            f"act{i}": {"appliesTo": {"principalTypes": names, "resourceTypes": names}}
            for i in range(300)
        },
    }})


def entities_json(users: int) -> str:
    """`users` users spread over up to 100 groups, plus the groups."""
    groups = min(100, users)
    return json.dumps(
        [{"uid": {"type": "User", "id": f"u{i}"}, "attrs": {"x": i},
          "parents": [{"type": "Group", "id": f"g{i % groups}"}]} for i in range(users)]
        + [{"uid": {"type": "Group", "id": f"g{i}"}, "attrs": {}, "parents": []} for i in range(groups)]
    )


def policies(count: int) -> str:
    return "\n".join(
        f'permit(principal == User::"u{i}", action == Action::"a{i}", resource) when {{ resource.x == {i} }};'
        for i in range(count)
    )


def size_label(text: str) -> str:
    size = len(text.encode())
    return f"{size} B" if size < 1000 else f"{size / 1000:.0f} KB"


def cases() -> List[Tuple[str, Callable[[bool], object]]]:
    """(label, call) pairs; each call takes `release_gil`."""
    template_schema = Schema.from_json_str(template_schema_json())
    small_schema, large_schema = small_schema_json(), large_schema_json()
    small_entities, large_entities = entities_json(5), entities_json(20_000)
    out = [
        ("`validate_policies`, one two-slot template, 2,114-combination schema",
         lambda rg: validate_policies(TWO_SLOT_TEMPLATE, template_schema, release_gil=rg)),
        (f"`Schema.from_json_str`, {size_label(small_schema)}",
         lambda rg: Schema.from_json_str(small_schema, release_gil=rg)),
        (f"`Schema.from_json_str`, {size_label(large_schema)}",
         lambda rg: Schema.from_json_str(large_schema, release_gil=rg)),
        (f"`Entities.from_json_str`, {len(json.loads(small_entities)):,} entities",
         lambda rg: Entities.from_json_str(small_entities, release_gil=rg)),
        (f"`Entities.from_json_str`, {len(json.loads(large_entities)):,} entities",
         lambda rg: Entities.from_json_str(large_entities, release_gil=rg)),
    ]
    for count in (10, 100, 300, 1_000, 3_000):
        text = policies(count)
        out.append((f"`PolicySet.from_str`, {count:,} policies",
                    lambda rg, text=text: PolicySet.from_str(text, release_gil=rg)))
    return out


# =============================================================================
# Measurement
# =============================================================================

def _spinner(stop: threading.Event, counter: List[int]) -> threading.Thread:
    """A thread that runs a CPU-bound Python loop until `stop` is set."""
    def spin() -> None:
        n = 0
        while not stop.is_set():
            n += 1
        counter[0] = n
    return threading.Thread(target=spin)


def solo_spin_rate(seconds: float) -> float:
    """The busy thread's loop iterations per second with nothing else running."""
    stop, counter = threading.Event(), [0]
    thread = _spinner(stop, counter)
    thread.start()
    time.sleep(seconds)
    stop.set()
    thread.join()
    return counter[0] / seconds


def run(call: Callable[[], object], seconds: float, busy: bool) -> Tuple[float, float]:
    """Call `call` repeatedly for `seconds`, optionally beside a busy thread.
    Return the median per-call duration in seconds and the busy thread's loop
    iterations per second (0 when `busy` is False)."""
    stop, counter = threading.Event(), [0]
    spinner = _spinner(stop, counter) if busy else None
    if spinner:
        spinner.start()
    durations = []
    started = time.perf_counter()
    deadline = started + seconds
    while True:
        t = time.perf_counter()
        if t >= deadline:
            break
        call()
        durations.append(time.perf_counter() - t)
    elapsed = time.perf_counter() - started
    stop.set()
    if spinner:
        spinner.join()
    return statistics.median(durations), counter[0] / elapsed


def fmt_duration(seconds: float) -> str:
    return f"{seconds * 1e6:.0f} µs" if seconds < 1e-3 else f"{seconds * 1e3:.1f} ms"


def environment() -> str:
    cpu = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        try:
            cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                 capture_output=True, text=True, check=True).stdout.strip() or cpu
        except (OSError, subprocess.CalledProcessError):
            pass
    free_threaded = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    return (
        f"cedarpy {importlib.metadata.version('cedarpy')}, "
        f"{platform.python_implementation()} {platform.python_version()}"
        f"{' (free-threaded)' if free_threaded else ''}, "
        f"{platform.system()} {platform.release()} {platform.machine()}, {cpu}, "
        f"switch interval {sys.getswitchinterval() * 1000:g} ms"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seconds", type=float, default=2.0,
                        help="how long to call each function in each run (default 2)")
    parser.add_argument("--only", default="",
                        help="run only the calls whose label contains this text")
    args = parser.parse_args()

    print(environment())
    print(f"Median per-call duration over {args.seconds:g} s runs.")
    print()
    print("| Call | `release_gil` | Alone | Beside a CPU-bound thread | Busy thread's share of its solo rate |")
    print("|---|---|---|---|---|")
    for label, call in cases():
        if args.only not in label:
            continue
        solo = solo_spin_rate(args.seconds)
        for release_gil in (False, True):
            bound = lambda: call(release_gil)
            for _ in range(3):
                bound()  # warm up
            alone, _ = run(bound, args.seconds, busy=False)
            beside, rate = run(bound, args.seconds, busy=True)
            name = label if not release_gil else ""
            print(f"| {name} | `{release_gil}` | {fmt_duration(alone)} | {fmt_duration(beside)} | {rate / solo:.0%} |",
                  flush=True)


if __name__ == "__main__":
    main()
