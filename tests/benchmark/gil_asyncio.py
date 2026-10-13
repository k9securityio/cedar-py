"""Validate two-slot templates in `asyncio.to_thread` and measure the event loop.

Reproduces the shape of the case study in docs/guides/threads-and-asyncio-guide.md
with synthetic inputs: two-slot templates, each naming two actions, against the
2,114-combination schema from tests/unit/test_gil_release.py, in place of the
service's own schema and policies. For an idle and a busy event loop and each
`release_gil` setting, it validates the templates one at a time in
`asyncio.to_thread` and reports the median over `--runs` runs of:

- Validation took: the wall time to validate all the templates.
- Worst event-loop delay: a ticker coroutine sleeps 5 ms in a loop and records
  how much longer than 5 ms each sleep took. This is the largest of those.
- Handler slices run meanwhile (busy loop only): a handler coroutine does 1 ms
  of CPU-bound work and yields, in place of request handling. This counts the
  slices it completed while the templates validated.

Run it with a release build:

    maturin develop --release
    python tests/benchmark/gil_asyncio.py                 # 49 templates, 5 runs
    python tests/benchmark/gil_asyncio.py --templates 20 --runs 3

The output is a Markdown table, preceded by the environment it ran in.
This is not a pytest module: the file name does not start with `test_`, so
`pytest tests/benchmark` does not collect it.
"""
import argparse
import asyncio
import statistics
import time
from typing import List, Tuple

from cedarpy import Schema, validate_policies

from gil_contention import environment, template_schema_json

TICK = 0.005
SLICE = 0.001


def templates(count: int) -> List[str]:
    """Two-slot templates, each naming a different pair of the schema's actions."""
    return [
        f'permit(principal in ?principal, action in [Action::"a{2 * i % 150}", Action::"a{(2 * i + 1) % 150}"], '
        f'resource in ?resource);'
        for i in range(count)
    ]


async def scenario(schema: Schema, texts: List[str], release_gil: bool, busy: bool) -> Tuple[float, float, int]:
    """Validate `texts` in `asyncio.to_thread`; return how long it took, the
    worst event-loop delay, and the handler slices run meanwhile."""
    stop = asyncio.Event()
    worst = [0.0]
    slices = [0]

    async def ticker() -> None:
        while not stop.is_set():
            started = time.perf_counter()
            await asyncio.sleep(TICK)
            worst[0] = max(worst[0], time.perf_counter() - started - TICK)

    async def handler() -> None:
        while not stop.is_set():
            deadline = time.perf_counter() + SLICE
            while time.perf_counter() < deadline:
                pass
            slices[0] += 1
            await asyncio.sleep(0)

    def validate_all() -> None:
        for text in texts:
            validate_policies(text, schema, release_gil=release_gil)

    tasks = [asyncio.create_task(ticker())]
    if busy:
        tasks.append(asyncio.create_task(handler()))
    await asyncio.sleep(0.05)
    started, slices_before = time.perf_counter(), slices[0]
    await asyncio.to_thread(validate_all)
    took, slices_during = time.perf_counter() - started, slices[0] - slices_before
    stop.set()
    await asyncio.gather(*tasks)
    return took, worst[0], slices_during


async def run_all(count: int, runs: int) -> None:
    schema = Schema.from_json_str(template_schema_json())
    texts = templates(count)
    validate_policies(texts[0], schema)  # warm up
    results = {}
    for _ in range(runs):
        for busy in (False, True):
            for release_gil in (False, True):
                results.setdefault((busy, release_gil), []).append(await scenario(schema, texts, release_gil, busy))

    print(environment())
    print(f"{count} two-slot templates against the 2,114-combination schema; median of {runs} runs.")
    print()
    print("| Event loop | `release_gil` | Validation took | Worst event-loop delay | Handler slices run meanwhile |")
    print("|---|---|---|---|---|")
    for (busy, release_gil), rows in results.items():
        took, worst, slices = (statistics.median(column) for column in zip(*rows))
        print(f"| {'busy' if busy else 'idle'} | `{release_gil}` | {took:.2f} s | {worst * 1000:.0f} ms | "
              f"{f'{int(slices):,}' if busy else '—'} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--templates", type=int, default=49,
                        help="how many two-slot templates to validate (default 49)")
    parser.add_argument("--runs", type=int, default=5,
                        help="runs per setting; the table reports medians (default 5)")
    args = parser.parse_args()
    asyncio.run(run_all(args.templates, args.runs))


if __name__ == "__main__":
    main()
