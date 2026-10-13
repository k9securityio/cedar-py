# Calling cedarpy from threads and asyncio

On standard (GIL) builds of CPython, a cedarpy call holds the GIL by default until it returns.
No other Python thread runs during the call, including your other worker threads and an asyncio event loop.
`asyncio.to_thread` does not change that, because the worker thread holds the GIL.

`validate_policies` and the constructors of the reusable handles take a keyword-only `release_gil` argument:

- `validate_policies`
- `PolicySet.from_str`, `PolicySet.from_json_str`, `PolicySet.from_pst`
- `Schema.from_str`, `Schema.from_json_str`
- `Entities.from_json_str`

With `release_gil=True`, the GIL is released while Cedar works, so other Python threads run during the call.
The default, `False`, holds the GIL for the whole call.
Both settings return the same result and raise the same errors.

## Basic usage

```python
import asyncio
from cedarpy import Schema, validate_policies

async def load_schema(schema_json: str) -> Schema:
    return await asyncio.to_thread(Schema.from_json_str, schema_json, release_gil=True)

async def policies_are_valid(policies: str, schema: Schema) -> bool:
    result = await asyncio.to_thread(validate_policies, policies, schema, release_gil=True)
    return result.validation_passed
```

## What releasing the GIL costs

When the Cedar work finishes, the call needs the GIL back.
If another thread is running Python code, the call waits until that thread gives it up.
That wait is typically about `sys.getswitchinterval()` (5 ms by default), sometimes longer.
A call longer than the switch interval waits about as long with the default, because that other thread asks for the GIL during the call (see Measurements).
For a call that takes microseconds, the wait can be hundreds of times longer than the call.

Reading the arguments and building the result still hold the GIL.
For `PolicySet.from_pst`, reading the `cedarpy.pst` nodes is most of the call, so releasing the GIL frees only a small part of it.

On free-threaded builds, other threads run during the call either way.
`release_gil=True` also detaches the call from the interpreter, so garbage collection and other stop-the-world events do not wait on it.

## When it pays off

Consider releasing the GIL for calls that take longer than the switch interval when other threads need to run. That includes validating policies, especially templates, and building handles from large inputs. In the case study below, validating a two-slot template (`principal in ?principal ... resource in ?resource`) took about 9 times longer than the same policy written as a static policy.

Keep the default for calls that take less than the switch interval, such as building a handle from a small input. With `release_gil=True`, each such call waits about the switch interval to resume when it runs alongside a busy thread.

Measure with your workload. The trade-off depends on how long the call takes, what the other threads do, your latency requirements (minimum, average and maximum),
`sys.getswitchinterval()`, whether the interpreter is free-threaded, and the OS and CPU.

## Measurements

CPython 3.11.15 on macOS 26.4 with an Apple M4 Max (16 cores), release build.
Each call ran repeatedly for 2 seconds on its own, then beside one Python thread running a CPU-bound loop.
Each latency is the median per-call duration over its 2-second run.
The Alone column is each call's duration with no other Python thread running.
The Beside a CPU-bound thread column is each call's duration while that busy thread runs.
The last column is how much of its solo rate the busy thread kept.
Values a little over 100% are possibly measurement noise.
The schemas are a synthetic one with 150 actions and 2,114 action × principal type × resource type combinations,
a 230-byte schema with two entity types, and the 142 KB schema from the case study.

| Call | `release_gil` | Alone | Beside a CPU-bound thread | Busy thread's share of its solo rate |
|---|---|---|---|---|
| `validate_policies`, one two-slot template, 2,114-combination schema | `False` | 22.8 ms | 29.2 ms | 21% |
| | `True` | 22.9 ms | 29.5 ms | 101% |
| `Schema.from_json_str`, 230 B | `False` | 48 µs | 48 µs | 50% |
| | `True` | 49 µs | 6.3 ms | 101% |
| `Schema.from_json_str`, 142 KB | `False` | 9.7 ms | 15.7 ms | 41% |
| | `True` | 9.6 ms | 16.6 ms | 103% |
| `Entities.from_json_str`, 10 entities | `False` | 12 µs | 12 µs | 57% |
| | `True` | 13 µs | 6.3 ms | 108% |
| `Entities.from_json_str`, 20,100 entities | `False` | 85.2 ms | 91.0 ms | 9% |
| | `True` | 85.1 ms | 94.9 ms | 102% |

With no other thread running, a call takes the same time whether it holds or releases the GIL.

Beside a busy thread, a call longer than the switch interval waits about one switch interval for the GIL either way.
That is why each long call takes about 6–10 ms longer beside the busy thread than alone, with either setting.
With the default, the busy thread asks for the GIL during the call, so the caller hands the GIL over after the call returns and waits to get it back.
With `release_gil=True`, the caller waits to get the GIL back when the Cedar work finishes.
The flag changes what the busy thread does during the call.
With the default, the busy thread stops for the whole call and keeps only 9–41% of its rate.
With `release_gil=True`, it keeps running at its full rate.

A short call finishes before the busy thread asks for the GIL.
With the default, it takes the same time beside the busy thread as alone, and the two threads take turns with the GIL.
With `release_gil=True`, it gives up the GIL on every call and waits about 6 ms to get it back, so it goes from microseconds to about 6 ms.

To produce results for a similar workload on your own machine, run `make benchmark-gil` from a cedar-py source checkout.
It runs `tests/benchmark/gil_contention.py`, which measures these calls and `PolicySet.from_str` with synthetic inputs in place of the case study's schema.
It reports the median per-call duration and the environment it ran in.

## Case study: validating policies in an asyncio service

A multi-tenant API service runs one asyncio event loop per process and authorizes with Cedar.
The schema in this test is the service's built-in catalog: 124 actions and 2,030 action × principal type × resource type combinations, 142 KB as Cedar JSON.
Its 49 built-in policies are all two-slot templates: `permit(principal in ?principal, action in [...], resource in ?resource)`.
It caches validation results by policy and schema digest.
Validation still runs inside the server when a policy is published and after a cedarpy upgrade changes the schema digest.
Validating all 49 takes about 3 seconds on the machine above, about 60 ms per policy.
Each template takes about 9 times longer to validate than the same policy written as a static policy.

This test validates all 49 in `asyncio.to_thread`.
Meanwhile, a ticker coroutine on the event loop sleeps 5 ms in a loop and records how much longer than 5 ms each sleep took.
The worst event-loop delay in the table is the largest of those.
In the busy case, the loop also runs a handler that does 1 ms of CPU work and yields, in place of request handling.
The last column counts the slices it completed while the policies validated.
Each value is the median of 5 runs.

| Event loop | `release_gil` | Validation took | Worst event-loop delay | Handler slices run meanwhile |
|---|---|---|---|---|
| idle | `False` | 3.13 s | 197 ms | — |
| idle | `True` | 3.09 s | 3 ms | — |
| busy | `False` | 3.12 s | 196 ms | 53 |
| busy | `True` | 3.03 s | 5 ms | 2,952 |

With the default, the event loop stops for the length of each validation call, up to 197 ms, and runs about one handler slice between calls.
With `release_gil=True`, its worst delay is 5 ms and it runs about 56 times as many slices.
Validation takes about the same time.
The event loop gives up the GIL each time it polls for I/O.
So the validation thread got the GIL back without waiting out the switch interval, unlike when running beside a thread that never blocks, as in the measurements above.

To reproduce this shape on your own machine, run `make benchmark-gil-asyncio` from a cedar-py source checkout.
It runs `tests/benchmark/gil_asyncio.py`, which validates 49 synthetic two-slot templates against the 2,114-combination schema from the Measurements table, in place of the service's schema and policies, and reports the same columns.
Each synthetic template validates in about 23 ms, so its delays are shorter than the service's.
On the machine above, its worst event-loop delay was 45 ms with the default and 1 ms with `release_gil=True`, and the busy loop ran 53 handler slices with the default and 1,146 with `release_gil=True`.
