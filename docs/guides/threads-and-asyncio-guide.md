# Calling cedarpy from threads and asyncio

By default, a cedarpy call holds the GIL until it returns.
While it runs, no other Python thread runs: not your other worker threads, and not an asyncio event loop.
`asyncio.to_thread` does not change that, because the worker thread holds the GIL.

`validate_policies` and the constructors of the reusable handles take a keyword-only `release_gil` argument.
With `release_gil=True`, the GIL is released while Cedar works, so other Python threads run during the call:

- `validate_policies`
- `PolicySet.from_str`, `PolicySet.from_json_str`, `PolicySet.from_pst`
- `Schema.from_str`, `Schema.from_json_str`
- `Entities.from_json_str`

The result is the same either way; only which threads may run during the call changes.
The default, `False`, holds the GIL for the whole call.

## Basic usage

```python
import asyncio
from cedarpy import Schema, validate_policies

schema = Schema.from_json_str(schema_json, release_gil=True)

async def policies_are_valid(policies: str) -> bool:
    result = await asyncio.to_thread(validate_policies, policies, schema, release_gil=True)
    return result.validation_passed
```

## What releasing the GIL costs

When the Cedar work finishes, the call needs the GIL back.
If another thread is running Python code, the call waits until that thread gives it up:
typically about `sys.getswitchinterval()` (5 ms by default), sometimes longer.
For a call that takes tens of milliseconds, that wait is small.
For a call that takes microseconds, it can be hundreds of times longer than the call.

Reading the arguments and building the result still hold the GIL.
For `PolicySet.from_pst`, reading the `cedarpy.pst` nodes is most of the call, so releasing the GIL frees only a small part of it.

On free-threaded builds, `release_gil=True` detaches the call from the interpreter, so garbage collection and other stop-the-world events do not wait on it.

## When it pays off

- **Release the GIL for calls that take milliseconds or more** while other threads need to run:
  validating policies, especially templates, and building handles from large inputs.
  Validating a two-slot template (`principal in ?principal ... resource in ?resource`)
  took about 9 times longer than the same policy written as a static policy in the case study below.
- **Keep the default for calls that take microseconds**, such as building a handle from a small input.
  Beside a busy thread, each such call waits about the switch interval to resume.
- **Measure with your workload.** The trade-off depends on how long the call takes, what the other threads do,
  `sys.getswitchinterval()`, whether the interpreter is free-threaded, and the OS and CPU.

## Measurements

CPython 3.11, macOS on Apple silicon, release build.
Each call ran repeatedly for 2 s on its own, then beside one Python thread running a CPU-bound loop.
The last column is how much of its solo rate that thread kept; values a little over 100% are measurement noise.
The schemas: a synthetic one with 150 actions and 2,114 action × principal type × resource type combinations,
a 230-byte schema with two entity types, and the 142 KB production schema from the case study.

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

On its own, a call takes the same time either way.
Beside a busy thread, a long call takes about as long either way, and the busy thread keeps its full rate instead of 9–41% of it.
A short call goes from microseconds to about 6 ms: the time it waits to get the GIL back.

## Case study: validating policies in an asyncio service

A multi-tenant API service runs one asyncio event loop per process and authorizes with Cedar.
Its schema has 147 actions and about 2,150 action × principal type × resource type combinations.
Its 49 built-in policies are all two-slot templates: `permit(principal in ?principal, action in [...], resource in ?resource)`.
It caches validation results by policy and schema digest, but some validation runs inside the server:
when a policy is published, and after a cedarpy upgrade changes the schema digest.
Validating all 49 takes about 2.9 s on the machine above, about 60 ms per policy.

This test validates all 49 in `asyncio.to_thread` while the event loop runs a 5 ms ticker.
In the busy case, the loop also runs a handler that does 1 ms of CPU work and yields, in place of request handling.

| Event loop | `release_gil` | Validation took | Worst event-loop delay | Handler slices run meanwhile |
|---|---|---|---|---|
| idle | `False` | 2.83 s | 182 ms | — |
| idle | `True` | 2.83 s | 1 ms | — |
| busy | `False` | 2.89 s | 176 ms | 103 |
| busy | `True` | 2.87 s | 2 ms | 2,876 |

With the default, the event loop stops for the length of each validation call, up to 182 ms, and runs about 100 handler slices while the policies validate.
With `release_gil=True`, its worst delay is 2 ms and it runs about 28 times as many.
Validation takes the same time.
The event loop gives up the GIL each time it polls for I/O, so the validation thread got the GIL back without waiting out the switch interval,
as it does beside a thread running only CPU-bound Python code.
