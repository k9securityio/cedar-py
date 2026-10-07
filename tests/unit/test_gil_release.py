"""cedarpy releases the GIL while the Cedar engine works.

Each test runs one cedarpy call while a second Python thread spins and records
the longest stretch it went without running. A call that held the GIL for its
whole duration would stall that thread for about as long as the call took; a
call that releases it stalls the thread only while converting its arguments and
results.
"""
import json
import threading
import time
import unittest

from parameterized import parameterized

import cedarpy
from cedarpy import Entities, PolicySet, Schema


def _longest_stall(call) -> tuple[float, float]:
    """Run `call` while another thread spins; return the call's duration and
    the other thread's longest gap between iterations, both in seconds."""
    stop = threading.Event()
    ready = threading.Event()
    longest = [0.0]

    def spin() -> None:
        last = time.perf_counter()
        ready.set()
        while not stop.is_set():
            now = time.perf_counter()
            longest[0] = max(longest[0], now - last)
            last = now

    spinner = threading.Thread(target=spin)
    spinner.start()
    ready.wait()
    started = time.perf_counter()
    call()
    duration = time.perf_counter() - started
    stop.set()
    spinner.join()
    return duration, longest[0]


def _policies(count: int) -> str:
    return "\n".join(
        f'permit(principal == User::"u{i}", action == Action::"a{i}", resource) when {{ resource.x == {i} }};'
        for i in range(count)
    )


def _schema_json(type_count: int) -> str:
    """300 actions that each apply to every pair of `type_count` entity types."""
    type_names = [f"T{i}" for i in range(type_count)]
    return json.dumps({"": {
        "entityTypes": {name: {"memberOfTypes": []} for name in type_names},
        "actions": {
            f"act{i}": {"appliesTo": {"principalTypes": type_names, "resourceTypes": type_names}}
            for i in range(300)
        },
    }})


# Template linking is not timed here: most of its cost is reading the link
# dicts and their entity uids, which needs the GIL.
CASES = [
    "format_policies",
    "policies_to_json_str",
    "policies_from_json_str",
    "PolicySet.from_str",
    "PolicySet.from_json_str",
    "PolicySet.with_added_str",
    "Schema.from_json_str",
    "Entities.from_json_str",
    "validate_policies",
    "is_authorized",
    "is_authorized_batch",
    "is_authorized_partial",
]


class GilReleaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        policies = _policies(8000)
        policies_json = cedarpy.policies_to_json_str(policies)
        policy_set = PolicySet.from_str(policies)

        schema_json = _schema_json(60)
        validation_schema = Schema.from_json_str(_schema_json(30))
        validated = 'permit(principal, action == Action::"act0", resource);'
        formatted = _policies(700)

        entities_json = json.dumps(
            [{"uid": {"type": "User", "id": f"u{i}"}, "attrs": {"x": i},
              "parents": [{"type": "Group", "id": f"g{i % 100}"}]} for i in range(20000)]
            + [{"uid": {"type": "Group", "id": f"g{i}"}, "attrs": {}, "parents": []} for i in range(100)]
        )

        request = {"principal": 'User::"u1"', "action": 'Action::"a1"', "resource": 'Doc::"d"', "context": {}}

        cls.work = {
            "format_policies": lambda: cedarpy.format_policies(formatted, 80, 2),
            "policies_to_json_str": lambda: cedarpy.policies_to_json_str(policies),
            "policies_from_json_str": lambda: cedarpy.policies_from_json_str(policies_json),
            "PolicySet.from_str": lambda: PolicySet.from_str(policies),
            "PolicySet.from_json_str": lambda: PolicySet.from_json_str(policies_json),
            "PolicySet.with_added_str": lambda: policy_set.with_added_str(policies),
            "Schema.from_json_str": lambda: Schema.from_json_str(schema_json),
            "Entities.from_json_str": lambda: Entities.from_json_str(entities_json),
            "validate_policies": lambda: cedarpy.validate_policies(validated, validation_schema),
            "is_authorized": lambda: cedarpy.is_authorized(request, policies, "[]"),
            "is_authorized_batch": lambda: cedarpy.is_authorized_batch([request] * 4, policies, "[]"),
            "is_authorized_partial": lambda: cedarpy.is_authorized_partial(request, policies, "[]"),
        }

    @parameterized.expand([(name,) for name in CASES])
    def test_call_releases_the_gil(self, name: str) -> None:
        duration, stall = _longest_stall(self.work[name])
        # The comparison needs a call long enough to dwarf the interpreter's
        # 5 ms thread switch interval.
        self.assertGreater(duration, 0.04, f"{name} took {duration * 1000:.0f} ms; enlarge its workload")
        self.assertLess(
            stall,
            duration / 2,
            f"{name} stalled another thread for {stall * 1000:.0f} ms of a {duration * 1000:.0f} ms call",
        )


if __name__ == "__main__":
    unittest.main()
