"""`release_gil=True` lets other Python threads run while Cedar works.

Each timing test runs one cedarpy call while a second Python thread spins and
records the longest stretch it went without running. A call that holds the GIL
for its whole duration stalls that thread for about as long as the call takes;
a call that releases it stalls the thread only while converting its arguments
and result.
"""
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from parameterized import parameterized

import cedarpy
from cedarpy import Entities, PolicySet, Schema, policies_to_pst, validate_policies


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


def _policies_json(count: int) -> str:
    """The Cedar JSON (EST) form of `_policies(count)`."""
    policies = ",".join(
        f'"policy{i}": {{"effect": "permit", '
        f'"principal": {{"op": "==", "entity": {{"type": "User", "id": "u{i}"}}}}, '
        f'"action": {{"op": "==", "entity": {{"type": "Action", "id": "a{i}"}}}}, '
        f'"resource": {{"op": "All"}}, '
        f'"conditions": [{{"kind": "when", "body": {{"==": {{"left": {{".": {{"left": {{"Var": "resource"}}, '
        f'"attr": "x"}}}}, "right": {{"Value": {i}}}}}}}}}]}}'
        for i in range(count)
    )
    return f'{{"staticPolicies": {{{policies}}}, "templates": {{}}, "templateLinks": []}}'


def _dense_schema_json(type_count: int) -> str:
    """300 actions that each apply to every pair of `type_count` entity types."""
    type_names = [f"T{i}" for i in range(type_count)]
    return json.dumps({"": {
        "entityTypes": {name: {"memberOfTypes": []} for name in type_names},
        "actions": {
            f"act{i}": {"appliesTo": {"principalTypes": type_names, "resourceTypes": type_names}}
            for i in range(300)
        },
    }})


def _dense_schema_cedar(type_count: int) -> str:
    """The Cedar schema syntax form of `_dense_schema_json(type_count)`."""
    names = ", ".join(f"T{i}" for i in range(type_count))
    return "\n".join(
        [f"entity T{i};" for i in range(type_count)]
        + [f"action act{i} appliesTo {{ principal: [{names}], resource: [{names}] }};" for i in range(300)]
    )


def _template_schema_json() -> str:
    """A small schema shaped like a multi-tenant service's: 150 actions, each
    for 7 principal types that belong to groups and a workspace, and for one of
    20 resource types; 8 actions apply to every resource type. 2,114 action ×
    principal type × resource type combinations."""
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


# Two-slot templates validate an order of magnitude slower than static
# policies, so a few of them against a small schema take tens of milliseconds.
TEMPLATES = "\n".join(
    f'permit(principal in ?principal, action in [Action::"a{2 * i}", Action::"a{2 * i + 1}"], resource in ?resource);'
    for i in range(3)
)


CASES = [
    "validate_policies",
    "PolicySet.from_str",
    "PolicySet.from_json_str",
    "Schema.from_str",
    "Schema.from_json_str",
    "Entities.from_json_str",
]


class GilReleaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        policies = _policies(8000)
        policies_json = _policies_json(8000)
        schema_cedar = _dense_schema_cedar(25)
        schema_json = _dense_schema_json(40)
        template_schema = Schema.from_json_str(_template_schema_json())
        entities_json = json.dumps(
            [{"uid": {"type": "User", "id": f"u{i}"}, "attrs": {"x": i},
              "parents": [{"type": "Group", "id": f"g{i % 100}"}]} for i in range(20000)]
            + [{"uid": {"type": "Group", "id": f"g{i}"}, "attrs": {}, "parents": []} for i in range(100)]
        )

        def work(release_gil: bool) -> dict:
            return {
                "validate_policies": lambda: validate_policies(TEMPLATES, template_schema, release_gil=release_gil),
                "PolicySet.from_str": lambda: PolicySet.from_str(policies, release_gil=release_gil),
                "PolicySet.from_json_str": lambda: PolicySet.from_json_str(policies_json, release_gil=release_gil),
                "Schema.from_str": lambda: Schema.from_str(schema_cedar, release_gil=release_gil),
                "Schema.from_json_str": lambda: Schema.from_json_str(schema_json, release_gil=release_gil),
                "Entities.from_json_str": lambda: Entities.from_json_str(entities_json, release_gil=release_gil),
            }

        cls.released = work(True)
        cls.held = work(False)

    def _measure(self, name: str, work: dict) -> tuple[float, float]:
        duration, stall = _longest_stall(work[name])
        # The comparison needs a call long enough to dwarf the interpreter's
        # 5 ms thread switch interval.
        self.assertGreater(duration, 0.04, f"{name} took {duration * 1000:.0f} ms; enlarge its workload")
        return duration, stall

    @parameterized.expand([(name,) for name in CASES])
    def test_release_gil_lets_other_threads_run(self, name: str) -> None:
        duration, stall = self._measure(name, self.released)
        self.assertLess(
            stall,
            duration / 2,
            f"{name}(release_gil=True) stalled another thread for {stall * 1000:.0f} ms of a {duration * 1000:.0f} ms call",
        )

    def test_default_holds_the_gil(self) -> None:
        duration, stall = self._measure("validate_policies", self.held)
        self.assertGreater(
            stall,
            duration / 2,
            f"validate_policies() stalled another thread for only {stall * 1000:.0f} ms of a {duration * 1000:.0f} ms call",
        )


class ReleaseGilResultsTestCase(unittest.TestCase):
    """`release_gil` changes only who may run during the call, not its result."""

    def test_from_pst_builds_the_same_set(self) -> None:
        # Not timed: reading the `cedarpy.pst` nodes holds the GIL, and it is
        # most of the call.
        nodes = policies_to_pst(_policies(50))
        released = PolicySet.from_pst(nodes, release_gil=True)
        self.assertEqual(str(PolicySet.from_pst(nodes)), str(released))

    def test_errors_are_unchanged(self) -> None:
        for call in (
            lambda release_gil: PolicySet.from_str("permit(", release_gil=release_gil),
            lambda release_gil: PolicySet.from_json_str("{", release_gil=release_gil),
            lambda release_gil: Schema.from_str("entity", release_gil=release_gil),
            lambda release_gil: Schema.from_json_str("{", release_gil=release_gil),
            lambda release_gil: Entities.from_json_str("[{", release_gil=release_gil),
        ):
            messages = []
            for release_gil in (False, True):
                with self.assertRaises(ValueError) as raised:
                    call(release_gil)
                messages.append(str(raised.exception))
            self.assertEqual(messages[0], messages[1])

    def test_release_gil_is_keyword_only(self) -> None:
        with self.assertRaises(TypeError):
            PolicySet.from_str("", True)
        with self.assertRaises(TypeError):
            Schema.from_json_str("{}", True)
        with self.assertRaises(TypeError):
            validate_policies("", "{}", True)


SCHEMA = """
    entity User;
    entity Photo = { "owner": User };
    action view appliesTo { principal: User, resource: Photo };
"""


class SharedSchemaAcrossThreadsTestCase(unittest.TestCase):
    """With `release_gil=True`, constructors and validation run Rust work in
    parallel against one shared `Schema` handle."""

    def test_entities_built_in_parallel_against_one_schema(self) -> None:
        schema = Schema.from_str(SCHEMA)

        def build(i: int) -> object:
            owner = f"user{i}" if i % 2 == 0 else 42  # odd i violates the schema
            document = json.dumps([
                {"uid": {"type": "User", "id": f"user{i}"}, "attrs": {}, "parents": []},
                {"uid": {"type": "Photo", "id": f"photo{i}"},
                 "attrs": {"owner": {"__entity": {"type": "User", "id": owner}} if isinstance(owner, str) else owner},
                 "parents": []},
            ])
            try:
                return len(Entities.from_json_str(document, schema=schema, release_gil=True))
            except ValueError:
                return ValueError

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(build, range(64)))

        # Two entities plus the schema's one action entity for each valid document.
        self.assertEqual([3 if i % 2 == 0 else ValueError for i in range(64)], results)

    def test_validation_in_parallel_against_one_schema(self) -> None:
        schema = Schema.from_str(SCHEMA)
        valid = 'permit(principal, action == Action::"view", resource) when { resource.owner == principal };'
        invalid = 'permit(principal, action == Action::"view", resource) when { resource.size > 1 };'

        def validate(i: int) -> bool:
            return validate_policies(valid if i % 2 == 0 else invalid, schema, release_gil=True).validation_passed

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(validate, range(64)))

        self.assertEqual([i % 2 == 0 for i in range(64)], results)


if __name__ == "__main__":
    unittest.main()
