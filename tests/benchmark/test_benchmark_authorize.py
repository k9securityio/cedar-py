"""
Performance regression tests for cedarpy authorization functions.

This module uses pytest-benchmark to measure and track the performance
of is_authorized and is_authorized_batch functions across different
policy complexities, entity set sizes, and batch sizes.

Usage (prefer Makefile targets):
    make benchmark          # Run benchmarks
    make benchmark-save     # Save results to results/out/
    make benchmark-compare  # Compare against baseline (fails on regression)

See BENCHMARKS.md for detailed usage information.
"""
import json
import pytest
from typing import List

from cedarpy import is_authorized, is_authorized_batch, Decision

from benchmark import load_file_as_str


# =============================================================================
# Test Fixtures - Policies with varying complexity
# =============================================================================

class PolicyFixtures:
    """Policy fixtures with varying complexity levels."""

    @staticmethod
    def simple_policy() -> str:
        """Single permit policy with basic principal/action/resource matching."""
        return """
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
        """

    @staticmethod
    def medium_policy() -> str:
        """Multiple policies with conditions and attribute checks."""
        return """
            // Allow users to view their own resources
            permit(
                principal,
                action == Action::"view",
                resource
            )
            when {
                resource.owner == principal
            };

            // Allow users to edit resources they own
            permit(
                principal,
                action == Action::"edit",
                resource
            )
            when {
                resource.owner == principal
            };

            // Allow admins to view all resources
            permit(
                principal,
                action == Action::"view",
                resource
            )
            when {
                principal.role == "admin"
            };

            // Deny access to private resources unless owner
            forbid(
                principal,
                action,
                resource
            )
            when {
                resource.private == true &&
                resource.owner != principal
            };
        """

    @staticmethod
    def complex_policy() -> str:
        """Complex policies with multiple conditions, hierarchy checks, and context."""
        return """
            // Allow users to view public resources
            permit(
                principal,
                action == Action::"view",
                resource
            )
            when {
                resource.private == false
            };

            // Allow users to view their own private resources
            permit(
                principal,
                action == Action::"view",
                resource
            )
            when {
                resource.private == true &&
                resource.owner == principal
            };

            // Allow users to edit resources they own
            permit(
                principal,
                action == Action::"edit",
                resource
            )
            when {
                resource.owner == principal
            };

            // Allow users to delete resources they own when authenticated
            permit(
                principal,
                action == Action::"delete",
                resource
            )
            when {
                resource.owner == principal &&
                context.authenticated == true
            };

            // Allow admins to perform any action
            permit(
                principal,
                action,
                resource
            )
            when {
                principal.role == "admin"
            };

            // Allow managers to view and edit team resources
            permit(
                principal,
                action == Action::"view",
                resource
            )
            when {
                principal.role == "manager" &&
                resource.team == principal.team
            };

            permit(
                principal,
                action == Action::"edit",
                resource
            )
            when {
                principal.role == "manager" &&
                resource.team == principal.team
            };

            // Allow shared access for resources with explicit sharing
            permit(
                principal,
                action == Action::"view",
                resource
            )
            when {
                principal in resource.shared_with
            };

            // Forbid access to archived resources except for admins
            forbid(
                principal,
                action,
                resource
            )
            when {
                resource.archived == true &&
                principal.role != "admin"
            };

            // Forbid access outside business hours unless urgent
            forbid(
                principal,
                action,
                resource
            )
            when {
                context has business_hours &&
                context.business_hours == false &&
                !(context has urgent && context.urgent == true)
            };
        """


class EntityFixtures:
    """Entity fixtures with varying sizes."""

    @staticmethod
    def small_entities() -> List[dict]:
        """Small entity set (~10 entities)."""
        return [
            {"uid": {"type": "User", "id": "alice"},
             "attrs": {"role": "user", "team": "engineering"},
             "parents": []},
            {"uid": {"type": "User", "id": "bob"},
             "attrs": {"role": "user", "team": "sales"},
             "parents": []},
            {"uid": {"type": "User", "id": "admin"},
             "attrs": {"role": "admin", "team": "ops"},
             "parents": []},
            {"uid": {"type": "Resource", "id": "doc1"},
             "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}},
                       "private": False, "team": "engineering",
                       "archived": False, "shared_with": []},
             "parents": []},
            {"uid": {"type": "Resource", "id": "doc2"},
             "attrs": {"owner": {"__entity": {"type": "User", "id": "bob"}},
                       "private": True, "team": "sales",
                       "archived": False, "shared_with": []},
             "parents": []},
            {"uid": {"type": "Resource", "id": "doc3"},
             "attrs": {"owner": {"__entity": {"type": "User", "id": "alice"}},
                       "private": True, "team": "engineering",
                       "archived": False,
                       "shared_with": [{"__entity": {"type": "User", "id": "bob"}}]},
             "parents": []},
        ]

    @staticmethod
    def medium_entities() -> List[dict]:
        """Medium entity set (~50 entities)."""
        entities = []

        # Create 20 users with varying roles
        roles = ["user", "manager", "admin"]
        teams = ["engineering", "sales", "marketing", "ops", "support"]

        for i in range(20):
            role = roles[i % len(roles)]
            team = teams[i % len(teams)]
            entities.append({
                "uid": {"type": "User", "id": f"user_{i}"},
                "attrs": {"role": role, "team": team},
                "parents": []
            })

        # Create 30 resources with varying attributes
        for i in range(30):
            owner_id = f"user_{i % 20}"
            team = teams[i % len(teams)]
            entities.append({
                "uid": {"type": "Resource", "id": f"resource_{i}"},
                "attrs": {
                    "owner": {"__entity": {"type": "User", "id": owner_id}},
                    "private": i % 3 == 0,
                    "team": team,
                    "archived": i % 10 == 0,
                    "shared_with": []
                },
                "parents": []
            })

        return entities

    @staticmethod
    def large_entities() -> List[dict]:
        """Large entity set (~200 entities)."""
        entities = []

        # Create 50 users
        roles = ["user", "manager", "admin"]
        teams = ["engineering", "sales", "marketing", "ops", "support",
                 "finance", "legal", "hr", "product", "design"]

        for i in range(50):
            role = roles[i % len(roles)]
            team = teams[i % len(teams)]
            entities.append({
                "uid": {"type": "User", "id": f"user_{i}"},
                "attrs": {"role": role, "team": team},
                "parents": []
            })

        # Create 150 resources
        for i in range(150):
            owner_id = f"user_{i % 50}"
            team = teams[i % len(teams)]
            # Some resources are shared with multiple users
            shared_with = []
            if i % 5 == 0:
                shared_with = [
                    {"__entity": {"type": "User", "id": f"user_{(i + 1) % 50}"}},
                    {"__entity": {"type": "User", "id": f"user_{(i + 2) % 50}"}}
                ]
            entities.append({
                "uid": {"type": "Resource", "id": f"resource_{i}"},
                "attrs": {
                    "owner": {"__entity": {"type": "User", "id": owner_id}},
                    "private": i % 3 == 0,
                    "team": team,
                    "archived": i % 15 == 0,
                    "shared_with": shared_with
                },
                "parents": []
            })

        return entities


class RequestFixtures:
    """Request fixtures for benchmarking."""

    @staticmethod
    def simple_allow_request() -> dict:
        """Request expected to be allowed with simple policy."""
        return {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Resource::"doc1"',
            "context": {}
        }

    @staticmethod
    def simple_deny_request() -> dict:
        """Request expected to be denied."""
        return {
            "principal": 'User::"bob"',
            "action": 'Action::"delete"',
            "resource": 'Resource::"doc1"',
            "context": {}
        }

    @staticmethod
    def request_with_context() -> dict:
        """Request with context attributes."""
        return {
            "principal": 'User::"alice"',
            "action": 'Action::"delete"',
            "resource": 'Resource::"doc1"',
            "context": {"authenticated": True, "business_hours": True}
        }

    @staticmethod
    def generate_batch_requests(size: int) -> List[dict]:
        """Generate a batch of requests of the specified size."""
        actions = ["view", "edit", "delete"]
        requests = []
        for i in range(size):
            requests.append({
                "principal": f'User::"user_{i % 20}"',
                "action": f'Action::"{actions[i % len(actions)]}"',
                "resource": f'Resource::"resource_{i % 30}"',
                "context": {"authenticated": i % 2 == 0, "business_hours": True}
            })
        return requests


# =============================================================================
# Pytest Fixtures
# =============================================================================

@pytest.fixture
def simple_policy():
    return PolicyFixtures.simple_policy()


@pytest.fixture
def medium_policy():
    return PolicyFixtures.medium_policy()


@pytest.fixture
def complex_policy():
    return PolicyFixtures.complex_policy()


@pytest.fixture
def small_entities():
    return EntityFixtures.small_entities()


@pytest.fixture
def medium_entities():
    return EntityFixtures.medium_entities()


@pytest.fixture
def large_entities():
    return EntityFixtures.large_entities()


@pytest.fixture
def sandbox_b_entities():
    """Load the sandbox_b entities from the test resources."""
    return load_file_as_str("resources/sandbox_b/entities.json")


@pytest.fixture
def sandbox_b_schema():
    """Load the sandbox_b schema from the test resources."""
    return load_file_as_str("resources/sandbox_b/schema.json")


@pytest.fixture
def sandbox_b_policy():
    """A realistic policy for the sandbox_b schema."""
    return """
        // Allow users to view their own photos
        permit(
            principal,
            action == Action::"view",
            resource
        )
        when {
            resource.account.owner == principal
        };

        // Allow users to view public photos
        permit(
            principal,
            action == Action::"view",
            resource
        )
        when {
            resource.private == false
        };

        // Allow users to edit their own photos
        permit(
            principal,
            action == Action::"edit",
            resource
        )
        when {
            resource.account.owner == principal
        };

        // Allow users to delete their own photos when authenticated
        permit(
            principal,
            action == Action::"delete",
            resource
        )
        when {
            resource.account.owner == principal &&
            context.authenticated == true
        };

        // Allow users to comment on any photo when authenticated
        permit(
            principal,
            action == Action::"comment",
            resource
        )
        when {
            context.authenticated == true
        };

        // Allow photo admins to perform any action
        permit(
            principal,
            action,
            resource
        )
        when {
            principal in resource.admins
        };
    """


# =============================================================================
# Benchmark Tests - is_authorized
# =============================================================================

class IsAuthorizedBenchmarkTestCase:
    """Benchmarks for the is_authorized function."""

    # -------------------------------------------------------------------------
    # Policy Complexity Benchmarks
    # -------------------------------------------------------------------------

    def test_simple_policy_allow(self, benchmark, simple_policy, small_entities):
        """Benchmark is_authorized with simple policy (allow case)."""
        request = RequestFixtures.simple_allow_request()

        result = benchmark(is_authorized, request, simple_policy, small_entities)

        assert result.decision == Decision.Allow

    def test_simple_policy_deny(self, benchmark, simple_policy, small_entities):
        """Benchmark is_authorized with simple policy (deny case)."""
        request = RequestFixtures.simple_deny_request()

        result = benchmark(is_authorized, request, simple_policy, small_entities)

        assert result.decision == Decision.Deny

    def test_medium_policy(self, benchmark, medium_policy, small_entities):
        """Benchmark is_authorized with medium complexity policy."""
        request = RequestFixtures.simple_allow_request()

        result = benchmark(is_authorized, request, medium_policy, small_entities)

        # Result depends on policy evaluation
        assert result.decision in [Decision.Allow, Decision.Deny]

    def test_complex_policy(self, benchmark, complex_policy, small_entities):
        """Benchmark is_authorized with complex policy."""
        request = RequestFixtures.request_with_context()

        result = benchmark(is_authorized, request, complex_policy, small_entities)

        assert result.decision in [Decision.Allow, Decision.Deny]

    # -------------------------------------------------------------------------
    # Entity Set Size Benchmarks
    # -------------------------------------------------------------------------

    def test_small_entity_set(self, benchmark, medium_policy, small_entities):
        """Benchmark is_authorized with small entity set (~10 entities)."""
        request = RequestFixtures.simple_allow_request()

        result = benchmark(is_authorized, request, medium_policy, small_entities)

        assert result.decision in [Decision.Allow, Decision.Deny]

    def test_medium_entity_set(self, benchmark, medium_policy, medium_entities):
        """Benchmark is_authorized with medium entity set (~50 entities)."""
        request = {
            "principal": 'User::"user_0"',
            "action": 'Action::"view"',
            "resource": 'Resource::"resource_0"',
            "context": {}
        }

        result = benchmark(is_authorized, request, medium_policy, medium_entities)

        assert result.decision in [Decision.Allow, Decision.Deny]

    def test_large_entity_set(self, benchmark, medium_policy, large_entities):
        """Benchmark is_authorized with large entity set (~200 entities)."""
        request = {
            "principal": 'User::"user_0"',
            "action": 'Action::"view"',
            "resource": 'Resource::"resource_0"',
            "context": {}
        }

        result = benchmark(is_authorized, request, medium_policy, large_entities)

        assert result.decision in [Decision.Allow, Decision.Deny]

    # -------------------------------------------------------------------------
    # Realistic Scenario Benchmarks (sandbox_b)
    # -------------------------------------------------------------------------

    def test_sandbox_b_view_own_photo(self, benchmark, sandbox_b_policy,
                                       sandbox_b_entities, sandbox_b_schema):
        """Benchmark realistic scenario: user viewing their own photo."""
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": json.dumps({"authenticated": True})
        }

        result = benchmark(
            is_authorized, request, sandbox_b_policy,
            sandbox_b_entities, schema=sandbox_b_schema
        )

        assert result.decision == Decision.Allow

    def test_sandbox_b_view_public_photo(self, benchmark, sandbox_b_policy,
                                          sandbox_b_entities, sandbox_b_schema):
        """Benchmark realistic scenario: user viewing public photo."""
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"view"',
            "resource": 'Photo::"vacation.jpg"',
            "context": json.dumps({"authenticated": False})
        }

        result = benchmark(
            is_authorized, request, sandbox_b_policy,
            sandbox_b_entities, schema=sandbox_b_schema
        )

        assert result.decision == Decision.Allow

    def test_sandbox_b_delete_with_auth(self, benchmark, sandbox_b_policy,
                                         sandbox_b_entities, sandbox_b_schema):
        """Benchmark realistic scenario: authenticated delete."""
        request = {
            "principal": 'User::"alice"',
            "action": 'Action::"delete"',
            "resource": 'Photo::"alice_w2.jpg"',
            "context": json.dumps({"authenticated": True})
        }

        result = benchmark(
            is_authorized, request, sandbox_b_policy,
            sandbox_b_entities, schema=sandbox_b_schema
        )

        assert result.decision == Decision.Allow


# =============================================================================
# Benchmark Tests - is_authorized_batch
# =============================================================================

class IsAuthorizedBatchBenchmarkTestCase:
    """Benchmarks for the is_authorized_batch function."""

    # -------------------------------------------------------------------------
    # Batch Size Benchmarks
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("batch_size", [1, 5, 10, 25, 50, 100])
    def test_batch_size_scaling(self, benchmark, medium_policy, medium_entities,
                                 batch_size):
        """Benchmark batch authorization with varying batch sizes."""
        requests = RequestFixtures.generate_batch_requests(batch_size)

        results = benchmark(
            is_authorized_batch, requests, medium_policy, medium_entities
        )

        assert len(results) == batch_size

    # -------------------------------------------------------------------------
    # Policy Complexity with Batch
    # -------------------------------------------------------------------------

    def test_batch_simple_policy(self, benchmark, simple_policy, small_entities):
        """Benchmark batch with simple policy."""
        requests = [RequestFixtures.simple_allow_request() for _ in range(10)]

        results = benchmark(
            is_authorized_batch, requests, simple_policy, small_entities
        )

        assert len(results) == 10

    def test_batch_complex_policy(self, benchmark, complex_policy, medium_entities):
        """Benchmark batch with complex policy."""
        requests = RequestFixtures.generate_batch_requests(10)

        results = benchmark(
            is_authorized_batch, requests, complex_policy, medium_entities
        )

        assert len(results) == 10

    # -------------------------------------------------------------------------
    # Realistic Batch Scenarios (sandbox_b)
    # -------------------------------------------------------------------------

    def test_sandbox_b_batch_mixed_actions(self, benchmark, sandbox_b_policy,
                                            sandbox_b_entities, sandbox_b_schema):
        """Benchmark realistic batch: mixed actions on photos."""
        actions = ['view', 'edit', 'comment', 'delete']
        resources = ['alice_w2.jpg', 'vacation.jpg', 'prototype_v0.jpg',
                     'sales_projections.jpg']
        requests = []

        for action in actions:
            for resource in resources:
                requests.append({
                    "principal": 'User::"alice"',
                    "action": f'Action::"{action}"',
                    "resource": f'Photo::"{resource}"',
                    "context": json.dumps({"authenticated": True})
                })

        results = benchmark(
            is_authorized_batch, requests, sandbox_b_policy,
            sandbox_b_entities, schema=sandbox_b_schema
        )

        assert len(results) == len(actions) * len(resources)

    def test_sandbox_b_batch_multiple_users(self, benchmark, sandbox_b_policy,
                                             sandbox_b_entities, sandbox_b_schema):
        """Benchmark realistic batch: multiple users accessing resources."""
        users = ['alice', 'ahmad', 'stacey', 'guiseppe']
        requests = []

        for user in users:
            requests.append({
                "principal": f'User::"{user}"',
                "action": 'Action::"view"',
                "resource": 'Photo::"vacation.jpg"',
                "context": json.dumps({"authenticated": True})
            })

        results = benchmark(
            is_authorized_batch, requests, sandbox_b_policy,
            sandbox_b_entities, schema=sandbox_b_schema
        )

        assert len(results) == len(users)


# =============================================================================
# Comparative Benchmarks - Single vs Batch
# =============================================================================

class SingleVsBatchBenchmarkTestCase:
    """Compare performance of single calls vs batch calls."""

    def test_ten_single_calls(self, benchmark, medium_policy, medium_entities):
        """Benchmark 10 individual is_authorized calls."""
        requests = RequestFixtures.generate_batch_requests(10)

        def run_single_calls():
            results = []
            for request in requests:
                results.append(
                    is_authorized(request, medium_policy, medium_entities)
                )
            return results

        results = benchmark(run_single_calls)

        assert len(results) == 10

    def test_ten_batch_call(self, benchmark, medium_policy, medium_entities):
        """Benchmark single is_authorized_batch call with 10 requests."""
        requests = RequestFixtures.generate_batch_requests(10)

        results = benchmark(
            is_authorized_batch, requests, medium_policy, medium_entities
        )

        assert len(results) == 10


# =============================================================================
# Input Format Benchmarks
# =============================================================================

class InputFormatBenchmarkTestCase:
    """Benchmark different input format options."""

    def test_entities_as_list(self, benchmark, medium_policy, medium_entities):
        """Benchmark with entities passed as Python list."""
        request = RequestFixtures.simple_allow_request()

        result = benchmark(
            is_authorized, request, medium_policy, medium_entities
        )

        assert result.decision in [Decision.Allow, Decision.Deny]

    def test_entities_as_json_string(self, benchmark, medium_policy, medium_entities):
        """Benchmark with entities passed as JSON string."""
        request = RequestFixtures.simple_allow_request()
        entities_json = json.dumps(medium_entities)

        result = benchmark(
            is_authorized, request, medium_policy, entities_json
        )

        assert result.decision in [Decision.Allow, Decision.Deny]

    def test_context_as_dict(self, benchmark, medium_policy, medium_entities):
        """Benchmark with context passed as dict."""
        request = {
            "principal": 'User::"user_0"',
            "action": 'Action::"view"',
            "resource": 'Resource::"resource_0"',
            "context": {"authenticated": True, "key": "value"}
        }

        result = benchmark(
            is_authorized, request, medium_policy, medium_entities
        )

        assert result.decision in [Decision.Allow, Decision.Deny]

    def test_context_as_json_string(self, benchmark, medium_policy, medium_entities):
        """Benchmark with context passed as JSON string."""
        request = {
            "principal": 'User::"user_0"',
            "action": 'Action::"view"',
            "resource": 'Resource::"resource_0"',
            "context": json.dumps({"authenticated": True, "key": "value"})
        }

        result = benchmark(
            is_authorized, request, medium_policy, medium_entities
        )

        assert result.decision in [Decision.Allow, Decision.Deny]
