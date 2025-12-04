import json
import unittest

from cedarpy import validate_policies, ValidationResult, ValidationError

from unit import load_file_as_str


class ValidatePoliciesTestCase(unittest.TestCase):
    """Tests for the validate_policies function."""

    def setUp(self) -> None:
        super().setUp()
        # Load schema from test resources
        self.schema = load_file_as_str("resources/sandbox_b/schema.json")

        # Valid policy that matches the schema
        self.valid_policy = """
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
        """

        # Invalid policy with misspelled entity type (Usr instead of User)
        self.invalid_policy_bad_entity = """
            permit(
                principal == Usr::"alice",
                action == Action::"view",
                resource
            );
        """

        # Invalid policy with misspelled action
        self.invalid_policy_bad_action = """
            permit(
                principal == User::"alice",
                action == Action::"veiw",
                resource
            );
        """

    def test_validate_valid_policy_passes(self):
        """Test that a valid policy passes validation."""
        result = validate_policies(self.valid_policy, self.schema)

        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.validation_passed)
        self.assertEqual([], result.errors)
        # Test __bool__ method
        self.assertTrue(result)

    def test_validate_invalid_policy_with_bad_entity_type_fails(self):
        """Test that a policy with an invalid entity type fails validation."""
        result = validate_policies(self.invalid_policy_bad_entity, self.schema)

        self.assertIsInstance(result, ValidationResult)
        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)
        # Test __bool__ method
        self.assertFalse(result)

        # Check that the error mentions the unrecognized entity type
        error_messages = [str(e) for e in result.errors]
        self.assertTrue(
            any("Usr" in msg for msg in error_messages),
            f"Expected error about 'Usr' entity type, got: {error_messages}"
        )

    def test_validate_invalid_policy_with_bad_action_fails(self):
        """Test that a policy with an invalid action fails validation."""
        result = validate_policies(self.invalid_policy_bad_action, self.schema)

        self.assertIsInstance(result, ValidationResult)
        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)

        # Check that the error mentions the unrecognized action
        error_messages = [str(e) for e in result.errors]
        self.assertTrue(
            any("veiw" in msg for msg in error_messages),
            f"Expected error about 'veiw' action, got: {error_messages}"
        )

    def test_validate_with_schema_as_dict(self):
        """Test that schema can be provided as a dict."""
        schema_dict = json.loads(self.schema)
        result = validate_policies(self.valid_policy, schema_dict)

        self.assertTrue(result.validation_passed)
        self.assertEqual([], result.errors)

    def test_validate_with_invalid_schema_fails(self):
        """Test that an invalid schema returns an error."""
        invalid_schema = "{ this is not valid json }"
        result = validate_policies(self.valid_policy, invalid_schema)

        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)
        self.assertTrue(
            any("Schema parse error" in str(e) for e in result.errors),
            f"Expected schema parse error, got: {[str(e) for e in result.errors]}"
        )

    def test_validate_with_empty_schema_fails(self):
        """Test that an empty schema returns an error."""
        result = validate_policies(self.valid_policy, "")

        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)
        self.assertTrue(
            any("Schema is required" in str(e) for e in result.errors),
            f"Expected schema required error, got: {[str(e) for e in result.errors]}"
        )

    def test_validate_with_invalid_policy_syntax_fails(self):
        """Test that a policy with invalid syntax returns an error."""
        invalid_policy = "this is not a valid cedar policy"
        result = validate_policies(invalid_policy, self.schema)

        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)
        self.assertTrue(
            any("Policy parse error" in str(e) for e in result.errors),
            f"Expected policy parse error, got: {[str(e) for e in result.errors]}"
        )

    def test_validation_error_properties(self):
        """Test ValidationError class properties."""
        result = validate_policies(self.invalid_policy_bad_entity, self.schema)

        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)

        error = result.errors[0]
        self.assertIsInstance(error, ValidationError)
        # policy_id should be a string (may be empty for some errors)
        self.assertIsInstance(error.policy_id, str)
        # error should be a non-empty string
        self.assertIsInstance(error.error, str)
        self.assertGreater(len(error.error), 0)
        # __str__ should return a non-empty string
        self.assertGreater(len(str(error)), 0)
        # __repr__ should contain the class name
        self.assertIn("ValidationError", repr(error))

    def test_validation_result_repr(self):
        """Test ValidationResult __repr__ method."""
        result = validate_policies(self.valid_policy, self.schema)
        repr_str = repr(result)
        self.assertIn("ValidationResult", repr_str)
        self.assertIn("validation_passed=True", repr_str)


class ValidatePoliciesWithCedarSchemaTestCase(unittest.TestCase):
    """Tests for validate_policies with Cedar schema syntax (not JSON)."""

    def test_validate_with_cedar_schema_syntax(self):
        """Test that Cedar schema syntax (not JSON) works."""
        # Cedar schema in human-readable format
        cedar_schema = """
            entity User;
            entity Photo;
            action view appliesTo { principal: User, resource: Photo };
        """

        policy = """
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource == Photo::"photo1"
            );
        """

        result = validate_policies(policy, cedar_schema)
        self.assertTrue(result.validation_passed, f"Validation failed: {[str(e) for e in result.errors]}")


class ValidatePoliciesMultiplePoliciesTestCase(unittest.TestCase):
    """Tests for validating multiple policies at once."""

    def setUp(self) -> None:
        super().setUp()
        self.schema = load_file_as_str("resources/sandbox_b/schema.json")

    def test_validate_multiple_valid_policies(self):
        """Test that multiple valid policies all pass validation."""
        policies = """
            @id("policy1")
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );

            @id("policy2")
            permit(
                principal == User::"bob",
                action == Action::"edit",
                resource
            );
        """

        result = validate_policies(policies, self.schema)
        self.assertTrue(result.validation_passed)
        self.assertEqual([], result.errors)

    def test_validate_multiple_policies_with_one_invalid(self):
        """Test that if one policy is invalid, validation fails."""
        policies = """
            @id("valid_policy")
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );

            @id("invalid_policy")
            permit(
                principal == BadType::"alice",
                action == Action::"view",
                resource
            );
        """

        result = validate_policies(policies, self.schema)
        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)

        # Check that the error references the invalid policy
        error_messages = [str(e) for e in result.errors]
        self.assertTrue(
            any("BadType" in msg for msg in error_messages),
            f"Expected error about 'BadType', got: {error_messages}"
        )


class ValidatePoliciesRustParityTestCase(unittest.TestCase):
    """Tests that mirror the Rust CLI validation tests from sample.rs.

    These use the same policy and schema files as the Rust CLI tests to ensure parity.
    Files are loaded from third_party/cedar/cedar-policy-cli/sample-data/.
    """

    # Path to the Rust CLI sample data relative to tests/unit/
    SAMPLE_DATA = "../../third_party/cedar/cedar-policy-cli/sample-data"

    def test_validate_policies_1_bad_misspelled_entity_type(self):
        """Test case from Rust: policies_1_bad.txt has 'UsrGroup' instead of 'UserGroup'.

        This mirrors the Rust test:
            run_validate_test(
                "sample-data/sandbox_a/policies_1_bad.txt",
                "sample-data/sandbox_a/schema.json",
                CedarExitCode::ValidationFailure,
            );
        """
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/policies_1_bad.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/schema.json")

        result = validate_policies(policies, schema)
        self.assertFalse(result.validation_passed)
        self.assertGreater(len(result.errors), 0)

        # Should mention the unrecognized entity type
        error_messages = [str(e) for e in result.errors]
        self.assertTrue(
            any("UsrGroup" in msg for msg in error_messages),
            f"Expected error about 'UsrGroup', got: {error_messages}"
        )

    def test_validate_policies_5_bad_missing_has_check(self):
        """Test case from Rust: policies_5_bad.txt accesses optional attribute without 'has' check.

        This mirrors the Rust test:
            run_validate_test(
                "sample-data/sandbox_b/policies_5_bad.txt",
                "sample-data/sandbox_b/schema.json",
                CedarExitCode::ValidationFailure,
            );

        The policy accesses resource.private without checking 'has' first,
        but 'private' is an optional attribute in the schema.
        """
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/policies_5_bad.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/schema.json")

        result = validate_policies(policies, schema)

        # This should fail validation because we access an optional attribute
        # without a 'has' guard in strict mode
        self.assertFalse(result.validation_passed,
                        f"Expected validation to fail for optional attribute access without 'has' check. "
                        f"Errors: {[str(e) for e in result.errors]}")

    def test_validate_policies_1_valid(self):
        """Test case from Rust: policies_1.txt is valid.

        This mirrors the Rust test:
            run_validate_test(
                "sample-data/sandbox_a/policies_1.txt",
                "sample-data/sandbox_a/schema.json",
                CedarExitCode::Success,
            );
        """
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/policies_1.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/schema.json")

        result = validate_policies(policies, schema)
        self.assertTrue(result.validation_passed,
                       f"Expected valid policy to pass. Errors: {[str(e) for e in result.errors]}")

    def test_validate_policies_2_valid(self):
        """Test case from Rust: policies_2.txt is valid."""
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/policies_2.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/schema.json")

        result = validate_policies(policies, schema)
        self.assertTrue(result.validation_passed,
                       f"Expected valid policy to pass. Errors: {[str(e) for e in result.errors]}")

    def test_validate_policies_3_valid(self):
        """Test case from Rust: policies_3.txt is valid."""
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/policies_3.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_a/schema.json")

        result = validate_policies(policies, schema)
        self.assertTrue(result.validation_passed,
                       f"Expected valid policy to pass. Errors: {[str(e) for e in result.errors]}")

    def test_validate_sandbox_b_policies_4_valid(self):
        """Test case from Rust: sandbox_b/policies_4.txt is valid."""
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/policies_4.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/schema.json")

        result = validate_policies(policies, schema)
        self.assertTrue(result.validation_passed,
                       f"Expected valid policy to pass. Errors: {[str(e) for e in result.errors]}")

    def test_validate_sandbox_b_policies_5_valid(self):
        """Test case from Rust: sandbox_b/policies_5.txt is valid (has proper 'has' checks)."""
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/policies_5.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/schema.json")

        result = validate_policies(policies, schema)
        self.assertTrue(result.validation_passed,
                       f"Expected valid policy to pass. Errors: {[str(e) for e in result.errors]}")

    def test_validate_sandbox_b_policies_6_valid(self):
        """Test case from Rust: sandbox_b/policies_6.txt is valid."""
        policies = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/policies_6.txt")
        schema = load_file_as_str(f"{self.SAMPLE_DATA}/sandbox_b/schema.json")

        result = validate_policies(policies, schema)
        self.assertTrue(result.validation_passed,
                       f"Expected valid policy to pass. Errors: {[str(e) for e in result.errors]}")


if __name__ == '__main__':
    unittest.main()
