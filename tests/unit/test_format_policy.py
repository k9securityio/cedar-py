import unittest

from textwrap import dedent

from cedarpy import format_policies

class FormatPolicyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

    def test_policy_gets_formatted(self):
        input_policy = dedent("""
            permit(
                principal,
                action == Action::"edit",
                resource
            )
            when {
                resource.owner == principal
            };
        """).strip()

        expect_result = dedent("""
            permit (
              principal,
              action == Action::"edit",
              resource
            )
            when { resource.owner == principal };
        """).strip()

        actual_result = format_policies(input_policy, indent_width=2)

        self.assertEqual(expect_result, actual_result)

    def test_policy_formatting_error(self):
        input_policy = dedent("""
            invalid(
                principal,
                action == Action::"edit",
                resource
            )
            when {
                resource.owner == principal
            };
        """).strip()

        try:
            format_policies(input_policy, indent_width=2)
            self.fail("should have failed to parse")
        except ValueError as e:
            pass
