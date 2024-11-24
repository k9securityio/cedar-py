import unittest

from textwrap import dedent

from cedarpy import format_policies, policies_from_json_str, policies_to_json_str

from unit import load_file_as_str

import json

class FormatPolicyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        common_policies = """
                permit(
                    principal,
                    action == Action::"edit",
                    resource
                )
                when {
                   resource.account == principal
                };
                permit(
                    principal,
                    action == Action::"delete",
                    resource
                )
                when {
                    context.authenticated == true
                    &&
                    resource has account && principal == resource.account.owner
                }
                ;

        """.strip()
        self.policies: dict[str, str] = {
            "common": common_policies,
            "alice": f"""
                permit(
                    principal == User::"alice",
                    action == Action::"view",
                    resource
                )
                ;
                {common_policies}""".strip(),
            "bob": f"""
                permit(
                    principal == User::"bob",
                    action == Action::"view",
                    resource
                )
                ;
                {common_policies}""".strip(),
        }


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
        """).lstrip()

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

    def test_policy_to_json(self):
        result: dict = json.loads(policies_to_json_str(self.policies["bob"]))
        expected: dict = json.loads(load_file_as_str("resources/json/bob_policy.json"))
        self.assertEqual(expected, result, msg='expected cedar to be parsed to json correctly')

    def test_policy_from_json(self):
        json_str = load_file_as_str("resources/json/bob_policy.json")
        # this is required as conversion order in rust cedar library is non deterministic so could be one of n! variants
        # good thing bob only has three policies!!!
        expected = [
            load_file_as_str("resources/json/bob_policy1.cedar"),
            load_file_as_str("resources/json/bob_policy2.cedar"),
            load_file_as_str("resources/json/bob_policy3.cedar"),
            load_file_as_str("resources/json/bob_policy4.cedar"),
            load_file_as_str("resources/json/bob_policy5.cedar"),
            load_file_as_str("resources/json/bob_policy6.cedar"),
        ]
        result = format_policies(policies_from_json_str(json_str))
        self.assertIn(result, expected, msg='expected json to be parsed to cedar correctly')

