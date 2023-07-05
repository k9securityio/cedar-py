import json
import random
import unittest
from typing import List

import cedarpolicy
from integration import load_file_as_json, load_file_as_str, pretty_format


class CedarIntegrationTestCase(unittest.TestCase):

    def test_example_use_cases_doc_1a(self):
        # Load the test data - this should be a parameterized test data creation function
        cedar_int_tests_base = "resources/cedar-integration-tests"
        use_case_id = "1a"
        test_def: dict = load_file_as_json(f"{cedar_int_tests_base}/tests/example_use_cases_doc/{use_case_id}.json")
        print(f'loading tests defined for use case: {use_case_id}')

        policies_file_name: str = test_def['policies']
        entities_file_name: str = test_def['entities']
        schema_file_name: str = test_def['schema']
        should_validate: bool = test_def['should_validate']
        queries: List[dict] = test_def['queries']
        policies: str = load_file_as_str(f"{cedar_int_tests_base}/{policies_file_name}")
        entities: list = load_file_as_json(f"{cedar_int_tests_base}/{entities_file_name}")
        schema: object = load_file_as_json(f"{cedar_int_tests_base}/{schema_file_name}")

        for query in queries:
            self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                                  should_validate=should_validate,
                                                  query=query)

    def exec_authz_query_with_assertions(self,
                                         policies: str,
                                         entities: list,
                                         schema: dict,
                                         should_validate: bool,  # ignored; currently don't have the equivalent
                                         query: dict) -> None:
        print(f"executing authz query:\n{pretty_format(query)}")
        request = {
            'principal': query['principal'],
            'action': query['action'],
            'resource': query['resource'],
            'context': query.get('context', {}),
        }
        authz_resp: dict = cedarpolicy.is_authorized(request=request, policies=policies, entities=entities,
                                                     schema=schema)

        self.assertEqual(query['decision'], authz_resp['decision'])
