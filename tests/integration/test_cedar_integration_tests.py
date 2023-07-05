from parameterized import parameterized
import random
import unittest
from typing import List

import cedarpolicy
from integration import load_file_as_json, load_file_as_str, pretty_format


def custom_name_func(testcase_func, param_num, param):
    # print(f'{type(param.args)} {param.args}')
    return "%s_%s__%s" %(
        testcase_func.__name__,
        param_num,
        parameterized.to_safe_name("__".join(parameterized.to_safe_name(str(x)) for x in param.args)),
    )


def get_authz_test_params_for_use_case(use_case_id: str) -> list:
    # Load the test data
    cedar_int_tests_base = "resources/cedar-integration-tests"
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

    testing_params = []

    for query in queries:
        testing_params.append((policies,
                               entities,
                               schema,
                               should_validate,
                               query))

    print(f'selected {len(testing_params)} test cases for {use_case_id}:\n{pretty_format(testing_params)}')
    return testing_params


class CedarIntegrationTestCase(unittest.TestCase):

    @parameterized.expand(get_authz_test_params_for_use_case("1a"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_1a(self,
                                      policies: str,
                                      entities: list,
                                      schema: dict,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              query=query)

    @parameterized.expand(get_authz_test_params_for_use_case("2a"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_2a(self,
                                      policies: str,
                                      entities: list,
                                      schema: dict,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              query=query)

    @parameterized.expand(get_authz_test_params_for_use_case("2b"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_2b(self,
                                      policies: str,
                                      entities: list,
                                      schema: dict,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              query=query)

    @parameterized.expand(get_authz_test_params_for_use_case("2c"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_2c(self,
                                      policies: str,
                                      entities: list,
                                      schema: dict,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

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
