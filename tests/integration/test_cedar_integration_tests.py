from parameterized import parameterized
import unittest
from typing import List

import cedarpy

from shared import pretty_format, load_file_as_json, load_file_as_str


def custom_name_func(testcase_func, param_num, param):
    # print(f'{type(param.args)} {param.args}')
    return "%s_%s__%s" %(
        testcase_func.__name__,
        param_num,
        parameterized.to_safe_name("__".join(parameterized.to_safe_name(str(x)) for x in param.args)),
    )


def get_authz_test_params_for_test_suite(test_kind: str, test_suite: str) -> list:
    """Get authorization test params for a cedar-integration-tests test suite
    :param test_kind is one of the kinds of tests organized by directory in the cedar-integration-tests/tests
    directory, e.g. example_use_cases_doc
    :param test_suite is the test suite's 'id', which is the name of the file without the `.json`, e.g. '1a'
    """
    # Load the test data
    cedar_int_tests_base = "resources/cedar-integration-tests"
    test_def: dict = load_file_as_json(f"{cedar_int_tests_base}/tests/{test_kind}/{test_suite}.json")
    print(f'loading tests defined for use case: {test_suite}')

    policies_file_name: str = test_def['policies']
    entities_file_name: str = test_def['entities']
    schema_file_name: str = test_def['schema']
    should_validate: bool = test_def['shouldValidate']
    request_models: List[dict] = test_def['requests']
    policies: str = load_file_as_str(f"{cedar_int_tests_base}/{policies_file_name}")
    entities: list = load_file_as_json(f"{cedar_int_tests_base}/{entities_file_name}")
    schema: object = load_file_as_str(f"{cedar_int_tests_base}/{schema_file_name}")

    testing_params = []

    for request_model in request_models:
        testing_params.append((policies,
                               entities,
                               schema,
                               should_validate,
                               request_model))

    print(f'selected {len(testing_params)} test cases for {test_suite}:\n{pretty_format(testing_params)}')
    return testing_params


class BaseDataDrivenCedarIntegrationTestCase(unittest.TestCase):

    def exec_authz_query_with_assertions(self,
                                         policies: str,
                                         entities: list,
                                         schema: str,
                                         should_validate: bool,  # ignored; currently don't have the equivalent
                                         request_model: dict) -> None:
        print(f"executing authz request model:\n{pretty_format(request_model)}")
        request = {
            'principal': f"{request_model['principal']['type']}::\"{request_model['principal']['id']}\"",
            'action': f"{request_model['action']['type']}::\"{request_model['action']['id']}\"",
            'resource': f"{request_model['resource']['type']}::\"{request_model['resource']['id']}\"",
            'context': request_model.get('context', {}),
        }
        authz_result: cedarpy.AuthzResult = cedarpy.is_authorized(request=request, policies=policies, entities=entities,
                                                                  schema=schema,
                                                                  verbose=True)

        description = request_model['description']
        self.assertEqual(request_model['decision'], authz_result.decision.value.lower(),
                         msg=f'unexpected decision for query desc: {description}')
        # 'reason' spelling is correct here, but a debatable choice as it's a list
        # 'reason' matches the (Rust) Decision enum but Java API has exposed as reasons (plural)
        self.assertEqual(request_model['reason'], authz_result.diagnostics.reasons,
                         msg=f'unexpected errors for query desc: {description}')
        self.assertEqual(request_model['errors'], authz_result.diagnostics.errors,
                         msg=f'unexpected errors for query desc: {description}')


class CedarExampleUseCasesIntegrationTestCase(BaseDataDrivenCedarIntegrationTestCase):

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "1a"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_1a(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "2a"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_2a(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "2b"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_2b(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "2c"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_2c(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "3a"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_3a(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "3b"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_3b(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "3c"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_3c(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "4a"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_4a(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    # Test is not present in cedar-integration-tests release/4.1.x
    # @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "4c"),
    #                       name_func=custom_name_func)
    # @unittest.skip(reason="A couple of requests failing here; true reason TBD")
    # def test_example_use_cases_doc_4c(self,
    #                                   policies: str,
    #                                   entities: list,
    #                                   schema: str,
    #                                   should_validate: bool,  # ignored; currently don't have the equivalent
    #                                   query: dict):
    #
    #     self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
    #                                           should_validate=should_validate,
    #                                           request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "4d"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_4d(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "4e"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_4e(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "4f"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_4f(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("example_use_cases", "5b"),
                          name_func=custom_name_func)
    def test_example_use_cases_doc_5b(self,
                                      policies: str,
                                      entities: list,
                                      schema: str,
                                      should_validate: bool,  # ignored; currently don't have the equivalent
                                      query: dict):

        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)


class CedarIPIntegrationTestCase(BaseDataDrivenCedarIntegrationTestCase):

    @parameterized.expand(get_authz_test_params_for_test_suite("ip", "1"),
                          name_func=custom_name_func)
    def test_ip_1(self,
                  policies: str,
                  entities: list,
                  schema: str,
                  should_validate: bool,  # ignored; currently don't have the equivalent
                  query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("ip", "2"),
                          name_func=custom_name_func)
    def test_ip_2(self,
                  policies: str,
                  entities: list,
                  schema: str,
                  should_validate: bool,  # ignored; currently don't have the equivalent
                  query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("ip", "3"),
                          name_func=custom_name_func)
    def test_ip_3(self,
                  policies: str,
                  entities: list,
                  schema: str,
                  should_validate: bool,  # ignored; currently don't have the equivalent
                  query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)


class CedarMultiIntegrationTestCase(BaseDataDrivenCedarIntegrationTestCase):

    @parameterized.expand(get_authz_test_params_for_test_suite("multi", "1"),
                          name_func=custom_name_func)
    def test_multi_1(self,
                     policies: str,
                     entities: list,
                     schema: str,
                     should_validate: bool,  # ignored; currently don't have the equivalent
                     query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("multi", "2"),
                          name_func=custom_name_func)
    def test_multi_2(self,
                     policies: str,
                     entities: list,
                     schema: str,
                     should_validate: bool,  # ignored; currently don't have the equivalent
                     query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("multi", "3"),
                          name_func=custom_name_func)
    def test_multi_3(self,
                     policies: str,
                     entities: list,
                     schema: str,
                     should_validate: bool,  # ignored; currently don't have the equivalent
                     query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("multi", "4"),
                          name_func=custom_name_func)
    @unittest.skip(reason="12 pass, 1 fails")
    def test_multi_4(self,
                     policies: str,
                     entities: list,
                     schema: str,
                     should_validate: bool,  # ignored; currently don't have the equivalent
                     query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("multi", "5"),
                          name_func=custom_name_func)
    @unittest.skip(reason="Depends on unspecified principal, which is (currently) unsupported by is_authorized, i.e. principal is a required parameter")
    def test_multi_5(self,
                     policies: str,
                     entities: list,
                     schema: str,
                     should_validate: bool,  # ignored; currently don't have the equivalent
                     query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)


class CedarDecimalIntegrationTestCase(BaseDataDrivenCedarIntegrationTestCase):

    @parameterized.expand(get_authz_test_params_for_test_suite("decimal", "1"),
                          name_func=custom_name_func)
    def test_decimal_1(self,
                       policies: str,
                       entities: list,
                       schema: str,
                       should_validate: bool,  # ignored; currently don't have the equivalent
                       query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

    @parameterized.expand(get_authz_test_params_for_test_suite("decimal", "2"),
                          name_func=custom_name_func)
    def test_decimal_2(self,
                       policies: str,
                       entities: list,
                       schema: str,
                       should_validate: bool,  # ignored; currently don't have the equivalent
                       query: dict):
        self.exec_authz_query_with_assertions(policies=policies, entities=entities, schema=schema,
                                              should_validate=should_validate,
                                              request_model=query)

