import random
import unittest


class ImportModuleTestCase(unittest.TestCase):
    def test_cedarpolicy_module_imports(self):

        # noinspection PyUnresolvedReferences
        import cedarpolicy
        # successfully imported cedarpolicy module
        self.assertTrue(True)


class InvokeModuleTestFunctionTestCase(unittest.TestCase):

    def test_invoke_parse_test_policy(self):
        import cedarpolicy
        result = cedarpolicy.parse_test_policy()
        self.assertEqual('Ok!', result)

    def test_invoke_echo(self):
        import cedarpolicy
        expect = f'This is a test message: {random.randint(0, 10000)}'
        actual = cedarpolicy.echo(expect)
        self.assertEqual(expect, actual)
