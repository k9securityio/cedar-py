import unittest


class ImportModuleTestCase(unittest.TestCase):
    def test_cedarpolicy_module_imports(self):

        # noinspection PyUnresolvedReferences
        import cedarpolicy
        # successfully imported cedarpolicy module
        self.assertTrue(True)


class InvokeModuleTestFunctionTestCase(unittest.TestCase):

    def test_invoke_module_test_function(self):
        import cedarpolicy
        result = cedarpolicy.parse_test_policy()
        self.assertEqual('Ok!', result)
