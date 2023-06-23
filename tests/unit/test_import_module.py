import unittest


class ImportModuleTestCase(unittest.TestCase):
    def test_cedarpolicy_module_imports(self):

        # noinspection PyUnresolvedReferences
        import cedarpolicy
        # successfully imported cedarpolicy module
        self.assertTrue(True)
