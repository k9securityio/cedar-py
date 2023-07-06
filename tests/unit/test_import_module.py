import random
import unittest


class ImportModuleTestCase(unittest.TestCase):
    def test_cedarpy_module_imports(self):

        # noinspection PyUnresolvedReferences
        import cedarpy
        # successfully imported cedarpy module
        self.assertTrue(True)


class InvokeModuleTestFunctionTestCase(unittest.TestCase):

    def test_invoke_echo(self):
        import cedarpy
        expect = f'This is a test message: {random.randint(0, 10000)}'
        actual = cedarpy.echo(expect)
        self.assertEqual(expect, actual)
