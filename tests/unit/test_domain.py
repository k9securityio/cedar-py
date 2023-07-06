import unittest

from cedarpolicy import AuthzResult, Decision, Diagnostics


class AuthzResultTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        self.allow_authz_resp = {
            "decision": "Allow",
            "diagnostics": {
                "reason": ["policy0"],
                "errors": []
            },
            "metrics": {"authz_duration_micros": 42}
        }

        self.deny_authz_resp = {
            'decision': 'Deny',
            'diagnostics': {
                'errors': ['while evaluating policy policy2, encountered the '
                           'following error: record does not have the '
                           'required attribute: authenticated'],
                'reason': []
            },
            "metrics": {"authz_duration_micros": 99}
        }

    def test_decision_property_when_Allow(self):
        authz_result = AuthzResult(self.allow_authz_resp)
        # print(f'authz_result ({type(authz_result)}): {authz_result}')
        self.assertEqual(Decision.Allow, authz_result.decision)
        self.assertEqual(Decision.Allow, authz_result['decision'])
        self.assertTrue(authz_result.allowed)

    def test_decision_property_when_Deny(self):
        authz_result = AuthzResult(self.deny_authz_resp)
        self.assertEqual(authz_result.decision, Decision.Deny)
        self.assertEqual(Decision.Deny, authz_result['decision'])
        self.assertFalse(authz_result.allowed)

    def test_diagnostics_are_available(self):
        for authz_resp in [
            self.allow_authz_resp,
            self.deny_authz_resp,
        ]:
            authz_result = AuthzResult(authz_resp)
            self.assertIsNotNone(authz_result.diagnostics)

            self.assertEqual(authz_resp['diagnostics']['errors'],
                             authz_result.diagnostics.errors)

            self.assertEqual(authz_resp['diagnostics']['reason'],
                             authz_result.diagnostics.reasons,
                             f"expected 'reason' key (singular) to be mapped to reasons property (plural)"
                             f"; authz_resp: {authz_resp}")


class DiagnosticsTestCase(unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()

        self.allow_diagnostics_resp = {
            "errors": [],
            "reason": ["policy0"],
        }

        self.deny_diagnostics_resp = {
            'errors': ['while evaluating policy policy2, encountered the '
                       'following error: record does not have the '
                       'required attribute: authenticated'],
            'reason': [],
        }

    def test_errors_are_resolved(self):
        for diagnostics_resp in [self.allow_diagnostics_resp, self.deny_diagnostics_resp]:
            diagnostics = Diagnostics(diagnostics_resp)
            self.assertEqual(diagnostics_resp['errors'],
                             diagnostics.errors)

    def test_reasons_are_resolved(self):
        for diagnostics_resp in [self.allow_diagnostics_resp, self.deny_diagnostics_resp]:
            diagnostics = Diagnostics(diagnostics_resp)
            self.assertEqual(diagnostics_resp['reason'],
                             diagnostics.reasons)
