import unittest

from cedarpy import AuthzResult, Decision, Diagnostics


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
        self.assertEqual(Decision.Allow, authz_result.decision)
        self.assertEqual(Decision.Allow, authz_result['decision'],
                         msg="decision should be available via subscript")
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

    def test_metrics_are_available(self):
        missing_metrics = {}
        empty_metrics = {
            "metrics": {}  # empty metrics
        }
        for authz_resp in [
            self.allow_authz_resp,
            self.deny_authz_resp,
            empty_metrics,
            missing_metrics,
        ]:
            authz_result = AuthzResult(authz_resp)
            self.assertIsNotNone(authz_result.metrics,
                                 msg=f"metrics were none for {authz_resp}")

            if 'metrics' in authz_resp:
                self.assertEqual(authz_resp['metrics'],
                                 authz_result.metrics)
            else:
                self.assertEqual({}, authz_result.metrics)

    def test__getitem__makes_properties_subscriptable(self):
        for authz_resp in [
            self.allow_authz_resp,
            self.deny_authz_resp,
        ]:
            authz_result = AuthzResult(authz_resp)
            
            self.assertEqual(authz_result.decision, authz_result['decision'])
            self.assertEqual(authz_result.allowed, authz_result['allowed'])
            self.assertEqual(authz_result.diagnostics, authz_result['diagnostics'])
            self.assertEqual(authz_result.metrics, authz_result['metrics'])


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
