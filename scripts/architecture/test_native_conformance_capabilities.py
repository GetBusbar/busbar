import unittest
from native_conformance_capabilities import manifest

class Provisioning(unittest.TestCase):
    def test_unknown_owner_and_missing_bundle_cannot_become_available(self):
        self.assertEqual(manifest('unknown', 'a'*40, {'mcp-tools'}, True)['suites'], {})
        row=manifest('GetBusbar/busbar-plane-mcp', 'a'*40, {}, True)['suites']['mcp']
        self.assertFalse(row['available'])
        self.assertIn('mcp-tools',row['reason'])

    def test_required_bundles_and_runtime_are_both_needed(self):
        for bundles,ready,expected in [({'oidf'},True,False),({'oidf','oidc-source'},False,False),({'oidf','oidc-source'},True,True)]:
            record=manifest('GetBusbar/busbar','a'*40,bundles,ready)
            self.assertEqual(record['suites']['oidf-oauth2']['available'],expected)
            self.assertFalse(record['suites']['slsa-verifier']['available'])
        record=manifest('GetBusbar/busbar-plane-streaming','a'*40,{},True)
        self.assertTrue(all(row['available'] for row in record['suites'].values()))

if __name__ == '__main__':unittest.main()
